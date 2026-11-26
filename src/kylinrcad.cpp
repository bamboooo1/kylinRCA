#include "config_manager.h"
#include "cpu_bpf_config.h"
#include "cpu_runtime_sampler.h"
#include "cpu_usage_sampler.h"
#include "daemon_snapshot.h"
#include "json_reporter.h"
#include "lock_analyzer.h"
#include "lock_bpf_config.h"
#include "ring_buffer_consumer.h"
#include "syscall_bpf_config.h"
#include "tracer_bpf_config.h"
#include "unix_socket_server.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

using kylinrca::AppConfig;
using kylinrca::Logger;
using kylinrca::LogLevel;
using namespace std::chrono_literals;

std::atomic<bool> stop_requested{false};
static_assert(std::atomic<bool>::is_always_lock_free);

void request_stop(int)
{
    stop_requested.store(true, std::memory_order_relaxed);
}

// The same open/load/configure/attach sequence is used by each probe.
struct Probe {
    /*智能指针*/
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object{nullptr, bpf_object__close};
    using Link = std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)>;
    std::vector<Link> links;

    bool start(const char* name, const char* path, bool (*configure)(bpf_object*),
               RingBufferConsumer& consumer, Logger& runtime_log)
    {
        // 定义了一个叫 fail 的小函数。以后哪里启动失败，就把错误消息交给它。它会写一条日志，再返回 false。
        const auto fail = [&](const char* message) {
            runtime_log.log(LogLevel::Error, name, message);
            return false;
        };
        // 按 path 打开并解析 .bpf.o 文件，`nullptr` 表示使用默认选项。`object.reset(...)` 把返回的指针交给智能指针 object 管理。
        object.reset(bpf_object__open_file(path, nullptr));
        if (!object)
            return fail("Cannot open BPF object");
        if (bpf_object__load(object.get()) != 0) // 将bpf对象指针加载到内核
            return fail("Cannot load BPF object");
        if (!configure_tracer_pid(object.get()) || !configure(object.get()))
            return fail("Cannot configure BPF maps");
        if (!consumer.add(object.get()))
            return fail("Cannot add BPF ring buffer");

        // For syscall and lock, attach exit handlers before entry handlers.
        for (auto* program = bpf_object__prev_program(object.get(), nullptr);
             program; program = bpf_object__prev_program(object.get(), program)) {
            Link link(bpf_program__attach(program), bpf_link__destroy);
            if (!link)
                return fail("Cannot attach BPF program");
            links.push_back(std::move(link));
        }
        runtime_log.log(LogLevel::Info, name, "BPF probe attached");
        return true;
    }

    void detach()
    {
        while (!links.empty())
            links.pop_back();
    }
};

void analyze(EventQueue& queue, const AppConfig& config, uint64_t started_ns,
             SnapshotStore& snapshots)
{
    SyscallAnalyzer syscalls;
    SyscallAnalyzer window_syscalls;
    CpuAnalyzer cpu;
    LockAnalyzerConfig lock_config;
    lock_config.window_ns = uint64_t{config.window_ms} * 1'000'000;
    LockAnalyzer locks(lock_config);
    if (config.enable_lock)
        locks.advance_window(started_ns);

    uint64_t last_lock_report = 0;
    const auto report_lock_window = [&] {
        if (locks.window_end_ns() != last_lock_report) {
            std::cout << JsonReporter::report_locks(locks) << std::flush;
            last_lock_report = locks.window_end_ns();
        }
    };

    AnalysisProgress progress;
    progress.started_ns = started_ns;
    progress.updated_ns = started_ns;
    auto next_syscall_cleanup = std::chrono::steady_clock::now() + 60s; //把第一次清理 Syscall 统计的时间定在 60 秒后    
    while (auto event = queue.wait_pop()) {
        if (const auto* syscall = std::get_if<syscall_event>(&*event)) {
            syscalls.process(*syscall);
            window_syscalls.process(*syscall);
            ++progress.syscall_events;
        } else if (const auto* schedule = std::get_if<cpu_event>(&*event)) {
            cpu.process(*schedule);
            ++progress.cpu_events;
        } else if (const auto* lock = std::get_if<kylinrca_lock_event>(&*event)) {
            locks.process(*lock);
            ++progress.lock_events;
            report_lock_window();
        } else {
            const auto& tick = std::get<AnalysisTick>(*event);
            if (tick.cpu) {
                cpu.process_usage(*tick.cpu); //这个函数先根据本轮数据更新诊断结果，然后清空window_stats_.clear();
                std::cout << JsonReporter::report_cpu(cpu.diagnosis(), tick.cpu->window_start_ns,
                                                     tick.cpu->timestamp_ns, progress.cpu_events) << std::flush;
                cpu.cleanup_exited_threads(60s);
            }
            if (config.enable_lock) {
                locks.advance_window(tick.timestamp_ns); //查是否跨过了窗口边界。需要结算时，它会调用 finish_window()
                report_lock_window();
            }
            const auto now = std::chrono::steady_clock::now();
            if (config.enable_syscall && now >= next_syscall_cleanup) {
                syscalls.cleanup_exited_processes(60s);
                next_syscall_cleanup = now + 60s;
            }
            progress.window_start_ns = progress.updated_ns;
            progress.updated_ns = tick.timestamp_ns;
            ++progress.completed_windows;
            const CpuUsageObservation empty_cpu_window;
            // 把结果送进查询服务使用的同一个仓库
            snapshots.publish(make_daemon_snapshot(config, progress, syscalls, window_syscalls,
                              tick.cpu ? *tick.cpu : empty_cpu_window, cpu, locks));
            window_syscalls = SyscallAnalyzer{}; //清空本轮syscalls统计
        }
    }

    if (config.enable_lock) {
        locks.flush(cpu_monotonic_ns());
        report_lock_window();
    }
    if (config.enable_syscall)
        std::cout << JsonReporter::report_syscalls(syscalls) << std::flush;
}

int run(const AppConfig& config)
{
    //logger.h里的class Logger定义了类型，说明了每个Logger 对象有哪些成员和方法。
    //Logger::Logger(LogLevel minimum) : minimum_(minimum) {} 实现了构造函数。
    //创建 runtime_log 时会执行它，把传进来的 config.log_level 存到这个对象自己的 minimum_ 里。
    Logger runtime_log(config.log_level);
    if (!config.enable_syscall && !config.enable_cpu && !config.enable_lock) {
        runtime_log.log(LogLevel::Error, "daemon", "Enable at least one of Syscall, CPU or Lock");
        return 1;
    }

    EventQueue queue;
    Probe syscall_probe;
    Probe cpu_probe;
    Probe lock_probe;
    RingBufferConsumer consumer(queue);

    const uint64_t started_ns = cpu_monotonic_ns();

    /*KYLINRCA_SYSCALL_BPF_OBJECT 是 CMake 在编译时传给 C++ 的宏，
    所以你在 kylinrcad.cpp 前面找不到它的声明。
    它展开后就是 syscall.bpf.o 的文件路径。
    start() 把这个路径接收到参数 path 里，再调用 bpf_object__open_file(path, nullptr) 
    打开文件。这一步才得到那份 bpf_object。*/
    if ((config.enable_syscall &&
         !syscall_probe.start("syscall", KYLINRCA_SYSCALL_BPF_OBJECT,
                              configure_syscall_namespace, consumer, runtime_log)) ||
        (config.enable_cpu &&
         !cpu_probe.start("cpu", KYLINRCA_CPU_BPF_OBJECT,
                          configure_cpu_namespace, consumer, runtime_log)) ||
        (config.enable_lock &&
         !lock_probe.start("lock", KYLINRCA_LOCK_BPF_OBJECT,
                           [](bpf_object* object) { return configure_lock_probe(object, 0); },
                           consumer, runtime_log)))
        return 1;

    CpuUsageSampler sampler;
    if (config.enable_cpu && !sampler.start(cpu_probe.object.get())) {
        runtime_log.log(LogLevel::Error, "cpu", "Cannot establish /proc and BPF snapshot baseline");
        return 1;
    }

    const auto window = std::chrono::milliseconds(config.window_ms);
    auto next_tick = std::chrono::steady_clock::now() + window;
    AnalysisProgress initial_progress; //制作“刚启动时的第一张照片”。刚启动时，第一个窗口还没结束，但查询服务已经需要回答：“我正在运行，这些模块已开启，目前完成了 0 个窗口。”
    initial_progress.started_ns = started_ns;
    initial_progress.updated_ns = started_ns;
    SnapshotStore snapshots(make_daemon_snapshot(config, initial_progress,
                            SyscallAnalyzer{}, SyscallAnalyzer{}, CpuUsageObservation{},
                            CpuAnalyzer{}, LockAnalyzer{}));
    UnixSocketServer query_server(config.socket_path, snapshots);
    try {
        query_server.start();
    } catch (const std::exception& error) {
        runtime_log.log(LogLevel::Error, "socket", error.what());
        return 1;
    }
    std::thread worker([&] { analyze(queue, config, started_ns, snapshots); });
    runtime_log.log(LogLevel::Info, "daemon", "Ready");

    int result = 0;

    // 线程调用 poll() 时，最多等多久才回去检查是否该采样或退出。
    const int poll_timeout_ms = static_cast<int>(std::min(window, 100ms).count());


    for (;;) {
        const int error = consumer.poll(poll_timeout_ms);
        if (error < 0 && error != -EINTR) {
            runtime_log.log(LogLevel::Error, "daemon", "Ring buffer poll failed");
            result = 1;
            break;
        }
        if (stop_requested.load(std::memory_order_relaxed)) //如果有人要求程序停止，就跳出当前循环。
            break;
        if (std::chrono::steady_clock::now() < next_tick) //现在到下一次采样的时间了吗？
            continue;

        AnalysisTick tick{};
        if (config.enable_cpu && !sampler.sample(tick.cpu)) {
            runtime_log.log(LogLevel::Error, "cpu", "Cannot read CPU snapshot");
            result = 1;
            break;
        }
        tick.timestamp_ns = cpu_monotonic_ns();
        // Queue events already in the rings before advancing the analysis window.
        // CpuAnalyzer uses event timestamps to keep newer events for the next window.
        consumer.drain();
        queue.push(std::move(tick));
        next_tick = std::chrono::steady_clock::now() + window;
    }

    query_server.stop();
    syscall_probe.detach();
    cpu_probe.detach();
    lock_probe.detach();
    consumer.drain();
    queue.close();
    worker.join();
    return result;
}

} // namespace

int main(int argc, char** argv)
{
    const std::string_view usage = "Usage: kylinrcad [--config PATH]\n";

    if (argc != 1 && (argc != 3 || std::string_view(argv[1]) != "--config")) {
        std::cerr << usage;
        return 1;
    }

    std::signal(SIGINT, request_stop);
    std::signal(SIGTERM, request_stop); //收到 Ctrl+C（SIGINT） 或 系统发来的停止信号（SIGTERM） 时，就调用 request_stop()。
    AppConfig config;
    if (argc == 3) {
        try {
            config = kylinrca::ConfigManager::load(argv[2]);
        } catch (const std::exception& error) {
            Logger{}.log(LogLevel::Error, "config", error.what());
            return 1;
        }
    }
    return run(config);
}
