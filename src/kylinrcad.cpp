#include "config_manager.h"
#include "cpu_bpf_config.h"
#include "cpu_config.h"
#include "lock_config.h"
#include "cpu_runtime_sampler.h"
#include "cpu_usage_sampler.h"
#include "json_reporter.h"
#include "io_config.h"
#include "io_snapshot.h"
#include <functional>
#include "lock_analyzer.h"
#include "lock_bpf_config.h"
#include "ring_buffer_consumer.h"
#include "syscall_bpf_config.h"
#include "tracer_bpf_config.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <string_view>
#include <string>
#include <stdexcept>
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

// 收到中断或终止信号时只设置停止标志；实际解除挂载、排空队列和回收线程由主线程完成。
void request_stop(int)
{
    stop_requested.store(true, std::memory_order_relaxed);
}

// 统一管理每个模块的 BPF 对象与挂载连接，复用“打开、加载、配置、登记接收、挂载”的启动流程。
struct Probe {
    /*智能指针*/
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object{nullptr, bpf_object__close};
    using Link = std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)>;
    std::vector<Link> links;

    // 主线程按模块开关调用：加载 path 指向的对象，调用模块配置函数，登记事件缓冲区并挂载探针。
    // name 用于定位模块日志；任一步失败返回 false，由调用方结束启动，已持有资源随对象释放。
    bool start(const char* name, const char* path, const std::function<bool(bpf_object*)>& configure,
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
        // Syscall、CPU、Lock 使用通用采集进程配置；I/O 只有自己的设备配置表，不能写不存在的通用表。
        if ((std::string_view(name) != "io" && !configure_tracer_pid(object.get())) ||
            !configure(object.get()))
            return fail("Cannot configure BPF maps");
        if (!consumer.add(object.get()))
            return fail("Cannot add BPF ring buffer");

        // 反向遍历本项目的程序定义，让 Syscall、Lock 的结束处理先于开始处理挂载。
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

    // 主线程退出时调用：逐一销毁挂载连接，停止继续采集；保留 BPF 对象和表，供读取最终计数。
    void detach()
    {
        while (!links.empty())
            links.pop_back();
    }
};

// 分析线程入口：直接持有四种分析器，按类型处理队列消息；I/O 与 Lock 一样自行管理窗口。
// 模块只负责分析，报告输出和共享快照由此入口处理；队列排空后完成最后的 Lock、Syscall 报告。
void analyze(EventQueue& queue, const AppConfig& config, const CpuAnalyzerConfig& cpu_settings,
             const LockAnalyzerConfig& lock_settings, const IoAnalyzerConfig& io_settings,
             uint64_t started_ns, IoSnapshotStore& io_snapshots)
{
    SyscallAnalyzer syscalls;
    // 各模块分别接收自己的规则，Lock 的窗口长度仍由公共配置覆盖。
    CpuAnalyzer cpu(cpu_settings);
    auto lock_config = lock_settings;
    lock_config.window_ns = uint64_t{config.window_ms} * 1'000'000;
    LockAnalyzer locks(lock_config);
    if (config.enable_lock)
        locks.advance_window(started_ns);

    // 模块专用规则来自 IoConfig，只有窗口长度与 Lock 一样由 daemon 的公共设置传入。
    auto io_config = io_settings;
    io_config.window_ns = uint64_t{config.window_ms} * 1'000'000;
    IoAnalyzer io(started_ns, io_config);
    IoProbeHealth io_health;

    // 从分析器读取结果构造值副本；分析器不持有快照对象，也不依赖查询线程。
    const auto publish_io = [&] {
        IoSnapshot snapshot;
        snapshot.enabled = config.enable_io;
        if (config.enable_io) {
            snapshot.counters = io.counters();
            snapshot.report = io.report();
            snapshot.probe = io_health;
        }
        io_snapshots.publish(std::move(snapshot));
    };
    publish_io();

    // 取走分析器本次结算的全部窗口并输出，保留跨越多个空窗口时的完整恢复证据。
    // 与 Lock 的报告助手相同，序列化和快照职责留在 daemon，而不是放入分析器。
    const auto report_io_windows = [&] {
        const auto reports = io.take_reports();
        for (const auto& report : reports)
            std::cout << JsonReporter::report_io(report) << '\n' << std::flush;
        if (!reports.empty()) publish_io();
    };

    uint64_t last_lock_report = 0;
    // 只有最近结算窗口变化时输出，避免处理同一窗口中的多条 Lock 事件时重复打印。
    const auto report_lock_window = [&] {
        if (locks.window_end_ns() != last_lock_report) {
            std::cout << JsonReporter::report_locks(locks) << std::flush;
            last_lock_report = locks.window_end_ns();
        }
    };

    uint64_t cpu_events = 0;
    auto next_syscall_cleanup = std::chrono::steady_clock::now() + 60s;
    while (auto event = queue.wait_pop()) {
        if (const auto* syscall = std::get_if<syscall_event>(&*event)) {
            syscalls.process(*syscall);
        } else if (const auto* schedule = std::get_if<cpu_event>(&*event)) {
            cpu.process(*schedule);
            ++cpu_events;
        } else if (const auto* lock = std::get_if<kylinrca_lock_event>(&*event)) {
            locks.process(*lock);
            report_lock_window();
        } else if (const auto* event_io = std::get_if<kylinrca_io_event>(&*event)) {
            // 直接调用 I/O 分析器，事件跨越窗口时可能已经产生报告，因此随后取走输出。
            io.process(*event_io);
            report_io_windows();
        } else {
            const auto& tick = std::get<AnalysisTick>(*event);
            if (tick.io) {
                io_health = *tick.io;
                std::cout << io_probe_health_json(io_health) << '\n' << std::flush;
            }
            if (config.enable_io) {
                // 普通定时消息推进完整窗口；退出消息调用与 Lock 对应的尾窗结算接口。
                if (tick.final) io.flush(tick.timestamp_ns);
                else io.advance_window(tick.timestamp_ns);
                report_io_windows();
                publish_io();
            }
            if (tick.cpu) {
                cpu.process_usage(*tick.cpu);
                std::cout << JsonReporter::report_cpu(cpu.diagnosis(), tick.cpu->window_start_ns,
                                                     tick.cpu->timestamp_ns, cpu_events, &cpu.config()) << std::flush;
                cpu.cleanup_exited_threads(60s);
            }
            if (config.enable_lock) {
                locks.advance_window(tick.timestamp_ns);
                report_lock_window();
            }
            const auto now = std::chrono::steady_clock::now();
            if (config.enable_syscall && now >= next_syscall_cleanup) {
                syscalls.cleanup_exited_processes(60s);
                next_syscall_cleanup = now + 60s;
            }
        }
    }
    if (config.enable_lock) {
        locks.flush(cpu_monotonic_ns());
        report_lock_window();
    }
    if (config.enable_syscall)
        std::cout << JsonReporter::report_syscalls(syscalls) << std::flush;
}

// daemon 的主线程入口：按配置启动探针、建立 CPU 基线和分析线程，再循环接收事件并发送定时消息。
// 停止时先断开探针、消费尾部、发送 I/O 最终消息，再关闭队列并等待分析结束；运行故障返回非零值。
int run(const AppConfig& config, const CpuConfig& cpu_config,
        const LockConfig& lock_config, const IoConfig& io_config)
{
    //logger.h里的class Logger定义了类型，说明了每个Logger 对象有哪些成员和方法。
    //Logger::Logger(LogLevel minimum) : minimum_(minimum) {} 实现了构造函数。
    //创建 runtime_log 时会执行它，把传进来的 config.log_level 存到这个对象自己的 minimum_ 里。
    Logger runtime_log(config.log_level);
    if (!config.enable_syscall && !config.enable_cpu && !config.enable_lock && !config.enable_io) {
        runtime_log.log(LogLevel::Error, "daemon", "Enable at least one of Syscall, CPU, Lock or I/O");
        return 1;
    }

    EventQueue queue;//把主线程收到的数据交给分析线程

    //分别持有对应的 BPF 对象和挂载连接
    Probe syscall_probe;
    Probe cpu_probe;
    Probe lock_probe;
    Probe io_probe;

    // 保存分析线程最近发布的 I/O 状态，供退出输出和未来查询接口读取副本。
    IoSnapshotStore io_snapshots;
    RingBufferConsumer consumer(queue); // 统一接收四个 BPF 对象的事件，再把副本送入公共队列。

    // 在任何模块开始挂载前确认 I/O 所需的内核参数形式；不兼容就明确退出，不猜测结构和参数。
    if (config.enable_io && !io_probe_compatible()) {
        runtime_log.log(LogLevel::Error, "io", "Kernel BTF unavailable or unsupported block raw tracepoint signature");
        return 1;
    }
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
                           consumer, runtime_log)) ||
        // I/O 启动时传入设备配置函数，完成 events 接收登记和全部请求生命周期探针挂载。
        (config.enable_io &&
         !io_probe.start("io", KYLINRCA_IO_BPF_OBJECT,
                         [&](bpf_object* object) { return configure_io_probe(object, io_config.device); },
                         consumer, runtime_log)))
        return 1;

    CpuUsageSampler sampler;
    if (config.enable_cpu && !sampler.start(cpu_probe.object.get())) {
        runtime_log.log(LogLevel::Error, "cpu", "Cannot establish /proc and BPF snapshot baseline");
        return 1;
    }

    const auto window = std::chrono::milliseconds(config.window_ms);
    auto next_tick = std::chrono::steady_clock::now() + window;
    //创建一个分析线程
    std::thread worker([&] { analyze(queue, config, cpu_config.analyzer, lock_config.analyzer,
                                      io_config.analyzer, started_ns, io_snapshots); });
    runtime_log.log(LogLevel::Info, "daemon", "Ready");//启用的 Probe 和必要采样基线已经建立，worker 也已经创建

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
        if (config.enable_io) {
            // 主线程读取内核累计健康计数，把结果随定时消息交给分析线程；读取失败停止运行。
            tick.io.emplace();
            if (!read_io_probe_health(io_probe.object.get(), *tick.io)) {
                runtime_log.log(LogLevel::Error, "io", "Cannot read probe health maps");
                result = 1;
                break;
            }
        }
        tick.timestamp_ns = cpu_monotonic_ns();
        // 先把当前可读事件放入队列，再通知分析线程推进时间；各分析器仍依据事件时间判断归属。
        // CPU 会保留属于后续窗口的事件，I/O 会拒收已经结算窗口的迟到记录。
        consumer.drain();
        queue.push(std::move(tick));
        next_tick = std::chrono::steady_clock::now() + window;
    }

    // 先停止四类探针继续产生事件，再接收缓冲区尾部，保证已经产生的数据仍能进入分析队列。
    syscall_probe.detach();
    cpu_probe.detach();
    lock_probe.detach();
    io_probe.detach();
    consumer.drain();
    if (config.enable_io) {
        // 尾部事件入队后再发送退出消息，使 I/O 在这些事件处理完后结算到停止采集的截止时间。
        AnalysisTick final_tick{};
        final_tick.timestamp_ns = cpu_monotonic_ns();
        final_tick.final = true;
        final_tick.io.emplace();
        if (!read_io_probe_health(io_probe.object.get(), *final_tick.io)) {
            runtime_log.log(LogLevel::Error, "io", "Cannot read final probe health maps");
            result = 1;
            // 计数读取失败时不发布可能不完整的健康数据，但仍发送退出消息，保留尾窗结算。
            final_tick.io.reset();
        }
        queue.push(std::move(final_tick));
    }
    // 关闭只表示后续不再生产消息，不清空队列；等待分析线程排空并输出最终结果。
    queue.close();
    worker.join();
    // 分析线程已退出，此时读取的是最终 I/O 状态；禁用模块时也明确输出 enabled=false。
    std::cout << io_snapshot_json(io_snapshots.read()) << '\n' << std::flush;
    return result;
}

} // 本文件辅助对象和函数命名空间结束

// 程序入口：分别加载公共与 CPU、Lock、I/O 模块配置，检查全部成功后才进入采集。
// 模块文件可独立省略或任意顺序传入；重复选项、非法参数和错误文件均明确失败。
int main(int argc, char** argv)
{
    const std::string_view usage =
        "Usage: kylinrcad [--config PATH] [--cpu-config PATH] [--lock-config PATH] [--io-config PATH]\n";
    AppConfig config;
    CpuConfig cpu_config;
    LockConfig lock_config;
    IoConfig io_config;
    bool app_seen = false, cpu_seen = false, lock_seen = false, io_seen = false;
    try {
        for (int i = 1; i < argc; ++i) {
            const std::string_view option(argv[i]);
            if (option == "--help" && argc == 2) {
                std::cout << usage;
                return 0;
            }
            if (i + 1 >= argc) throw std::runtime_error("missing option value");
            if (option == "--config" && !app_seen) {
                config = kylinrca::ConfigManager::load(argv[++i]);
                app_seen = true;
            } else if (option == "--cpu-config" && !cpu_seen) {
                cpu_config = CpuConfig::load(argv[++i]);
                cpu_seen = true;
            } else if (option == "--lock-config" && !lock_seen) {
                lock_config = LockConfig::load(argv[++i]);
                lock_seen = true;
            } else if (option == "--io-config" && !io_seen) {
                io_config = IoConfig::load(argv[++i]);
                io_seen = true;
            } else {
                throw std::runtime_error("unknown or duplicate option: " + std::string(option));
            }
        }
    } catch (const std::exception& error) {
        Logger{}.log(LogLevel::Error, "config", error.what());
        std::cerr << usage;
        return 1;
    }
    std::signal(SIGINT, request_stop);
    std::signal(SIGTERM, request_stop);
    return run(config, cpu_config, lock_config, io_config);
}
