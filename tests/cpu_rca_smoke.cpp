#include "cpu_runtime_sampler.h"
#include "cpu_usage_sampler.h"
#include "tracer_bpf_config.h"
#include "cpu_bpf_config.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cpu_analyzer.h"
#include "cpu_probe_stats.h"
#include "event.h"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

#include <unistd.h>

namespace {

/*
 * 主循环运行标志。信号处理函数只把它改为 0，主循环随后自行完成
 * RingBuffer、BPF link 和 bpf_object 的资源清理。
 */
volatile sig_atomic_t running = 1;

void handle_signal(int)
{
    running = 0;
}

/*
 * RingBuffer 回调只能接收一个 void* 上下文，所以把回调需要共享的
 * 分析器和调试计数器统一放进该结构。
 */
struct EventContext {
    // 回调收到事件后，通过该指针调用 CpuAnalyzer::process()。
    CpuAnalyzer* analyzer = nullptr;

    // 通过协议校验的全系统 CPU 事件总数。
    uint64_t received_events = 0;

    // BPF 未能填写真实 PID 的异常事件数，正常应始终为 0。
    uint64_t zero_pid_events = 0;
};

/*
 * 系统模式不再按目标 PID 过滤事件。
 *
 * 每个 cpu_event 都按 TID 进入 CpuAnalyzer；随后 /proc 选出的责任
 * TID 会与同一个诊断窗口中的 BPF 调度证据关联。
 */
int handle_cpu_event(
    void* opaque,
    void* data,
    size_t size)
{
    /*
     * ring_buffer__new() 传入的是 void*，这里恢复成真正的
     * EventContext*，才能访问 analyzer 和计数器。
     */
    auto* context =
        static_cast<EventContext*>(opaque);

    /*
     * 第一层校验用户态上下文和 RingBuffer 实际记录长度，防止空指针
     * 或错误长度被强制解释成 cpu_event。
     */
    if (context == nullptr ||
        context->analyzer == nullptr ||
        size != sizeof(cpu_event))
        return 0;

    // 长度确认正确后，才把原始字节解释成只读 cpu_event。
    const auto* event =
        static_cast<const cpu_event*>(data);

    /*
     * 第二层校验事件自身声明的版本、类型和大小，避免用户态与 BPF
     * 使用了不同版本的 event.h。
     */
    if (event->header.version !=
            KYLINRCA_EVENT_VERSION ||
        event->header.type !=
            EVENT_TYPE_CPU ||
        event->header.size !=
            sizeof(cpu_event))
        return 0;

    // 走到这里说明事件格式完整，可以计入总接收数。
    context->received_events++;

    if (event->header.pid == 0) {
        context->zero_pid_events++;
        return 0;
    }

    /*
     * 系统模式接收所有非零 PID 的事件。CpuAnalyzer 内部会按 TID
     * 分别累计本轮 on-CPU 时间和 runqueue 延迟。
     */
    context->analyzer->process(*event);
    return 0;
}

/*
 * 将命令行运行秒数解析为正整数。
 *
 * end 用于保证整个字符串都是数字，例如 "10abc" 不能被当成 10；
 * errno 和上界检查用于防止整数溢出。
 */
bool parse_positive_int(
    const char* text,
    int& value)
{
    char* end = nullptr;
    errno = 0;

    const long parsed =
        std::strtol(text, &end, 10);

    if (errno != 0 ||
        end == text ||
        *end != '\0' ||
        parsed <= 0 ||
        parsed > 2'147'483'647L)
        return false;

    value = static_cast<int>(parsed);
    return true;
}

/*
 * 统一销毁已经 attach 的 BPF link。
 *
 * link 存活就表示程序仍挂载在内核 hook 上，因此错误路径和正常退出
 * 都必须调用该函数，不能只关闭 bpf_object。
 */
void destroy_links(
    std::vector<bpf_link*>& links)
{
    for (bpf_link* link : links)
        bpf_link__destroy(link);

    links.clear();
}

/* 将丢事件、非法时间与 Map 写入失败转为本轮压力证据的质量标记。 */
/*
 * PERCPU_ARRAY 的每个 key 在每个 possible CPU 上都有一个 64 位值。
 * 必须一次提供全部 CPU 的空间；只传一个整数会导致缓冲区越界。
 * 在 detach 后读取，避免汇总期间探针继续更新，随后再关闭 object。
 */
bool print_cpu_probe_stats(bpf_object* object)
{
    bpf_map* map = bpf_object__find_map_by_name(object, "cpu_stats");
    const int cpu_count = libbpf_num_possible_cpus();
    if (map == nullptr || cpu_count <= 0) {
        std::cerr << "Cannot access CPU probe statistics\n";
        return false;
    }

    struct StatName {
        uint32_t key;
        const char* name;
    };
    /* 显式使用共享枚举，不依赖字符串数组下标推断计数器编号。 */
    const StatName names[] = {
        {CPU_STAT_WAKEUP_UPDATE_FAIL, "wakeup_update_fail"},
        {CPU_STAT_WAKEUP_MISS, "wakeup_miss"},
        {CPU_STAT_ONCPU_UPDATE_FAIL, "oncpu_update_fail"},
        {CPU_STAT_ONCPU_MISS, "oncpu_miss"},
        {CPU_STAT_REQUEUE_UPDATE_FAIL, "requeue_update_fail"},
        {CPU_STAT_RINGBUF_DROP, "ringbuf_drop"},
        {CPU_STAT_DELETE_FAIL, "delete_fail"},
        {CPU_STAT_BAD_RUNQUEUE_TIMESTAMP, "bad_runqueue_timestamp"},
        {CPU_STAT_BAD_ONCPU_TIMESTAMP, "bad_oncpu_timestamp"},
    };
    static_assert(sizeof(names) / sizeof(names[0]) == CPU_STAT_MAX,
                  "Every CPU statistic needs a printable name");

    if (bpf_map__max_entries(map) != CPU_STAT_MAX ||
        bpf_map__value_size(map) != sizeof(uint64_t) ||
        bpf_map__type(map) != BPF_MAP_TYPE_PERCPU_ARRAY) {
        std::cerr << "CPU statistics map definition mismatch\n";
        return false;
    }

    std::vector<uint64_t> values(cpu_count);
    bool success = true;
    for (const StatName& stat : names) {
        if (bpf_map_lookup_elem(bpf_map__fd(map), &stat.key,
                                values.data()) != 0) {
            std::cerr << "Cannot read CPU statistic " << stat.name
                      << ": " << std::strerror(errno) << '\n';
            success = false;
            continue;
        }
        uint64_t total = 0;
        for (uint64_t value : values)
            total += value;
        std::cout << "[CPU PROBE] " << stat.name << '=' << total << '\n';
    }
    return success;
}

} // namespace

/*
 * 系统级 CPU RCA 联调入口。
 *
 * 不再接收目标 PID；唯一可选参数是运行秒数。未指定时持续运行，
 * 直到 Ctrl+C 或 SIGTERM。
 */
int main(
    int argc,
    char* argv[])
{
    // argc 包含程序名，所以最多只能有“程序名 + 运行秒数”两个参数。
    if (argc > 2) {
        std::cerr
            << "Usage: "
            << argv[0]
            << " [duration-seconds]"
            << std::endl;
        return 1;
    }

    /*
     * 0 表示不设置截止时间；正数表示自动运行对应秒数。
     */
    int duration_seconds = 0;

    if (argc == 2 &&
        !parse_positive_int(
            argv[1],
            duration_seconds)) {
        std::cerr
            << "Invalid duration: "
            << argv[1]
            << std::endl;
        return 1;
    }

    /*
     * analyzer 同时接收两条数据流：
     * 1. RingBuffer 中的全系统调度事件；
     * 2. 每秒一次的全系统 /proc CPU 使用率观测。
     */
    CpuAnalyzer analyzer;
    EventContext event_context{
        &analyzer,
        0,
        0
    };

    /*
     * open_file 只解析 build/cpu.bpf.o，还没有把程序加载进内核。
     */
    bpf_object* object =
        bpf_object__open_file(
            "build/cpu.bpf.o",
            nullptr);

    if (object == nullptr) {
        std::cerr
            << "Failed to open build/cpu.bpf.o"
            << std::endl;
        return 1;
    }

    /*
     * load 将 BPF 程序和 Map 加载进内核，并由 verifier 校验安全性。
     */
    int error =
        bpf_object__load(object);

    if (error != 0) {
        std::cerr
            << "Failed to load CPU BPF object: "
            << error
            << std::endl;
        bpf_object__close(object);
        return 1;
    }

    if (!configure_tracer_pid(object)) {
        std::cerr << "Failed to configure tracer PID: " << std::strerror(errno) << '\n';
        bpf_object__close(object);
        return 1;
    }

    /*
     * 一个 cpu.bpf.o 中包含多个程序（wakeup、wakeup_new、switch）。
     * links 保存每次 attach 的结果，确保观测期间挂载关系一直存活。
     */
    if (!configure_cpu_namespace(object)) {
        std::cerr << "Cannot configure CPU PID namespace\n";
        bpf_object__close(object);
        return 1;
    }

    std::vector<bpf_link*> links;
    bpf_program* program = nullptr;

    // 遍历对象中的每个 BPF 程序，并按它的 SEC 类型自动 attach。
    bpf_object__for_each_program(
        program,
        object) {
        bpf_link* link =
            bpf_program__attach(program);

        if (link == nullptr) {
            std::cerr
                << "Failed to attach "
                << bpf_program__name(program)
                << std::endl;
            destroy_links(links);
            bpf_object__close(object);
            return 1;
        }

        links.push_back(link);
    }

    // events 是 BPF 向用户态提交 cpu_event 的 RingBuffer Map。
    bpf_map* events_map =
        bpf_object__find_map_by_name(
            object,
            "events");

    /*
     * ring 是用户态消费者；每收到一条记录，libbpf 就调用
     * handle_cpu_event(data, size)。
     */
    ring_buffer* ring = nullptr;

    if (events_map != nullptr) {
        ring = ring_buffer__new(
            bpf_map__fd(events_map),
            handle_cpu_event,
            &event_context,
            nullptr);
    }

    if (ring == nullptr) {
        std::cerr
            << "Failed to create CPU ring buffer"
            << std::endl;
        destroy_links(links);
        bpf_object__close(object);
        return 1;
    }

    CpuUsageSampler sampler;
    if (!sampler.start(object)) {
        std::cerr << "Cannot establish CPU snapshot baseline\n";
        ring_buffer__free(ring);
        destroy_links(links);
        bpf_object__close(object);
        return 1;
    }

    int result = 0;

    // Ctrl+C 和 SIGTERM 都走正常退出路径，保证 BPF 被解除挂载。
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    /*
     * started 用于判断本次测试运行时长。
     */
    const auto started =
        std::chrono::steady_clock::now();

    auto next_sample_time =
        started + std::chrono::seconds(1);

    std::cout
        << "CPU RCA system-wide test started"
        << std::endl;

    /*
     * 主循环有两种节奏：
     * - 每次最多等待 100ms 消费 BPF 事件；
     * - 每约 1 秒读取一次 /proc 并执行一次 RCA 判断。
     */
    while (running) {
        /*
         * poll 会等待事件并触发 handle_cpu_event；100 是毫秒超时，
         * 它保证无事件时也能定期检查采样时间和退出条件。
         */
        error = ring_buffer__poll(
            ring,
            100);

        /*
         * EINTR 表示等待被信号打断，不是 RingBuffer 损坏。重新进入
         * 循环后会检查 running，并在 Ctrl+C 时自然退出。
         */
        if (error == -EINTR)
            continue;

        if (error < 0) {
            std::cerr
                << "Ring buffer poll failed: "
                << error
                << std::endl;
            result = 1;
            break;
        }

        // poll_time 用于判断总运行时间以及是否到达下一次采样时间。
        const auto poll_time =
            std::chrono::steady_clock::now();

        // 指定运行秒数时，到期后退出；0 表示不自动到期。
        if (duration_seconds > 0 &&
            poll_time - started >=
                std::chrono::seconds(
                    duration_seconds))
            break;

        /*
         * 尚未满一个采样周期时只消费 BPF 事件，不读取 /proc。
         * 这些事件会继续累积在 CpuAnalyzer 当前窗口中。
         */
        if (poll_time < next_sample_time)
            continue;

        std::optional<CpuUsageObservation> observation;
        if (!sampler.sample(observation)) {
            std::cerr << "Cannot read current system CPU snapshot\n";
            result = 1;
            break;
        }
        const auto sampled_at = std::chrono::steady_clock::now();

        if (observation) {
            // 扫描期间积压的事件也先消费，再按事件时间过滤归窗。
            if (ring_buffer__consume(ring) < 0) {
                result = 1;
                break;
            }
            analyzer.process_usage(*observation);

            // 获取只读诊断结果，下面仅负责把字段打印到终端。
            const CpuDiagnosis& diagnosis =
                analyzer.diagnosis();

            /*
             * 输出分成三类：
             * 1. state/system：系统是否持续高 CPU；
             * 2. culprit_*：真正消耗 CPU 最多的进程和线程；
             * 3. victim_*：runqueue 等待最久的线程，它不一定是责任线程。
             */
            std::cout
                << "[CPU RCA]"
                << " sample_ns=" << cpu_monotonic_ns()
                << " state="
                << cpu_diagnosis_state_name(
                    diagnosis.state)
                << " system="
                << diagnosis.system_usage_percent
                << "%"
                << " culprit_pid="
                << diagnosis.culprit_pid
                << " process_comm="
                << diagnosis.culprit_process_comm
                << " process_usage="
                << diagnosis.
                    culprit_process_usage_percent
                << "%"
                << " culprit_tid="
                << diagnosis.culprit_tid
                << " thread_comm="
                << diagnosis.culprit_thread_comm
                << " thread_usage="
                << diagnosis.
                    culprit_thread_usage_percent
                << "%"
                << " culprit_oncpu_ns="
                << diagnosis.culprit_oncpu_time_ns
                << " runtime_valid=" << diagnosis.culprit_runtime_valid
                << " runtime_window_ns=" << diagnosis.culprit_runtime_window_ns
                << " runtime_uncertainty_ns=" << diagnosis.culprit_runtime_uncertainty_ns
                << " culprit_runqueue_ns="
                << diagnosis.culprit_runqueue_delay_ns
                << " victim_tid="
                << diagnosis.victim_tid
                << " victim_max_runqueue_ns="
                << diagnosis.
                    victim_max_runqueue_delay_ns
                << " consecutive="
                << diagnosis.consecutive_samples
                << std::endl;
        }

        next_sample_time = sampled_at + std::chrono::seconds(1);

        /*
         * 清理已经退出且 60 秒没有新 BPF 事件的 TID，防止生命周期
         * stats_ 随系统创建线程而无限增长。
         */
        analyzer.cleanup_exited_threads(
            std::chrono::seconds(60));
    }

    /*
     * 消费 BPF 批量唤醒策略留下的尾部事件。
     */
    /*
     * consume 不等待通知，只处理当前已经留在 RingBuffer 中的记录，
     * 避免批量唤醒不足一个批次的尾部事件丢在退出阶段。
     */
    /* 先停止生产事件，再消费尾部，最后读取稳定的内核统计。 */
    destroy_links(links);
    if (ring_buffer__consume(ring) < 0) {
        std::cerr << "Failed to consume final CPU events\n";
        result = 1;
    }
    if (!print_cpu_probe_stats(object))
        result = 1;

    std::cout
        << "CPU RCA system-wide test stopped"
        << " received_events="
        << event_context.received_events
        << " zero_pid_events="
        << event_context.zero_pid_events
        << " tracked_threads="
        << analyzer.thread_count()
        << std::endl;

    /*
     * links 已在尾部消费前解除挂载；统计读取完成后，
     * 释放用户态 RingBuffer，最后关闭 object 和 Map 文件描述符。
     */
    ring_buffer__free(ring);
    bpf_object__close(object);
    return result;
}
