#include "cpu_runtime_sampler.h"
#include "cpu_bpf_config.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cpu_analyzer.h"
#include "cpu_probe_stats.h"
#include "event.h"
#include "proc_cpu_sampler.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unordered_map>
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
 * 将 CpuAnalyzer 内部枚举转换成终端可读文本；这里只负责显示，
 * 不参与状态判断。
 */
const char* diagnosis_state_name(
    CpuDiagnosisState state)
{
    switch (state) {
    case CpuDiagnosisState::Normal:
        return "NORMAL";
    case CpuDiagnosisState::HighUsage:
        return "CPU_HIGH_USAGE";
    case CpuDiagnosisState::RunqueuePressure:
        return "CPU_RUNQUEUE_PRESSURE";
    }

    return "UNKNOWN";
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
 * 用前后两次全系统线程快照生成本轮进程和线程 CPU 使用率。
 *
 * 新建或已经退出的线程缺少完整前后样本，本轮跳过；下一轮拥有完整
 * 基线后即可参与排名。进程使用率是其有效线程使用率之和。
 */
std::vector<CpuProcessUsageObservation>
build_process_observations(
    const ThreadCpuStatMap& previous,
    const ThreadCpuStatMap& current,
    double elapsed_seconds,
    long clock_ticks)
{
    /*
     * processes 保存最终交给 CpuAnalyzer 的进程级结果。
     *
     * process_indexes 保存“PID -> processes 下标”，用于把多个 TID
     * 快速汇总到同一个进程，避免每遇到一个线程就线性查找 vector。
     */
    std::vector<CpuProcessUsageObservation> processes;
    std::unordered_map<uint32_t, std::size_t>
        process_indexes;

    /*
     * current 的 key 是 TID，value 是该线程当前累计的 utime/stime。
     * 这里逐个线程计算本轮增量。
     */
    for (const auto& [tid, current_thread] : current) {
        const auto previous_it =
            previous.find(tid); // 在 previous 里找同一个 TID

        /*
         * 当前快照中新出现的线程没有上一轮基线，无法计算差值；
         * 本轮跳过，下一轮它就会拥有完整的前后样本。
         */
        if (previous_it == previous.end())
            continue;

        // calculate_thread_cpu_usage() 会把 tick 差换算成百分比。
        double thread_usage = 0.0;

        if (!calculate_thread_cpu_usage(
                previous_it->second,
                current_thread,
                elapsed_seconds,
                clock_ticks,
                thread_usage)) //计算线程使用率
            continue;

        /*
         * current_thread.pid 是线程组 ID（TGID），同一进程内所有
         * 线程拥有相同 PID，但各自的 TID 不同。
         */
        const uint32_t pid = static_cast<uint32_t>(current_thread.pid);
        // tracer 自身已在 BPF 侧过滤，也不应出现在 /proc 热点排名中。
        if (pid == static_cast<uint32_t>(getpid()))
            continue; //获取线程所属进程PID

        /* 
         *第一次遇到某个 PID 时，
         *在 processes 中创建对应的进程统计对象，
         *并记录这个对象位于 processes 的哪个下标。
         * index_it：指向 Map 中对应元素的迭代器
         * inserted：这次是否真的插入了新元素
         */
        auto [index_it, inserted] =
            process_indexes.emplace(
                pid,
                processes.size());

        if (inserted) {
            /*
             * inserted == true 表示这个 PID 第一次出现。此时
             * processes.size() 就是新对象即将占用的下标。
             */
            CpuProcessUsageObservation process;
            process.pid = pid;
            processes.push_back(
                std::move(process));
        }

        /*
         * 无论 PID 是刚插入还是以前已经出现，index_it->second 都是
         * 它在 processes 中的下标。引用 process 后可直接累加。
         */
        CpuProcessUsageObservation& process =
            processes[index_it->second];

        /*
         * 线程组 leader 的 comm 最适合作为进程名；leader 本轮没有
         * 有效差分样本时，退化为第一个有效线程名。
         */
        if (process.comm.empty() ||
            current_thread.tid ==
                current_thread.pid)
            process.comm = current_thread.comm;

        /*
         * Linux 进程 CPU 使用率等于其线程使用率之和，所以多线程
         * 进程的结果可以超过 100%。
         */
        process.process_usage_percent +=
            thread_usage;

        /*
         * 除了累加进程总量，还保留每个线程的 TID、名称和使用率，
         * CpuAnalyzer 才能从最高使用率进程中继续选择责任线程。
         */
        CpuThreadUsageObservation thread;
        thread.tid =
            static_cast<uint32_t>(
                current_thread.tid);
        thread.comm = current_thread.comm;
        thread.usage_percent = thread_usage;
        thread.runtime_valid = calculate_runtime_delta(
            previous_it->second, current_thread,
            thread.runtime_ns, thread.runtime_window_ns);
        thread.runtime_uncertainty_ns = previous_it->second.bpf_uncertainty_ns
                                      + current_thread.bpf_uncertainty_ns;

        // 把线程明细放进它所属进程的 threads 列表。
        process.threads.push_back(
            std::move(thread));
    }

    /*
     * 排序不是 CpuAnalyzer 正确性的必要条件，但可以让调试输出和后续
     * Reporter 的 Top-N 结果保持稳定。
     */
    /*
     * 先把每个进程内部的线程按 CPU 使用率从高到低排序，
     * threads.front() 因而就是该进程最忙的线程。
     */
    for (CpuProcessUsageObservation& process :
         processes) {
        std::sort(
            process.threads.begin(),
            process.threads.end(),
            [](const auto& left, const auto& right) {
                return left.usage_percent >
                       right.usage_percent;
            });
    }

    /*
     * 再把所有进程按总 CPU 使用率从高到低排序。CpuAnalyzer 本身
     * 仍会比较数值，不依赖排序，但该顺序方便未来直接输出 Top-N。
     */
    std::sort(
        processes.begin(),
        processes.end(),
        [](const auto& left, const auto& right) {
            return left.process_usage_percent >
                   right.process_usage_percent;
        });

    // 返回“进程 -> 线程明细”的完整本轮观测结果。
    return processes;
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
bool read_cpu_probe_errors(bpf_object* object, uint64_t& total)
{
    bpf_map* map = bpf_object__find_map_by_name(object, "cpu_stats");
    const int cpus = libbpf_num_possible_cpus();
    if (!map || cpus <= 0)
        return false;
    const uint32_t keys[] = {CPU_STAT_RINGBUF_DROP, CPU_STAT_BAD_RUNQUEUE_TIMESTAMP,
        CPU_STAT_BAD_ONCPU_TIMESTAMP, CPU_STAT_WAKEUP_UPDATE_FAIL,
        CPU_STAT_ONCPU_UPDATE_FAIL, CPU_STAT_REQUEUE_UPDATE_FAIL};
    std::vector<uint64_t> values(cpus);
    total = 0;
    for (const uint32_t key : keys) {
        if (bpf_map_lookup_elem(bpf_map__fd(map), &key, values.data()) != 0)
            return false;
        for (uint64_t value : values)
            total += value;
    }
    return true;
}

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
     * CPU 使用率必须通过两次累计值做差计算：
     * previous_system 保存上一轮 /proc/stat；
     * previous_threads 保存上一轮所有 /proc/<pid>/task/<tid>/stat。
     */
    CpuStatSample previous_system;
    ThreadCpuStatMap previous_threads;

    // 建立第一轮系统和线程基线；任一快照完全失败都无法继续计算。
    if (!read_system_cpu_stat(previous_system) ||
        !read_all_thread_cpu_stats(
            previous_threads)) {
        std::cerr
            << "Cannot read initial system CPU snapshot"
            << std::endl;
        return 1;
    }

    /*
     * 时间基线必须紧跟初始 /proc 快照，确保线程 tick 增量和时间分母
     * 覆盖同一个区间。BPF 初始化耗时也会同时进入分子和分母。
     */
    auto previous_sample_time =
        std::chrono::steady_clock::now();

    /*
     * /proc 的 utime/stime 单位是 tick。_SC_CLK_TCK 表示一秒包含
     * 多少 tick，用于将线程 tick 增量换算成 CPU 秒。
     */
    const long clock_ticks =
        sysconf(_SC_CLK_TCK);

    if (clock_ticks <= 0) {
        std::cerr
            << "Cannot read _SC_CLK_TCK"
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

    /*
     * config_map 用来把当前观测程序的 PID 传给 BPF，从源头过滤
     * tracer 自己产生的调度事件。
     */
    bpf_map* config_map =
        bpf_object__find_map_by_name(
            object,
            "config_map");

    if (config_map == nullptr) {
        std::cerr
            << "Missing config_map"
            << std::endl;
        bpf_object__close(object);
        return 1;
    }

    // config_map 是单元素配置 Map，固定使用 key 0。
    const uint32_t config_key = 0;
    const uint32_t tracer_pid =
        static_cast<uint32_t>(getpid());

    /*
     * 把观测程序 PID 写入 BPF Map，避免 RingBuffer 消费造成新的
     * 调度事件并形成自观测反馈。
     */
    if (bpf_map_update_elem(
            bpf_map__fd(config_map),
            &config_key,
            &tracer_pid,
            BPF_ANY) != 0) {
        std::cerr
            << "Failed to configure tracer PID: "
            << std::strerror(errno)
            << std::endl;
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

    bpf_map* runtime_map = bpf_object__find_map_by_name(object, "runtime_map");
    const int runtime_fd = runtime_map ? bpf_map__fd(runtime_map) : -1;
    if (runtime_fd < 0) {
        ring_buffer__free(ring);
        destroy_links(links);
        bpf_object__close(object);
        return 1;
    }
    const ThreadSnapshotHook runtime_hook = [runtime_fd](ThreadCpuStatSample& sample) {
        read_cpu_runtime(runtime_fd, sample);
    };
    // BPF 已挂载后重新建立基线，不能把加载前的 /proc 区间与加载后的 BPF 比较。
    if (!read_system_cpu_stat(previous_system) ||
        !read_all_thread_cpu_stats(previous_threads, runtime_hook)) {
        ring_buffer__free(ring);
        destroy_links(links);
        bpf_object__close(object);
        return 1;
    }
    previous_sample_time = std::chrono::steady_clock::now();

    uint64_t previous_probe_errors = 0;
    read_cpu_probe_errors(object, previous_probe_errors);
    uint64_t previous_window_end = cpu_monotonic_ns();
    int result = 0;

    // Ctrl+C 和 SIGTERM 都走正常退出路径，保证 BPF 被解除挂载。
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    /*
     * started 只负责判断整个测试运行时长；previous_sample_time
     * 负责 CPU 差分区间，两者含义不同，不能混用。
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

        /*
         * current_* 是本轮新快照，与 previous_* 做差后得到这一秒的
         * 系统、进程和线程 CPU 使用率。
         */
        CpuStatSample current_system;
        ThreadCpuStatMap current_threads;

        if (!read_system_cpu_stat(
                current_system) ||
            !read_all_thread_cpu_stats(
                current_threads, runtime_hook)) {
            std::cerr
                << "Cannot read current system CPU snapshot"
                << std::endl;
            result = 1;
            break;
        }

        /*
         * 线程 tick 来自刚完成的 /proc 快照，因此在快照之后记录时间，
         * 避免分母短于 tick 的实际统计区间。
         */
        const auto current_sample_time =
            std::chrono::steady_clock::now();

        /*
         * 实际间隔不保证刚好等于 1 秒，因此必须使用单调时钟计算真实
         * 秒数，不能在公式中写死 1.0。
         */
        const double elapsed_seconds =
            std::chrono::duration<double>(
                current_sample_time -
                previous_sample_time)
                .count();

        // 保存 /proc/stat 前后差分得到的系统总体 CPU 百分比。
        double system_usage = 0.0;

        /*
         * 系统累计值有效时才构造 observation；如果计数回退或总增量
         * 为 0，本轮跳过诊断，但仍会推进下一轮快照。
         */
        if (calculate_system_cpu_usage(
                previous_system,
                current_system,
                system_usage)) {
            /*
             * observation 是 /proc sampler 与 CpuAnalyzer 的数据边界：
             * sampler 只负责计算，analyzer 只负责阈值和责任归因。
             */
            // 扫描期间积压的事件也先消费，再按事件时间过滤归窗。
            if (ring_buffer__consume(ring) < 0) {
                result = 1;
                break;
            }
            CpuUsageObservation observation;
            // 保存与本轮快照对应的单调时钟纳秒时间戳。
            observation.timestamp_ns = cpu_monotonic_ns();
            observation.window_start_ns = previous_window_end;
            previous_window_end = observation.timestamp_ns;
            // 系统使用率决定系统级 HighUsage 是否满足触发条件。
            uint64_t current_probe_errors = 0;
            observation.scheduling_evidence_valid =
                read_cpu_probe_errors(object, current_probe_errors) &&
                current_probe_errors == previous_probe_errors;
            previous_probe_errors = current_probe_errors;
            observation.has_runtime_snapshots = true;
            observation.system_usage_percent =
                system_usage;
            /*
             * 将线程快照差分并按 PID 汇总，生成：
             * 每个进程总使用率 + 该进程所有线程使用率。
             */
            observation.processes =
                build_process_observations(
                    previous_threads,
                    current_threads,
                    elapsed_seconds,
                    clock_ticks);

            /*
             * process_usage() 将 /proc 使用率与此前累计的 BPF 窗口
             * 合并，更新状态、责任 PID/TID 和调度证据，然后清空窗口。
             */
            analyzer.process_usage(observation);

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
                << diagnosis_state_name(
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

        /*
         * 当前快照完成诊断后变成下一轮基线。current_threads 使用
         * move 转移大量线程记录，避免复制整个全系统快照。
         */
        previous_system = current_system;
        previous_threads =
            std::move(current_threads);
        previous_sample_time =
            current_sample_time;
        next_sample_time =
            current_sample_time +
            std::chrono::seconds(1);

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
