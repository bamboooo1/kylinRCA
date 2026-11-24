/*用户态入口，负责加载内核探针、接收锁事件、打印结果和清理资源。
    这个程序负责把编译后的 lock.bpf.o 加载到内核、写入配置、挂载探针，然后等待 RingBuffer 中的事件。
    收到事件后，它先检查版本、类型和长度，再打印字段；--analyze 同时输出窗口诊断。
    输出格式类似：
    [LOCK] timestamp_ns=… pid=4200 tid=4202 lock_addr=0x… futex_op=128 duration_ns=6000000 ret=0*/
#include "lock_bpf_config.h"
#include "tracer_bpf_config.h"
#include "lock_analyzer.h"
#include "json_reporter.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/futex.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace {

volatile sig_atomic_t running = 1;

/*收到 Ctrl+C 等退出信号时，把 running 设为 0，让主循环结束。*/
void handle_signal(int)
{
    running = 0;
}

/*保存启动参数*/
struct Options {
    int duration = 0; //运行时长，默认时长为 0 表示持续运行
    uint32_t pid = 0; //目标进程，PID 为 0 表示不限制目标进程
    std::string object = KYLINRCA_LOCK_BPF_OBJECT; //BPF 文件路径
    bool analyze = false; // 同时执行窗口聚合、竞争诊断和 JSON 输出。
};

/*检查一段文字是否能完整转换为正整数，并把结果写入 value。*/
bool positive_integer(const char* text, int& value)
{
    const char* end = text + std::strlen(text);
    const auto parsed = std::from_chars(text, end, value); // 尝试将文本转换为整数
    return parsed.ec == std::errc{} && parsed.ptr == end && value > 0; // 检查转换是否成功，且没有剩余字符，且值大于 0
}

/*解析运行时长、PID、对象路径和分析开关；参数不合法时返回 false。*/
bool parse_options(int argc, char** argv, Options& options)
{
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--analyze") {
            options.analyze = true;
        } else if (argument == "--duration" || argument == "--pid") {
            int value = 0;
            if (++i == argc || !positive_integer(argv[i], value))
                return false;
            if (argument == "--duration")
                options.duration = value;
            else
                options.pid = static_cast<uint32_t>(value);
        } else if (argument == "--object") {
            if (++i == argc || !argv[i][0])
                return false;
            options.object = argv[i];
        } else {
            return false;
        }
    }
    return true;
}

/*集中管理程序使用的资源：BPF 对象 object、RingBuffer 消费者 ring、挂载连接 links。*/
struct Session {
    bpf_object* object = nullptr;
    ring_buffer* ring = nullptr;
    std::vector<bpf_link*> links;


    /*	解除已经挂载的 BPF 程序，并清空连接列表。*/
    void detach()
    {
        for (auto it = links.rbegin(); it != links.rend(); ++it)
            bpf_link__destroy(*it);
        links.clear();
    }

    /*	对象结束使用时自动执行：解除挂载、释放 RingBuffer、关闭 BPF 对象。
        正常退出和提前返回都会触发。*/
    ~Session()
    {
        detach();
        if (ring)
            ring_buffer__free(ring);
        if (object)
            bpf_object__close(object);
    }
};

/*	保存用户态接收情况：
    `received` 是通过检查的事件数，`rejected` 是格式不符合要求的事件数。*/
struct EventContext {
    uint64_t received = 0;
    uint64_t rejected = 0;
    bool analyze = false;
    LockAnalyzer analyzer;
    uint64_t reported_end_ns = 0;
};

/*使用与 bpf_ktime_get_ns 相同的 CLOCK_MONOTONIC 时钟推进分析窗口。*/
uint64_t monotonic_ns()
{
    timespec now {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return static_cast<uint64_t>(now.tv_sec) * 1'000'000'000ULL + now.tv_nsec;
}

/*每个已结算窗口输出一次；原始事件格式保持兼容现有采集验收脚本。*/
void report_window(EventContext& context)
{
    if (context.analyzer.window_end_ns() != context.reported_end_ns) {
        std::cout << JsonReporter::report_locks(context.analyzer) << std::flush;
        context.reported_end_ns = context.analyzer.window_end_ns();
    }
}

/*收到 RingBuffer 数据时执行。
    检查事件长度、版本、类型等；有效则打印并计入 received，无效则计入 rejected。*/
int handle_event(void* opaque, void* data, size_t size)
{
    auto& context = *static_cast<EventContext*>(opaque);
    if (!data || size != sizeof(kylinrca_lock_event)) {
        ++context.rejected;
        return 0;
    }
    kylinrca_lock_event event {};
    std::memcpy(&event, data, sizeof(event));
    const uint32_t command = event.futex_op & FUTEX_CMD_MASK;
    if (event.header.version != KYLINRCA_EVENT_VERSION ||
        event.header.type != EVENT_TYPE_LOCK ||
        event.header.size != sizeof(event) ||
        !event.header.pid || !event.header.tid || event.reserved ||
        (command != FUTEX_WAIT && command != FUTEX_WAIT_BITSET)) {
        ++context.rejected;
        return 0;
    }

    ++context.received;
    if (context.analyze)
        context.analyzer.process(event);
    std::cout << "[LOCK] timestamp_ns=" << event.header.timestamp_ns
              << " pid=" << event.header.pid
              << " tid=" << event.header.tid
              << " lock_addr=0x" << std::hex << event.lock_addr << std::dec
              << " futex_op=" << event.futex_op
              << " duration_ns=" << event.duration_ns
              << " ret=" << event.ret << '\n';
    return 0;
}

/*读取 lock_stats，把每个 CPU 的计数相加，打印各统计项的总数。*/
bool print_stats(bpf_object* object)
{
    bpf_map* map = bpf_object__find_map_by_name(object, "lock_stats");
    const int cpus = libbpf_num_possible_cpus();
    if (!map || cpus <= 0)
        return false;

    /*将统计项编号 key 与输出名称 name 对应起来。*/
    struct StatName {
        uint32_t key;
        const char* name;
    };
    const StatName names[] = {
        {LOCK_STAT_FUTEX_ENTER, "futex_enter"},
        {LOCK_STAT_WAIT_ENTER, "wait_enter"},
        {LOCK_STAT_WAIT_EXIT, "wait_exit"},
        {LOCK_STAT_START_UPDATE_FAIL, "start_update_fail"},
        {LOCK_STAT_START_MISS, "start_miss"},
        {LOCK_STAT_DELETE_FAIL, "delete_fail"},
        {LOCK_STAT_RINGBUF_DROP, "ringbuf_drop"},
        {LOCK_STAT_BAD_TIMESTAMP, "bad_timestamp"},
        {LOCK_STAT_THREAD_EXIT_CLEANUP, "thread_exit_cleanup"},
    };
    std::vector<uint64_t> values(cpus);
    for (const auto& stat : names) {
        if (bpf_map_lookup_elem(bpf_map__fd(map), &stat.key, values.data()) != 0)
            return false;
        uint64_t total = 0;
        for (uint64_t value : values)
            total += value;
        std::cout << "[LOCK PROBE] " << stat.name << '=' << total << '\n';
    }
    return true;
}

}

/*安排整个执行过程：
  解析参数 → 打开并加载 BPF → 写配置 → 创建消费者 → 挂载探针 → 循环接收事件 → 退出清理并打印统计。*/
int main(int argc, char** argv)
{
    // 请求帮助时打印启动方式并退出。
    if (argc == 2 && std::string(argv[1]) == "--help") {
        std::cout << "Usage: " << argv[0]
                  << " [--duration seconds] [--pid pid] [--object path] [--analyze]\n";
        return 0;
    }
    // 解析运行时长、目标 PID 和 BPF 文件路径。
    Options options;
    if (!parse_options(argc, argv, options)) {
        std::cerr << "Invalid arguments. Use --help for usage.\n";
        return 1;
    }
    // 排除将观测程序自身指定为目标的情况。
    if (options.pid == static_cast<uint32_t>(getpid())) {
        std::cerr << "The target PID must not be the probe itself.\n";
        return 1;
    }

    // 收到 Ctrl+C 或终止信号时，通知主循环正常退出。
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    // 创建资源管理对象，并打开、解析 BPF 文件。
    Session session;
    session.object = bpf_object__open_file(options.object.c_str(), nullptr);
    //session.object 是一个指向 bpf_object 的指针。它指向的是 libbpf 在用户态创建的管理对象，保存打开的 BPF 文件所包含的程序、Map、类型信息等。
    if (!session.object) {
        std::cerr << "Cannot open BPF object: " << std::strerror(errno) << '\n';
        return 1;
    }
    // 创建内核 Map，校验并加载 BPF 程序，此时尚未挂载。
    if (bpf_object__load(session.object) != 0) {
        std::cerr << "Cannot load lock BPF object; check privileges, kernel BTF and libbpf output.\n";
        return 1;
    }
    // 将自身 PID、目标 PID、命名空间和 futex 参数写入配置 Map。
    if (!configure_tracer_pid(session.object) ||
        !configure_lock_probe(session.object, options.pid)) {
        std::cerr << "Cannot configure lock probe: " << std::strerror(errno) << '\n';
        return 1;
    }

    // 创建事件消费者，指定收到数据后执行 handle_event。
    EventContext context;
    context.analyze = options.analyze;
    if (context.analyze)
        context.analyzer.advance_window(monotonic_ns());
    bpf_map* events = bpf_object__find_map_by_name(session.object, "events");
    if (events)
        session.ring = ring_buffer__new(bpf_map__fd(events), handle_event, &context, nullptr);
    if (!session.ring) {
        std::cerr << "Cannot create lock RingBuffer consumer.\n";
        return 1;
    }

    // 先挂载退出和清理探针，最后挂载进入探针，并保存挂载连接。
    const char* programs[] = {"handle_lock_exit", "handle_lock_thread_exit", "handle_lock_enter"};
    for (const char* name : programs) {
        bpf_program* program = bpf_object__find_program_by_name(session.object, name);
        if (!program) {
            std::cerr << "Cannot find BPF program: " << name << '\n';
            return 1;
        }
        bpf_link* link = bpf_program__attach(program);
        if (!link) {
            std::cerr << "Cannot attach BPF program: " << name << '\n';
            return 1;
        }
        session.links.push_back(link);
    }

    // 通知外部程序探针已就绪，并记录本次运行的开始时间。
    std::cout << "[LOCK PROBE] ready target_pid=" << options.pid << std::endl;
    const auto started = std::chrono::steady_clock::now();
    int result = 0;
    while (running) {
        // 最多等待 100 毫秒；收到事件时由 libbpf 调用回调处理。
        const int error = ring_buffer__poll(session.ring, 100);
        // 等待被信号中断时，回到循环条件检查是否需要退出。
        if (error == -EINTR)
            continue;
        // 其他接收错误记为失败，并结束循环。
        if (error < 0) {
            std::cerr << "Lock RingBuffer poll failed: " << error << '\n';
            result = 1;
            break;
        }
        // 没有新事件时仍推进窗口，让已经结束的竞争可以恢复为 NORMAL。
        if (context.analyze) {
            context.analyzer.advance_window(monotonic_ns());
            report_window(context);
        }
        // 设置了运行时长时，到期退出；默认 0 表示持续运行。
        if (options.duration > 0 && std::chrono::steady_clock::now() - started >=
            std::chrono::seconds(options.duration))
            break;
    }

    // 停止探针继续产生事件。
    session.detach();
    // 接收缓冲区中的尾部事件，再汇总并打印内核统计。
    if (ring_buffer__consume(session.ring) < 0 || !print_stats(session.object)) {
        std::cerr << "Cannot drain lock events or read probe statistics.\n";
        result = 1;
    }
    if (context.analyze) {
        context.analyzer.flush(monotonic_ns());
        report_window(context);
    }
    // 打印用户态接收和拒绝的事件数量。
    std::cout << "[LOCK PROBE] received=" << context.received
              << " rejected=" << context.rejected << std::endl;
    // 返回退出状态；离开 main 时由 Session 自动释放剩余资源。
    return context.rejected || (context.analyze && context.analyzer.rejected_events()) ? 1 : result;
}
