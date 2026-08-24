#include <bpf/libbpf.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>

#include <bpf/bpf.h>
#include <unistd.h>

#include "event.h"
#include "cpu_analyzer.h"


static volatile sig_atomic_t running = 1;


static void handle_signal(int)
{
    running = 0;
}

/*
 * RingBuffer 回调函数。
 *
 * data:
 *   eBPF 通过 RingBuffer 发送上来的 cpu_event。
 *
 * ctx:
 *   创建 RingBuffer 时传进来的 CpuAnalyzer 地址。
 */
static int handle_cpu_event(
    void* ctx,
    void* data,
    size_t size)
{
    if (size != sizeof(cpu_event)) {
        std::cerr
            << "Unexpected CPU event size: "
            << size
            << std::endl;

        return 0;
    }

    const auto* event =
        static_cast<const cpu_event*>(data);


    if (event->header.version
        != KYLINRCA_EVENT_VERSION) {

        std::cerr
            << "Unsupported event version"
            << std::endl;

        return 0;
    }


    if (event->header.type
        != EVENT_TYPE_CPU) {

        std::cerr
            << "Unexpected event type"
            << std::endl;

        return 0;
    }


    if (event->header.size
        != sizeof(cpu_event)) {

        std::cerr
            << "Invalid CPU event header size"
            << std::endl;

        return 0;
    }

    auto* analyzer = static_cast<CpuAnalyzer*>(ctx);

    if (analyzer == nullptr) {
        std::cerr
            << "CpuAnalyzer context is null"
            << std::endl;
        return 0;
    }

    analyzer->process(*event);


/*    if (event->kind
        == CPU_EVENT_RUNQUEUE_DELAY) {

        std::cout
            << "[RUNQUEUE]"
            << " tid=" << event->header.tid
            << " delay_ns="
            << event->runqueue_delay_ns
            << std::endl;

    } else if (
        event->kind
        == CPU_EVENT_ONCPU_TIME) {

        std::cout
            << "[ONCPU]"
            << " tid=" << event->header.tid
            << " time_ns="
            << event->on_cpu_time_ns
            << std::endl;

    } else {

        std::cerr
            << "Unknown CPU event kind: "
            << event->kind
            << std::endl;
    }
*/
    return 0;
}


int main()
{
    const char* bpf_object_path = "build/cpu.bpf.o";

    struct bpf_object* obj = nullptr;
    struct ring_buffer* rb = nullptr;

    CpuAnalyzer analyzer;

    obj = bpf_object__open_file(
        bpf_object_path,
        nullptr);

    if (!obj) {
        std::cerr
            << "Failed to open "
            << bpf_object_path
            << std::endl;

        return 1;
    }


    int err = bpf_object__load(obj);

    if (err != 0) {
        std::cerr
            << "Failed to load CPU BPF object: "
            << err
            << std::endl;

        bpf_object__close(obj);
        return 1;
    }

    /*
     * 配置 tracer 自过滤。
     *
     * 与 syscall loader 保持相同 ABI：
     *
     * config_map[0] = 当前用户态 tracer PID
     */

    struct bpf_map* config_map =
        bpf_object__find_map_by_name(obj, "config_map");

    if (config_map == nullptr) {
        std::cerr
            << "Failed to find BPF map: config_map"
            << std::endl;

        bpf_object__close(obj);
        return 1;
    }

    int config_map_fd = bpf_map__fd(config_map);

    if (config_map_fd < 0) {
        std::cerr
            << "Failed to get config_map fd"
            << std::endl;

        bpf_object__close(obj);
        return 1;
    }

    __u32 config_key = 0;
    __u32 tracer_pid = static_cast<__u32>(getpid());

    if (bpf_map_update_elem(
            config_map_fd,
            &config_key,
            &tracer_pid,
            BPF_ANY) != 0) {

        std::cerr
            << "Failed to write tracer PID to config_map: "
            << std::strerror(errno)
            << std::endl;

        bpf_object__close(obj);
        return 1;
    }

    std::cout
        << "Tracer PID configured: "
        << tracer_pid
        << std::endl;

    /*
     * 自动 attach cpu.bpf.o 中所有
     * tracepoint program。
     */
    struct bpf_program* prog;

    bpf_object__for_each_program(prog, obj) {

        struct bpf_link* link =
            bpf_program__attach(prog);

        if (!link) {

            std::cerr
                << "Failed to attach: "
                << bpf_program__name(prog)
                << std::endl;

            bpf_object__close(obj);
            return 1;
        }

        /*
         * 当前 smoke test 生命周期一直到进程退出，
         * 先不单独管理 link。
         *
         * 下一步我们会补完整资源管理。
         */
    }


    struct bpf_map* events_map =
        bpf_object__find_map_by_name(
            obj,
            "events");

    if (!events_map) {

        std::cerr
            << "Failed to find CPU events map"
            << std::endl;

        bpf_object__close(obj);
        return 1;
    }


    int map_fd =
        bpf_map__fd(events_map);

    if (map_fd < 0) {

        std::cerr
            << "Failed to get CPU events map fd"
            << std::endl;

        bpf_object__close(obj);
        return 1;
    }


    rb = ring_buffer__new(
        map_fd,
        handle_cpu_event,
        &analyzer,
        nullptr);

    if (!rb) {

        std::cerr
            << "Failed to create CPU ring buffer"
            << std::endl;

        bpf_object__close(obj);
        return 1;
    }


    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);


    std::cout
        << "CPU probe running. Press Ctrl+C to stop."
        << std::endl;


    while (running) {

        err = ring_buffer__poll(
            rb,
            100);

        if (err == -EINTR)
            continue;

        if (err < 0) {

            std::cerr
                << "Ring buffer poll failed: "
                << err
                << std::endl;

            break;
        }
    }

    /*
     * BPF 端不会为每条事件都唤醒用户态，而是按批次通知。
     *
     * 收到退出信号时，RingBuffer 中可能还剩下不足一个通知批次的
     * 事件。它们已经提交到 RingBuffer，但还没有触发回调。如果
     * 直接输出 CpuAnalyzer 汇总，就会漏掉这部分尾部事件。
     *
     * ring_buffer__consume() 不等待新的通知，只消费当前已经存在的
     * 数据，因此适合在退出前做最后一次 drain。
     */
    while (true) {

        err = ring_buffer__consume(rb);

        if (err == -EINTR)
            continue;

        if (err < 0) {

            std::cerr
                << "Failed to drain CPU ring buffer: "
                << err
                << std::endl;
        }

        break;
    }

    /*
     * Ctrl+C 后输出 CpuAnalyzer 聚合结果。
     *
     * 注意：
     *
     * 上面的 [RUNQUEUE] / [ONCPU]
     * 是原始事件。
     *
     * 这里的 Summary
     * 才是 CpuAnalyzer 的统计结果。
     */
    std::cout
        << "\n=== CPU Analyzer Summary ==="
        << std::endl;


    const auto& stats =
        analyzer.stats();


    if (stats.empty()) {

        std::cout
            << "No CPU events were aggregated."
            << std::endl;

    } else {

        for (const auto& [tid, stat] : stats) {

            std::cout
                << "TID=" << tid
                << std::endl;

            std::cout
                << "  runqueue_count="
                << stat.runqueue_count
                << std::endl;

            std::cout
                << "  total_runqueue_delay_ns="
                << stat.total_runqueue_delay_ns
                << std::endl;

            std::cout
                << "  max_runqueue_delay_ns="
                << stat.max_runqueue_delay_ns
                << std::endl;

            std::cout
                << "  oncpu_count="
                << stat.oncpu_count
                << std::endl;

            std::cout
                << "  total_oncpu_time_ns="
                << stat.total_oncpu_time_ns
                << std::endl;

            std::cout
                << "  max_oncpu_time_ns="
                << stat.max_oncpu_time_ns
                << std::endl;
        }
    }


    ring_buffer__free(rb);
    bpf_object__close(obj);

    return 0;
}
