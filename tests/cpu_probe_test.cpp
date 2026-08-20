#include <bpf/libbpf.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>

#include "event.h"


static volatile sig_atomic_t running = 1;


static void handle_signal(int)
{
    running = 0;
}


static int handle_cpu_event(
    void*,
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


    if (event->kind
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

    return 0;
}


int main()
{
    const char* bpf_object_path =
        "build/cpu.bpf.o";

    struct bpf_object* obj = nullptr;
    struct ring_buffer* rb = nullptr;

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
        nullptr,
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


    ring_buffer__free(rb);
    bpf_object__close(obj);

    return 0;
}
