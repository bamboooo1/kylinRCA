#include "json_reporter.h"
#include "ring_buffer_consumer.h"
#include "syscall_analyzer.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <unistd.h>

// Ctrl+C 的信号处理函数会把它设为 1，让下面的轮询循环退出；volatile 保证循环每次都重新读取它，sig_atomic_t 保证信号处理函数异步修改它时，简单读写不会做到一半被打断。
static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int)
{
    stop_requested = 1;
}

int main()
{
    const char* bpf_object_path = "build/syscall.bpf.o";

    // 1. 打开 BPF ELF object
    struct bpf_object* obj = bpf_object__open_file(bpf_object_path, nullptr);

    if (obj == nullptr) {
        std::cerr << "Failed to open BPF object: " << std::strerror(errno) << std::endl;
        return 1;
    }

    std::cout << "Successfully opened BPF object: " << bpf_object_path << std::endl;

    // 2. 查看 object 中有哪些 BPF program：int handle_sys_enter(...)和int handle_sys_exit(...)
    struct bpf_program* prog = nullptr;

    while ((prog = bpf_object__next_program(obj, prog)) != nullptr) {
        std::cout << "BPF program name: " << bpf_program__name(prog) << std::endl;
        std::cout << "BPF section: " << bpf_program__section_name(prog) << std::endl; // 这个程序挂载到内核的哪个位置
    }

    // 3. 把 BPF Maps 和 Programs 加载进内核
    int err = bpf_object__load(obj);

    if (err != 0) {
        std::cerr << "Failed to load BPF object, error: " << err << std::endl;
        bpf_object__close(obj);
        return 1;
    }
    std::cout << "Successfully loaded BPF object into kernel" << std::endl;

    // 4. 找到 config_map
    struct bpf_map* config_map =  bpf_object__find_map_by_name(obj, "config_map");
    if (config_map == nullptr) {
        std::cerr << "Failed to find BPF map: config_map" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    int config_map_fd = bpf_map__fd(config_map);
    if (config_map_fd < 0) {
        std::cerr << "Failed to get config_map fd" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    // config_map[0] = 当前 tracer 自己的 PID
    __u32 config_key = 0;
    __u32 tracer_pid = static_cast<__u32>(getpid());

    if (bpf_map_update_elem(config_map_fd, &config_key, &tracer_pid, BPF_ANY) != 0) {
        std::cerr << "Failed to write tracer PID to config_map: " << std::strerror(errno) << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    std::cout << "Tracer PID configured: " << tracer_pid << std::endl;

    // 5. 找 sys_enter BPF program
    struct bpf_program* enter_prog = bpf_object__find_program_by_name(obj, "handle_sys_enter");

    if (enter_prog == nullptr) {
        std::cerr << "Failed to find BPF program: handle_sys_enter" << std::endl;
        bpf_object__close(obj);
        return 1;
    }

    // 6. attach sys_enter
    struct bpf_link* enter_link = bpf_program__attach(enter_prog);
    if (enter_link == nullptr) {
        std::cerr << "Failed to attach handle_sys_enter: " << std::strerror(errno) << std::endl;
        bpf_object__close(obj);
        return 1;
    }
    std::cout << "Successfully attached handle_sys_enter" << std::endl;

    // 7. 找 sys_exit BPF program
    struct bpf_program* exit_prog = bpf_object__find_program_by_name(obj, "handle_sys_exit");

    if (exit_prog == nullptr) {
        std::cerr << "Failed to find BPF program: handle_sys_exit" << std::endl;
        bpf_link__destroy(enter_link);
        bpf_object__close(obj);
        return 1;
    }

    // 8. attach sys_exit
    struct bpf_link* exit_link = bpf_program__attach(exit_prog);

    if (exit_link == nullptr) {
        std::cerr << "Failed to attach handle_sys_exit: " << std::strerror(errno) << std::endl;
        bpf_link__destroy(enter_link);
        bpf_object__close(obj);
        return 1;
    }

    std::cout << "Successfully attached handle_sys_exit" << std::endl;

    int result = 0;

    // 单独作用域：
    // 保证 RingBufferConsumer 在 bpf_object 被关闭之前析构
    {
        EventQueue queue;
        RingBufferConsumer consumer(queue);
        SyscallAnalyzer analyzer;

        // 9. 让用户态 Consumer 监听 BPF 中的 events RingBuffer
        if (!consumer.init(obj)) {
            std::cerr << "Failed to initialize RingBuffer consumer" << std::endl;

            result = 1;
        } else {
            std::signal(SIGINT, handle_signal);

            std::cout << "Collecting syscall events..." << std::endl;

            std::cout << "Press Ctrl+C to stop and print JSON" << std::endl;

            // 10. 不断 poll 内核 RingBuffer
            while (!stop_requested) {
                int event_count = consumer.poll(100);

                if (event_count < 0) {
                    if (event_count == -EINTR) {continue;}

                    std::cerr << "RingBuffer poll failed: " << event_count << std::endl;
                    result = 1;
                    break;
                }

                // handle_event() 已经把这些事件 push 到 EventQueue
                // 现在再交给 Analyzer
                for (int i = 0; i < event_count; ++i) {
                    syscall_event event = queue.pop();
                    analyzer.process(event);
                }
            }

            // 11. 将真实内核事件统计转换成 JSON
            std::cout << JsonReporter::report_syscalls(analyzer) << std::endl;
        }
    }

    // 12. detach
    bpf_link__destroy(exit_link);
    bpf_link__destroy(enter_link);

    std::cout << "BPF programs detached" << std::endl;

    // 13. 释放 BPF object
    bpf_object__close(obj);

    return result;
}
