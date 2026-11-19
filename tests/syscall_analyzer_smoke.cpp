#include "syscall_analyzer.h"

#include <iostream>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main()
{
    SyscallAnalyzer analyzer;

    syscall_event event1{};
    event1.header.pid = 1234;
    event1.syscall_id = SYS_read;
    event1.ret = 128;
    event1.duration_ns = 1000;

    syscall_event event2{};
    event2.header.pid = 1234;
    event2.syscall_id = SYS_read;
    event2.ret = 64;
    event2.duration_ns = 3000;

    syscall_event event3{};
    event3.header.pid = 1234;
    event3.syscall_id = SYS_write;
    event3.ret = -1;
    event3.duration_ns = 2000;

    analyzer.process(event1);
    analyzer.process(event2);
    analyzer.process(event3);

    const auto& all_stats = analyzer.stats();

    const auto& reads = all_stats.at(1234).at(SYS_read);
    const auto& writes = all_stats.at(1234).at(SYS_write);
    if (reads.count != 2 || reads.total_duration_ns != 4000 || reads.max_duration_ns != 3000 ||
        reads.error_count != 0 || writes.count != 1 || writes.error_count != 1) {
        std::cerr << "Syscall aggregation failed\n";
        return 1;
    }

    for (const auto& [pid, syscall_map] : all_stats) {

        for (const auto& [syscall_id, stat] : syscall_map) {

            uint64_t avg_duration_ns =
                stat.count == 0
                    ? 0
                    : stat.total_duration_ns / stat.count;

            std::cout
                << "pid=" << pid
                << " syscall="
                << SyscallAnalyzer::syscall_name(syscall_id)
                << " count=" << stat.count
                << " avg_ns=" << avg_duration_ns
                << " max_ns=" << stat.max_duration_ns
                << " errors=" << stat.error_count
                << std::endl;
        }
    }

    // 用户态可见的 PID 应能直接用于存活检查：保留自己，清理已退出的子进程。
    const pid_t child = fork();
    if (child < 0)
        return 1;
    if (child == 0)
        _exit(0);
    if (waitpid(child, nullptr, 0) != child)
        return 1;
    SyscallAnalyzer cleanup_analyzer;
    event1.header.pid = getpid();
    cleanup_analyzer.process(event1);
    event1.header.pid = child;
    cleanup_analyzer.process(event1);
    if (cleanup_analyzer.cleanup_exited_processes(std::chrono::seconds(0)) != 1 ||
        cleanup_analyzer.process_count() != 1 || cleanup_analyzer.stats().count(getpid()) != 1) {
        std::cerr << "Visible PID process cleanup failed\n";
        return 1;
    }
    return 0;
}
