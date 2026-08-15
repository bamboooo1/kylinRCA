#include "syscall_analyzer.h"

#include <iostream>
#include <sys/syscall.h>

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

    return 0;
}