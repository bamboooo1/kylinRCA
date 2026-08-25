#include "cpu_analyzer.h"

#include <cassert>
#include <iostream>

int main()
{
    CpuAnalyzer analyzer;

    // 第一次 runqueue delay：TID 1001 等待 2 ms
    cpu_event event1{};
    event1.header.tid = 1001;
    event1.kind = CPU_EVENT_RUNQUEUE_DELAY;
    event1.runqueue_delay_ns = 2'000'000;

    analyzer.process(event1);

    // 第二次 runqueue delay：同一个线程等待 5 ms
    cpu_event event2{};
    event2.header.tid = 1001;
    event2.kind = CPU_EVENT_RUNQUEUE_DELAY;
    event2.runqueue_delay_ns = 5'000'000;

    analyzer.process(event2);

    // 一次 on-CPU：同一个线程运行 8 ms
    cpu_event event3{};
    event3.header.tid = 1001;
    event3.kind = CPU_EVENT_ONCPU_TIME;
    event3.on_cpu_time_ns = 8'000'000;

    analyzer.process(event3);

    // 第二个线程：TID 2002
    cpu_event event4{};
    event4.header.tid = 2002;
    event4.kind = CPU_EVENT_RUNQUEUE_DELAY;
    event4.runqueue_delay_ns = 10'000'000;

    analyzer.process(event4);

    cpu_event event5{};
    event5.header.tid = 2002;
    event5.kind = CPU_EVENT_ONCPU_TIME;
    event5.on_cpu_time_ns = 20'000'000;

    analyzer.process(event5);

    const auto& stats = analyzer.stats();

    assert(stats.count(1001) == 1); // 检查tid
    assert(stats.count(2002) == 1);

    const CpuStats& stat = stats.at(1001);
    const CpuStats& stat2 = stats.at(2002);

    assert(stat.runqueue_count == 2); // 检查tid为'1001'的线程的stat
    assert(stat.total_runqueue_delay_ns == 7'000'000);
    assert(stat.max_runqueue_delay_ns == 5'000'000);

    assert(stat.oncpu_count == 1);
    assert(stat.total_oncpu_time_ns == 8'000'000);
    assert(stat.max_oncpu_time_ns == 8'000'000);

    assert(stat2.runqueue_count == 1);
    assert(stat2.total_runqueue_delay_ns == 10'000'000);
    assert(stat2.max_runqueue_delay_ns == 10'000'000);
    
    assert(stat2.oncpu_count == 1);
    assert(stat2.total_oncpu_time_ns == 20'000'000);
    assert(stat2.max_oncpu_time_ns == 20'000'000);

    std::cout << "cpu_analyzer_test passed\n";

    return 0;
}
