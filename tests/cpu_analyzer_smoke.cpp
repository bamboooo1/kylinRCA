#include "cpu_analyzer.h"

#include <cassert>
#include <iostream>

namespace {

CpuUsageObservation make_usage(
    double system_percent,
    int pid,
    double process_percent)
{
    CpuUsageObservation observation{};
    observation.system_usage_percent = system_percent;
    observation.pid = pid;
    observation.process_usage_percent = process_percent;
    return observation;
}

cpu_event make_runqueue_event(
    uint32_t pid,
    uint32_t tid,
    uint64_t delay_ns)
{
    cpu_event event{};
    event.header.pid = pid;
    event.header.tid = tid;
    event.kind = CPU_EVENT_RUNQUEUE_DELAY;
    event.runqueue_delay_ns = delay_ns;
    return event;
}

cpu_event make_oncpu_event(
    uint32_t pid,
    uint32_t tid,
    uint64_t duration_ns)
{
    cpu_event event{};
    event.header.pid = pid;
    event.header.tid = tid;
    event.kind = CPU_EVENT_ONCPU_TIME;
    event.on_cpu_time_ns = duration_ns;
    return event;
}

void test_event_aggregation()
{
    CpuAnalyzer analyzer;

    analyzer.process(
        make_runqueue_event(
            101,
            1001,
            2'000'000));

    analyzer.process(
        make_runqueue_event(
            101,
            1001,
            5'000'000));

    analyzer.process(
        make_oncpu_event(
            101,
            1001,
            8'000'000));

    analyzer.process(
        make_runqueue_event(
            202,
            2002,
            10'000'000));

    analyzer.process(
        make_oncpu_event(
            202,
            2002,
            20'000'000));

    assert(analyzer.thread_count() == 2);

    const CpuStats* first =
        analyzer.find(1001);

    const CpuStats* second =
        analyzer.find(2002);

    assert(first != nullptr);
    assert(second != nullptr);

    assert(first->pid == 101);
    assert(first->tid == 1001);
    assert(first->runqueue_count == 2);
    assert(first->total_runqueue_delay_ns == 7'000'000);
    assert(first->average_runqueue_delay_ns() == 3'500'000);
    assert(first->max_runqueue_delay_ns == 5'000'000);
    assert(first->oncpu_count == 1);
    assert(first->total_oncpu_time_ns == 8'000'000);
    assert(first->average_oncpu_time_ns() == 8'000'000);
    assert(first->max_oncpu_time_ns == 8'000'000);

    assert(second->pid == 202);
    assert(second->tid == 2002);

    /*
     * 未知事件和 idle TID 不能污染统计表。
     */
    cpu_event unknown{};
    unknown.header.pid = 303;
    unknown.header.tid = 3003;
    unknown.kind = 999;

    analyzer.process(unknown);

    cpu_event idle =
        make_oncpu_event(
            0,
            0,
            1'000'000);

    analyzer.process(idle);

    assert(analyzer.find(3003) == nullptr);
    assert(analyzer.find(0) == nullptr);
    assert(analyzer.thread_count() == 2);
}

void test_high_usage_and_recovery()
{
    CpuAnalyzerConfig config;
    config.alert_consecutive_samples = 3;
    config.recovery_consecutive_samples = 3;

    CpuAnalyzer analyzer(config);

    const CpuUsageObservation high =
        make_usage(
            40.0,
            303,
            90.0);

    analyzer.process_usage(high);
    assert(analyzer.diagnosis().state ==
           CpuDiagnosisState::Normal);
    assert(analyzer.diagnosis().consecutive_samples == 1);

    analyzer.process_usage(high);
    assert(analyzer.diagnosis().state ==
           CpuDiagnosisState::Normal);
    assert(analyzer.diagnosis().consecutive_samples == 2);

    analyzer.process_usage(high);
    assert(analyzer.diagnosis().state ==
           CpuDiagnosisState::HighUsage);
    assert(analyzer.diagnosis().pid == 303);

    const CpuUsageObservation recovered =
        make_usage(
            20.0,
            303,
            10.0);

    analyzer.process_usage(recovered);
    analyzer.process_usage(recovered);

    assert(analyzer.diagnosis().state ==
           CpuDiagnosisState::HighUsage);
    assert(analyzer.diagnosis().consecutive_samples == 2);

    analyzer.process_usage(recovered);

    assert(analyzer.diagnosis().state ==
           CpuDiagnosisState::Normal);
    assert(analyzer.diagnosis().consecutive_samples == 0);
}

void test_runqueue_pressure_and_window_reset()
{
    CpuAnalyzerConfig config;
    config.alert_consecutive_samples = 3;
    config.recovery_consecutive_samples = 3;

    CpuAnalyzer analyzer(config);

    const CpuUsageObservation busy =
        make_usage(
            90.0,
            0,
            0.0);

    for (uint32_t sample = 0;
         sample < 3;
         sample++) {

        analyzer.process(
            make_runqueue_event(
                400,
                4000 + sample,
                15'000'000));

        analyzer.process_usage(busy);

        if (sample < 2) {
            assert(analyzer.diagnosis().state ==
                   CpuDiagnosisState::Normal);
        }
    }

    assert(analyzer.diagnosis().state ==
           CpuDiagnosisState::RunqueuePressure);

    assert(analyzer.diagnosis().max_runqueue_delay_ns ==
           15'000'000);

    /*
     * 下一窗口没有调度事件，历史最大值必须归零。
     */
    const CpuUsageObservation normal =
        make_usage(
            20.0,
            0,
            0.0);

    analyzer.process_usage(normal);

    assert(analyzer.diagnosis().max_runqueue_delay_ns == 0);
    assert(analyzer.diagnosis().average_runqueue_delay_ns == 0);

    /*
     * window_stats_ 清空不应影响生命周期累计 stats_。
     */
    assert(analyzer.thread_count() == 3);
    assert(analyzer.stats().at(4000).pid == 400);
}

void test_high_usage_survives_pressure_changes()
{
    CpuAnalyzerConfig config;
    config.alert_consecutive_samples = 3;

    CpuAnalyzer analyzer(config);

    const CpuUsageObservation process_high =
        make_usage(
            30.0,
            505,
            90.0);

    const CpuUsageObservation system_high =
        make_usage(
            90.0,
            0,
            0.0);

    analyzer.process_usage(process_high);

    analyzer.process(
        make_runqueue_event(
            606,
            6006,
            20'000'000));

    analyzer.process_usage(system_high);
    analyzer.process_usage(process_high);

    assert(analyzer.diagnosis().state ==
           CpuDiagnosisState::HighUsage);

    assert(analyzer.diagnosis().consecutive_samples == 0);
}

void test_system_wide_culprit_selection()
{
    CpuAnalyzerConfig config;
    config.alert_consecutive_samples = 1;

    CpuAnalyzer analyzer(config);

    /*
     * PID 700 的总使用率最高，其中 TID 702 是使用率最高的责任线程。
     */
    CpuProcessUsageObservation busy_process;
    busy_process.pid = 700;
    busy_process.comm = "busy-process";
    busy_process.process_usage_percent = 150.0;
    busy_process.threads = {
        {701, "worker-a", 40.0},
        {702, "worker-b", 110.0}
    };

    CpuProcessUsageObservation second_process;
    second_process.pid = 800;
    second_process.comm = "second-process";
    second_process.process_usage_percent = 80.0;
    second_process.threads = {
        {801, "worker-c", 80.0}
    };

    CpuUsageObservation observation;
    observation.system_usage_percent = 90.0;
    observation.processes = {
        second_process,
        busy_process
    };

    analyzer.process(
        make_oncpu_event(
            700,
            702,
            7'000'000));

    analyzer.process(
        make_runqueue_event(
            700,
            702,
            2'000'000));

    /*
     * TID 801 的 runqueue 延迟更大，所以它是受害线程；但它的 CPU
     * 使用率低于 TID 702，不能被误判为高 CPU 责任线程。
     */
    analyzer.process(
        make_runqueue_event(
            800,
            801,
            20'000'000));

    analyzer.process_usage(observation);

    const CpuDiagnosis& diagnosis =
        analyzer.diagnosis();

    assert(diagnosis.culprit_pid == 700);
    assert(diagnosis.culprit_process_comm ==
           "busy-process");
    assert(diagnosis.culprit_process_usage_percent ==
           150.0);
    assert(diagnosis.culprit_tid == 702);
    assert(diagnosis.culprit_thread_comm ==
           "worker-b");
    assert(diagnosis.culprit_thread_usage_percent ==
           110.0);
    assert(diagnosis.culprit_oncpu_time_ns ==
           7'000'000);
    assert(diagnosis.culprit_runqueue_delay_ns ==
           2'000'000);

    assert(diagnosis.victim_pid == 800);
    assert(diagnosis.victim_tid == 801);
    assert(diagnosis.victim_max_runqueue_delay_ns ==
           20'000'000);
}

} // namespace

int main()
{
    test_event_aggregation();
    test_high_usage_and_recovery();
    test_runqueue_pressure_and_window_reset();
    test_system_wide_culprit_selection();
    test_high_usage_survives_pressure_changes();

    std::cout
        << "cpu_analyzer_test passed"
        << std::endl;

    return 0;
}
