#include "cpu_runtime_sampler.h"
#include "cpu_analyzer.h"
#include <cassert>
#include <iostream>

int main()
{
    ThreadCpuStatSample a, b;
    a.pid = b.pid = 100; a.tid = b.tid = 101;
    a.starttime_ticks = b.starttime_ticks = 12;
    a.bpf_valid = b.bpf_valid = true;
    a.bpf_birth_ns = b.bpf_birth_ns = 120000000;
    a.bpf_sample_ns = 1000000000; b.bpf_sample_ns = 2000000000;
    a.bpf_total_ns = 500000000; b.bpf_total_ns = 1500000000;
    uint64_t duration = 0, window = 0;
    assert(calculate_runtime_delta(a, b, duration, window));
    assert(duration == 1000000000 && window == 1000000000);
    // 同号 TID 被复用、快照缺失、累计倒退和不可能的跨窗值必须拒绝。
    auto bad = b; bad.bpf_birth_ns++;
    assert(!calculate_runtime_delta(a, bad, duration, window));
    bad = b; bad.starttime_ticks++;
    assert(!calculate_runtime_delta(a, bad, duration, window));
    bad = b; bad.bpf_valid = false;
    assert(!calculate_runtime_delta(a, bad, duration, window));
    bad = b; bad.bpf_total_ns = 1;
    assert(!calculate_runtime_delta(a, bad, duration, window));
    bad = b; bad.bpf_total_ns = 4890000000ULL;
    assert(!calculate_runtime_delta(a, bad, duration, window));
    assert(duration == 0 && window == 0);

    a.utime = 100; b.utime = 150;
    a.sampled_at_ns = 1000000000; b.sampled_at_ns = 2000000000;
    double usage_percent = 0;
    assert(calculate_thread_cpu_usage(a, b, 99.0, 100, usage_percent));
    assert(usage_percent == 50.0); // 使用每线程 1 秒，而不是传入的全局 99 秒。
    bad = b; bad.starttime_ticks++;
    assert(!calculate_thread_cpu_usage(a, bad, 1.0, 100, usage_percent));

    CpuAnalyzer analyzer;
    cpu_event old {};
    old.header.pid = 100; old.header.tid = 101;
    old.kind = CPU_EVENT_ONCPU_TIME;
    old.on_cpu_time_ns = 4390000000ULL;
    analyzer.process(old);
    CpuThreadUsageObservation thread {101, "worker", 100.0};
    thread.runtime_valid = true;
    thread.runtime_ns = 1000000000;
    thread.runtime_window_ns = 1000000000;
    CpuProcessUsageObservation process;
    process.pid = 100; process.process_usage_percent = 100;
    process.threads.push_back(thread);
    CpuUsageObservation observation;
    observation.has_runtime_snapshots = true;
    observation.system_usage_percent = 100;
    observation.processes.push_back(process);
    analyzer.process_usage(observation);
    // 迟到的完整运行片段不能覆盖本窗口的累计快照差分。
    assert(analyzer.diagnosis().culprit_oncpu_time_ns == 1000000000);
    assert(analyzer.diagnosis().culprit_runtime_valid);
    analyzer.process_usage(observation);
    assert(analyzer.diagnosis().culprit_oncpu_time_ns == 1000000000);
    // 缺失快照要显式无效，不能把零值伪装为“没有运行”。
    observation.processes[0].threads[0].runtime_valid = false;
    observation.processes[0].threads[0].runtime_ns = 0;
    analyzer.process_usage(observation);
    assert(!analyzer.diagnosis().culprit_runtime_valid);

    // 事件按发生时间归窗：迟到旧事件不进入当前窗口，未来事件保留。
    CpuAnalyzer windows;
    cpu_event delay {};
    delay.header.pid = 100; delay.header.tid = 101;
    delay.kind = CPU_EVENT_RUNQUEUE_DELAY; delay.runqueue_delay_ns = 123;
    delay.header.timestamp_ns = 90; windows.process(delay);
    delay.header.timestamp_ns = 150; windows.process(delay);
    delay.header.timestamp_ns = 250; delay.runqueue_delay_ns = 456;
    windows.process(delay);
    CpuUsageObservation usage;
    usage.window_start_ns = 100; usage.timestamp_ns = 200;
    windows.process_usage(usage);
    assert(windows.diagnosis().max_runqueue_delay_ns == 123);
    usage.window_start_ns = 200; usage.timestamp_ns = 300;
    windows.process_usage(usage);
    assert(windows.diagnosis().max_runqueue_delay_ns == 456);
    CpuAnalyzerConfig config;
    config.alert_consecutive_samples = 1;
    config.recovery_consecutive_samples = 2;
    CpuAnalyzer pressure(config);
    delay.header.timestamp_ns = 0;
    delay.runqueue_delay_ns = 20000000;
    pressure.process(delay);
    CpuUsageObservation busy;
    busy.system_usage_percent = 100;
    pressure.process_usage(busy);
    assert(pressure.diagnosis().state == CpuDiagnosisState::RunqueuePressure);
    pressure.process_usage(busy);
    pressure.process_usage(busy);
    assert(pressure.diagnosis().state == CpuDiagnosisState::HighUsage);
    pressure.process(delay);
    busy.scheduling_evidence_valid = false;
    pressure.process_usage(busy);
    assert(pressure.diagnosis().state == CpuDiagnosisState::HighUsage);

    std::cout << "CPU runtime and window regression passed\n";
}
