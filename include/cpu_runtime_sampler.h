#ifndef KYLINRCA_CPU_RUNTIME_SAMPLER_H
#define KYLINRCA_CPU_RUNTIME_SAMPLER_H
#include "cpu_runtime.h"
#include "proc_cpu_sampler.h"
#include <bpf/bpf.h>
#include <time.h>

/*向系统读取单调时钟，返回纳秒值*/
inline uint64_t cpu_monotonic_ns()
{
    timespec now {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return static_cast<uint64_t>(now.tv_sec) * 1000000000ULL + now.tv_nsec;
}

/*
 * Hash value 由内核整项替换，lookup 取得一致快照。
 * 正在运行的尾部也补到读取时刻，不必等线程 switch-out 才获得证据。
 * 读取耗时作为不确定度保留，绝不将 missing 转成 /proc 推算值。
 */
inline void read_cpu_runtime(int fd, ThreadCpuStatSample& sample)
{
    sample.bpf_valid = false;
    const uint32_t tid = sample.tid;
    cpu_runtime_value value {};
    const uint64_t before = cpu_monotonic_ns();
    if (bpf_map_lookup_elem(fd, &tid, &value) != 0)
        return;
    const uint64_t after = cpu_monotonic_ns();
    if (!before || after < before || value.pid != static_cast<uint32_t>(sample.pid)
        || (value.running_since_ns && value.running_since_ns > after))
        return;
    sample.bpf_total_ns = value.completed_ns;
    if (value.running_since_ns)
        sample.bpf_total_ns += after - value.running_since_ns;
    sample.bpf_birth_ns = value.birth_ns;
    sample.bpf_sample_ns = after;
    sample.bpf_uncertainty_ns = after - before;
    sample.bpf_valid = true;
}

/* 使用相同线程、相同生命周期的两个累计快照做差。 */
inline bool calculate_runtime_delta(const ThreadCpuStatSample& previous,
                                    const ThreadCpuStatSample& current,
                                    uint64_t& runtime_ns, uint64_t& window_ns)
{
    // 失败时只输出 unavailable 对应的空值，不泄漏尚未验证的候选差值。
    runtime_ns = 0;
    window_ns = 0;
    if (!previous.bpf_valid || !current.bpf_valid ||
        previous.pid != current.pid || previous.tid != current.tid ||
        previous.starttime_ticks != current.starttime_ticks ||
        previous.bpf_birth_ns != current.bpf_birth_ns ||
        current.bpf_sample_ns <= previous.bpf_sample_ns ||
        current.bpf_total_ns < previous.bpf_total_ns)
        return false;
    const uint64_t runtime = current.bpf_total_ns - previous.bpf_total_ns;
    const uint64_t window = current.bpf_sample_ns - previous.bpf_sample_ns;
    /* 不截断成一个好看的数字：超出物理边界与读数不确定度就报告无效。 */
    if (runtime > window + previous.bpf_uncertainty_ns + current.bpf_uncertainty_ns)
        return false;
    runtime_ns = runtime;
    window_ns = window;
    return true;
}
#endif
