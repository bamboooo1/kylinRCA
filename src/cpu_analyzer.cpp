#include "cpu_analyzer.h"

#include <algorithm>

void CpuAnalyzer::process(const cpu_event& event)
{
    /*
     * CpuAnalyzer 当前只接受两种 CPU 事件。
     *
     * 必须在访问 stats_[tid] 之前完成判断，否则未知事件也会
     * 在 unordered_map 中创建一个内容全为 0 的统计项。
     */
    if (event.kind != CPU_EVENT_RUNQUEUE_DELAY &&
        event.kind != CPU_EVENT_ONCPU_TIME) {
        return;
    }

    /*
     * idle task 的 TID 为 0，不应该进入用户态聚合结果。
     * 正常情况下 BPF 已经过滤，这里再次防御，避免单元测试、
     * 协议错误或未来其他调用方污染统计。
     */
    if (event.header.tid == 0) {
        return;
    }

    const uint32_t tid = event.header.tid;
    CpuStats& stat = stats_[tid];

    if (event.kind == CPU_EVENT_RUNQUEUE_DELAY) {

        stat.runqueue_count++;
        stat.total_runqueue_delay_ns +=
            event.runqueue_delay_ns;

        stat.max_runqueue_delay_ns =
            std::max(
                stat.max_runqueue_delay_ns,
                static_cast<uint64_t>(
                    event.runqueue_delay_ns));

    } else {

        stat.oncpu_count++;
        stat.total_oncpu_time_ns +=
            event.on_cpu_time_ns;

        stat.max_oncpu_time_ns =
            std::max(
                stat.max_oncpu_time_ns,
                static_cast<uint64_t>(
                    event.on_cpu_time_ns));
    }
}

const std::unordered_map<uint32_t, CpuStats>& CpuAnalyzer::stats() const
{
    return stats_;
}
