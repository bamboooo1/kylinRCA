#ifndef KYLINRCA_CPU_ANALYZER_H
#define KYLINRCA_CPU_ANALYZER_H

#include "event.h"

#include <cstdint>
#include <unordered_map>

struct CpuStats {
    uint64_t runqueue_count = 0;
    uint64_t total_runqueue_delay_ns = 0;
    uint64_t max_runqueue_delay_ns = 0;

    uint64_t oncpu_count = 0;
    uint64_t total_oncpu_time_ns = 0;
    uint64_t max_oncpu_time_ns = 0;

    /*
     * 返回平均 runqueue delay。
     * 没有收到相应事件时返回 0，避免除以 0。
     */
    uint64_t average_runqueue_delay_ns() const
    {
        if (runqueue_count == 0)
            return 0;

        return total_runqueue_delay_ns /
               runqueue_count;
    }

    /*
     * 返回平均 on-CPU time。
     * 这里表示一次调度时间片的平均运行时间，
     * 不是进程 CPU 使用率。
     */
    uint64_t average_oncpu_time_ns() const
    {
        if (oncpu_count == 0)
            return 0;

        return total_oncpu_time_ns /
               oncpu_count;
    }
};

class CpuAnalyzer {
public:
    void process(const cpu_event& event);

    const std::unordered_map<uint32_t, CpuStats>& stats() const;

private:
    std::unordered_map<uint32_t, CpuStats> stats_;
};

#endif
