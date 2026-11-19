#ifndef KYLINRCA_IO_ANALYZER_H
#define KYLINRCA_IO_ANALYZER_H
#include "event.h"
#include <cstdint>
#include <map>
#include <vector>

// 设置分析规则和容量限制
struct IoAnalyzerConfig {
    uint64_t latency_threshold_ns = 10'000'000; //设备 P95 达到这个值时满足延迟条件
    uint64_t min_samples = 10; //设备在窗口内至少有这么多样本才允许告警
    std::size_t max_samples_per_device = 100000; //每个设备最多保存 100000 个样本
    std::size_t max_devices = 128; //每个窗口最多保存 128 个设备
    std::size_t max_total_samples = 100000; //所有设备合计最多保存 100000 个样本
};

//保存一个设备在一个窗口内的统计结果
struct IoStats {
    uint32_t major = 0, minor = 0;
    uint64_t count = 0, bytes = 0, reads = 0, writes = 0, errors = 0;
    uint64_t avg_duration_ns = 0, p95_duration_ns = 0, p99_duration_ns = 0;
    bool io_latency = false;
};

//保存所有设备在一个窗口内的统计结果
struct IoReport {
    uint64_t window_start_ns = 0, window_end_ns = 0;
    //使用了什么阈值和最低样本数
    uint64_t latency_threshold_ns = 0, min_samples = 0;
    //协议字段等检查不通过的事件数；属于已经关闭窗口的迟到事件数；超出分析器容量而被拒收的事件数
    uint64_t invalid_events = 0, late_events = 0, capacity_drops = 0;
    std::vector<IoStats> devices;
};
// Rejection reasons remain distinct for callers and window statistics.
enum class IoProcessResult { Accepted, Invalid, Late, CapacityDropped };

class IoAnalyzer {
public:
    explicit IoAnalyzer(uint64_t start_ns, IoAnalyzerConfig config = {});//输入当前窗口开始的时间以及使用的配置
    bool process(const kylinrca_io_event& event);
    IoProcessResult process_detailed(const kylinrca_io_event& event);
    // Consume only events <= end_ns before finishing; end_ns must advance.
    // Delayed events from a closed window are counted and rejected.
    IoReport finish_window(uint64_t end_ns);
private:
    //为每个设备准备一个桶。请求到达后，把延迟放进 durations，把延迟加到 total_ns，再更新 stats 中的请求数、bytes 等统计。
    struct Bucket {
        IoStats stats;
        long double total_ns = 0;
        std::vector<uint64_t> durations;
    };
    uint64_t start_;
    IoAnalyzerConfig config_;
    std::map<uint64_t, Bucket> buckets_;
    uint64_t invalid_ = 0, late_ = 0, dropped_ = 0;
    std::size_t samples_ = 0;
};
#endif
