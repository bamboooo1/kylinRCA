#include "io_analyzer.h"
#include <algorithm>
#include <stdexcept>

//保存配置并检查参数
IoAnalyzer::IoAnalyzer(uint64_t start_ns, IoAnalyzerConfig config)
    : start_(start_ns), config_(config)
{
    if (!config.min_samples || !config.latency_threshold_ns ||
        !config.max_samples_per_device || !config.max_devices || !config.max_total_samples)
        throw std::invalid_argument("I/O thresholds and capacities must be positive");
}

bool IoAnalyzer::process(const kylinrca_io_event& e)
{
    return process_detailed(e) == IoProcessResult::Accepted;
}

IoProcessResult IoAnalyzer::process_detailed(const kylinrca_io_event& e)
{
    // 检查事件是否合法
    if (e.header.version != KYLINRCA_EVENT_VERSION ||
        e.header.type != EVENT_TYPE_IO || e.header.size != sizeof(e) ||
        e.header.pid || e.header.tid || e.operation > IO_OP_OTHER || e.duration_ns > e.header.timestamp_ns) {
        ++invalid_; return IoProcessResult::Invalid;
    }
    // 拒绝旧窗口事件，并检查全窗口容量
    if (e.header.timestamp_ns <= start_) { ++late_; return IoProcessResult::Late; }
    if (samples_ >= config_.max_total_samples) { ++dropped_; return IoProcessResult::CapacityDropped; }

    // 把主次设备号组成一个键，再查找这个设备的桶
    uint64_t key = (uint64_t(e.dev_major) << 32) | e.dev_minor;
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {//如果没有找到这个设备
        if (buckets_.size() >= config_.max_devices) { ++dropped_; return IoProcessResult::CapacityDropped; }
        it = buckets_.emplace(key, Bucket{}).first; //it->first为设备键key
        it->second.stats.major = e.dev_major; //it->second为统计桶bucket
        it->second.stats.minor = e.dev_minor;
    }
    auto& b = it->second;
    if (b.durations.size() >= config_.max_samples_per_device) {
        ++dropped_; return IoProcessResult::CapacityDropped;
    }
    ++samples_; //全窗口样本数加 1
    ++b.stats.count; //本设备样本数加 1
    b.stats.bytes += e.bytes;
    b.stats.reads += e.operation == IO_OP_READ;
    b.stats.writes += e.operation == IO_OP_WRITE;
    b.stats.errors += e.status != 0;
    b.total_ns += e.duration_ns;
    b.durations.push_back(e.duration_ns);
    return IoProcessResult::Accepted;
}

//先检查时间，再填写报告基本信息
IoReport IoAnalyzer::finish_window(uint64_t end_ns)
{
    if (end_ns <= start_) throw std::invalid_argument("window must advance");
    // Caller supplies a monotonic cutoff after consuming the current batch.
    IoReport report;
    report.latency_threshold_ns = config_.latency_threshold_ns;
    report.min_samples = config_.min_samples;
    report.window_start_ns = start_;
    report.window_end_ns = end_ns;
    report.invalid_events = invalid_; report.late_events = late_;
    report.capacity_drops = dropped_;
    for (auto& pair : buckets_) {
        auto& b = pair.second;
        std::sort(b.durations.begin(), b.durations.end()); //遍历所有设备，对每个设备内的所有事件延迟进行排序
        auto quantile = [&](uint64_t percent) {
            return b.durations[(percent * b.durations.size() + 99) / 100 - 1];
        };
        b.stats.avg_duration_ns = static_cast<uint64_t>(b.total_ns / b.stats.count);
        b.stats.p95_duration_ns = quantile(95);
        b.stats.p99_duration_ns = quantile(99);
        b.stats.io_latency = b.stats.count >= config_.min_samples &&
            b.stats.p95_duration_ns >= config_.latency_threshold_ns;
        report.devices.push_back(b.stats);
    }
    buckets_.clear(); samples_ = 0; invalid_ = late_ = dropped_ = 0; start_ = end_ns;
    return report;
}
