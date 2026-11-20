#include "io_analyzer.h"
#include <algorithm>
#include <stdexcept>

//保存配置并检查参数
IoAnalyzer::IoAnalyzer(uint64_t start_ns, IoAnalyzerConfig config)
    : start_(start_ns), config_(config)
{
    if (!config.min_samples || !config.latency_threshold_ns ||
        !config.max_samples_per_device || !config.max_devices || !config.max_total_samples ||
        !config.alert_consecutive_windows || !config.recovery_consecutive_windows)
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
    if (it == buckets_.end()) {//如果没有记录过设备

        // 当前样本桶与跨窗口状态共享设备容量，避免历史设备状态无限增长。
        std::size_t tracked = states_.size(); //获取 states_ 容器中当前的io_latency设备数

        for (const auto& entry : buckets_) //遍历buckets_，记录只出现在buckets_中和只出现在states_中的设备数
            tracked += states_.count(entry.first) == 0; //tracked表示当前分析器当前一共跟踪了多少个不同设备
                                                        //用于检查是否达到 max_devices 容量上限。
        if (!states_.count(key) && tracked >= config_.max_devices) {
            ++dropped_; return IoProcessResult::CapacityDropped;
        }
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
IoReport IoAnalyzer::finish_window(uint64_t end_ns, bool complete)
{
    if (end_ns <= start_) throw std::invalid_argument("window must advance");
    // Caller supplies a monotonic cutoff after consuming the current batch.
    IoReport report;
    report.latency_threshold_ns = config_.latency_threshold_ns;
    report.min_samples = config_.min_samples;
    report.alert_consecutive_windows = config_.alert_consecutive_windows;
    report.recovery_consecutive_windows = config_.recovery_consecutive_windows;
    report.window_complete = complete;
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
        //计算本窗口指标
        b.stats.avg_duration_ns = static_cast<uint64_t>(b.total_ns / b.stats.count);
        b.stats.p95_duration_ns = quantile(95);
        b.stats.p99_duration_ns = quantile(99);
        b.stats.window_abnormal = b.stats.count >= config_.min_samples &&
            b.stats.p95_duration_ns >= config_.latency_threshold_ns;  //判断本窗口是否异常
    }

    if (complete) { //完整窗口更新诊断状态：增加异常或恢复次数，决定是否触发、解除告警
        for (const auto& pair : buckets_) {
            if (pair.second.stats.window_abnormal && !states_.count(pair.first)) { //为首次异常的设备建立状态
                IoDiagnosis state;
                state.major = pair.second.stats.major;
                state.minor = pair.second.stats.minor;
                states_.emplace(pair.first, state);
            }
        }
        for (auto it = states_.begin(); it != states_.end();) {
            auto& state = it->second;
            auto bucket = buckets_.find(it->first);
            const bool abnormal = bucket != buckets_.end() && bucket->second.stats.window_abnormal;
            if (abnormal) {
                // 计数在门槛处停止增长，避免长期运行时整数溢出。
                if (state.abnormal_windows < config_.alert_consecutive_windows)
                    ++state.abnormal_windows;
                state.recovery_windows = 0;
                if (state.abnormal_windows >= config_.alert_consecutive_windows)
                    state.io_latency = true;
            } else {
                state.abnormal_windows = 0;
                if (state.io_latency && ++state.recovery_windows >= config_.recovery_consecutive_windows)
                    state.io_latency = false;
            }
            // 正常窗口会打断待触发序列；恢复后不再保留历史设备状态。
            if (!state.io_latency && !state.abnormal_windows)
                it = states_.erase(it);
            else
                ++it;
        }
    }

    //非完整窗口保持诊断状态不变
    for (auto& pair : buckets_) {
        auto& stats = pair.second.stats;
        auto state = states_.find(pair.first);
        if (state != states_.end()) { //更新bucket_中设备的状态
            stats.io_latency = state->second.io_latency;
            stats.abnormal_windows = state->second.abnormal_windows;
            stats.recovery_windows = state->second.recovery_windows;
        }
        report.devices.push_back(stats);
    }
    // 将所有仍在告警的设备放入 diagnoses，包括当前没样本、仍在恢复观察期的设备。
    for (const auto& pair : states_)
        if (pair.second.io_latency) report.diagnoses.push_back(pair.second);
    buckets_.clear(); samples_ = 0; invalid_ = late_ = dropped_ = 0; start_ = end_ns;
    return report;
}
