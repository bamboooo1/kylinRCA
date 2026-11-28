#ifndef KYLINRCA_IO_ANALYZER_H
#define KYLINRCA_IO_ANALYZER_H
#include "event.h"
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

// 设置分析规则和容量限制
struct IoAnalyzerConfig {
    uint64_t latency_threshold_ns = 10'000'000; //设备 P95 达到这个值时满足延迟条件
    uint64_t min_samples = 10; //设备在窗口内至少有这么多样本才允许告警
    std::size_t max_samples_per_device = 100000; //每个设备最多保存 100000 个样本
    std::size_t max_devices = 128; //每个窗口最多保存 128 个设备
    std::size_t max_total_samples = 100000; //所有设备合计最多保存 100000 个样本
    std::size_t alert_consecutive_windows = 3; //连续三个异常窗口才触发
    std::size_t recovery_consecutive_windows = 3; //连续三个正常或空窗口才恢复
    uint64_t window_ns = 1'000'000'000; // 窗口长度；daemon 使用公共窗口设置覆盖，分析器负责实际推进。
};

//保存一个设备在一个窗口内的统计结果
struct IoStats {
    uint32_t major = 0, minor = 0;
    uint64_t count = 0, bytes = 0, reads = 0, writes = 0, errors = 0;
    uint64_t avg_duration_ns = 0, p95_duration_ns = 0, p99_duration_ns = 0;
    bool window_abnormal = false; //仅表示本窗口的样本数和 P95 达到门槛
    bool io_latency = false; //经过连续窗口确认后的持续诊断状态
    std::size_t abnormal_windows = 0, recovery_windows = 0;
};

// 持续告警独立输出：设备在空窗口中没有样本，也可能仍在等待恢复确认。
struct IoDiagnosis {
    uint32_t major = 0, minor = 0;
    bool io_latency = false;
    std::size_t abnormal_windows = 0, recovery_windows = 0;
};

//保存所有设备在一个窗口内的统计结果
struct IoReport {
    uint64_t window_start_ns = 0, window_end_ns = 0;
    //使用了什么阈值和最低样本数
    uint64_t latency_threshold_ns = 0, min_samples = 0;
    //协议字段等检查不通过的事件数；属于已经关闭窗口的迟到事件数；超出分析器容量而被拒收的事件数
    uint64_t invalid_events = 0, late_events = 0, capacity_drops = 0;
    std::vector<IoStats> devices;
    std::vector<IoDiagnosis> diagnoses; //只包含仍处于 IO_LATENCY 的设备
    std::size_t alert_consecutive_windows = 3, recovery_consecutive_windows = 3;
    bool window_complete = true;
};
// 区分拒收原因，供调用方检查单条事件，也分别累计到窗口报告和运行计数。
enum class IoProcessResult { Accepted, Invalid, Late, CapacityDropped };

// 从启动起的接收和拒收累计计数，与每窗口清空的设备统计分开保存。
struct IoCounters {
    uint64_t received = 0, invalid = 0, late = 0, capacity_drops = 0;
    uint64_t reads = 0, writes = 0, bytes = 0;
};

// 由调用方所属的分析线程独占，管理事件归属、设备聚合、连续告警、空窗口恢复和退出尾窗。
// 不访问 BPF、不输出 JSON，也不持有共享快照；这些工作由 daemon 或独立采集入口完成。
class IoAnalyzer {
public:
    // 设置首窗起点和模块规则，拒绝零窗口、零阈值或零容量；初始时还没有结算报告。
    explicit IoAnalyzer(uint64_t start_ns, IoAnalyzerConfig config = {});
    // 接收一条完成事件，必要时先结算已结束的窗口，再按设备聚合；返回是否成功进入统计。
    bool process(const kylinrca_io_event& event);
    // 与 process 执行相同处理，但区分无效、迟到和超容量；字段不合法时不使用其时间推进窗口。
    IoProcessResult process_detailed(const kylinrca_io_event& event);
    // 按单调时钟推进所有完整窗口，包括没有事件的空窗口；过期时间不会使窗口倒退。
    // 结算结果暂存在分析器中，由调用方在处理事件或推进后立即通过 take_reports 取走。
    bool advance_window(uint64_t timestamp_ns);
    // 停止采集并排空事件后调用：结算完整窗口，再保存不足整窗的尾部；尾窗不改变异常或恢复次数。
    bool flush(uint64_t timestamp_ns);
    // 取走自上次读取后结算的全部报告，保留每个空窗口的恢复证据；本函数不负责输出。
    std::vector<IoReport> take_reports();
    // 读取最近结算报告和从启动起的累计计数，供 daemon 构造共享状态副本。
    const std::optional<IoReport>& report() const { return report_; }
    const IoCounters& counters() const { return counters_; }
    // 返回当前收集窗口的右边界；恰好在边界完成的 I/O 属于当前窗。
    uint64_t next_window_end_ns() const { return start_ + config_.window_ns; }
    // 保留已有手动结算接口，供独立指标回归指定截止时间并直接取得结果；不会加入待输出报告列表。
    // end_ns 必须晚于当前起点；调用方应先消费属于该截止时间的事件，迟到记录不回写旧窗口。
    IoReport finish_window(uint64_t end_ns, bool complete = true);
private:
    // 保存一个设备当前窗口的样本、总耗时和基本计数，结算时计算平均值与分位数。
    struct Bucket {
        IoStats stats;
        long double total_ns = 0;
        std::vector<uint64_t> durations;
    };
    uint64_t start_;
    IoAnalyzerConfig config_;
    std::map<uint64_t, Bucket> buckets_; // 当前窗口样本；每次结算后清空。
    std::map<uint64_t, IoDiagnosis> states_; // 跨窗口连续异常和恢复状态；与当前样本分开保留。
    uint64_t invalid_ = 0, late_ = 0, dropped_ = 0;
    std::size_t samples_ = 0;
    IoCounters counters_; // 运行累计值不随窗口清空，包含合法接收但因迟到或容量不足拒收的记录。
    std::optional<IoReport> report_;
    std::vector<IoReport> reports_; // 调用方每次处理后取走，避免输出或快照职责进入分析器。
};
#endif
