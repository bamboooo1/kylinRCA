#ifndef KYLINRCA_CPU_ANALYZER_H
#define KYLINRCA_CPU_ANALYZER_H

#include "event.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct CpuStats {
    /*
     * 事件所属的真实进程 PID（TGID）和线程 TID。
     */
    uint32_t pid = 0;
    uint32_t tid = 0;

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

/*
 * 一次采样窗口中的线程 CPU 使用率。
 */
struct CpuThreadUsageObservation {
    uint32_t tid = 0;
    std::string comm;
    double usage_percent = 0.0;
};

/*
 * 一次采样窗口中的进程 CPU 使用率，以及该进程的线程明细。
 */
struct CpuProcessUsageObservation {
    uint32_t pid = 0;
    std::string comm;
    double process_usage_percent = 0.0;
    std::vector<CpuThreadUsageObservation> threads;
};

/*
 * /proc CPU sampler 计算完成后交给 CpuAnalyzer 的观测结果。
 *
 * CpuAnalyzer 不直接读取 /proc，避免把采样和诊断职责混在一起。
 */
struct CpuUsageObservation {
    /*
     * 采样发生的单调时钟时间。
     * 第一版测试中可以不使用，但为后续窗口和报告保留。
     */
    uint64_t timestamp_ns = 0;

    /*
     * 整个系统的 CPU 使用率，通常位于 0～100。
     */
    double system_usage_percent = 0.0;

    /*
     * 被分析进程的 PID。
     * pid == 0 表示当前没有指定目标进程。
     */
    int pid = 0;

    /*
     * 目标进程 CPU 使用率。
     *
     * 多线程进程可能超过100%，因为100%通常表示占满一个逻辑核心。
     */
    double process_usage_percent = 0.0;

    /*
     * 全系统模式下保存本轮所有进程及线程的 CPU 使用率。
     * 为空时仍按原来的指定 PID 模式处理，保持现有调用方兼容。
     */
    std::vector<CpuProcessUsageObservation> processes;
};


/*
 * CPU RCA 当前支持的诊断状态。
 */
enum class CpuDiagnosisState {
    Normal,
    HighUsage,
    RunqueuePressure
};


/*
 * CpuAnalyzer 的可配置阈值。
 *
 * 第一版先由构造函数传入，后续再接 YAML/INI 配置。
 */
struct CpuAnalyzerConfig {
    /*
     * 连续达到该使用率后触发 HighUsage。
     */
    double high_usage_threshold_percent = 80.0;

    /*
     * CPU 使用率回落到该阈值以下后，允许恢复 Normal。
     *
     * 恢复阈值低于告警阈值，可以避免状态在边界附近反复跳变。
     */
    double recovery_threshold_percent = 50.0;

    /*
     * runqueue delay 达到10ms时，认为存在明显调度排队。
     */
    uint64_t runqueue_delay_threshold_ns = 10'000'000;

    /*
     * 连续多少次满足异常条件后触发告警。
     */
    std::size_t alert_consecutive_samples = 3;

    /*
     * 连续多少次恢复正常后解除告警。
     */
    std::size_t recovery_consecutive_samples = 3;
};


/*
 * 对外输出的 CPU 诊断结果。
 *
 * 除了状态，还保存触发判断时使用的证据，方便后续 JSON Reporter
 * 和统一 RCA Engine 输出。
 */
struct CpuDiagnosis {
    CpuDiagnosisState state =
        CpuDiagnosisState::Normal;

    int pid = 0;

    double system_usage_percent = 0.0;
    double process_usage_percent = 0.0;

    /*
     * 高 CPU 的责任进程和责任线程。
     *
     * 责任线程按 /proc 线程 CPU 使用率选择，不能按最大 runqueue
     * delay 选择，因为等待时间最长的线程通常是受害线程。
     */
    uint32_t culprit_pid = 0;
    std::string culprit_process_comm;
    double culprit_process_usage_percent = 0.0;

    uint32_t culprit_tid = 0;
    std::string culprit_thread_comm;
    double culprit_thread_usage_percent = 0.0;

    /*
     * 责任线程在当前 BPF 窗口中的调度证据。
     */
    uint64_t culprit_oncpu_time_ns = 0;
    uint64_t culprit_runqueue_delay_ns = 0;

    /*
     * runqueue 延迟最大的受害线程。它与责任线程可能不是同一个线程。
     */
    uint32_t victim_pid = 0;
    uint32_t victim_tid = 0;
    uint64_t victim_max_runqueue_delay_ns = 0;

    uint64_t average_runqueue_delay_ns = 0;
    uint64_t max_runqueue_delay_ns = 0;

    /*
     * 当前已经连续观察到多少个异常或恢复样本。
     */
    std::size_t consecutive_samples = 0;
};

class CpuAnalyzer {
public:
    explicit CpuAnalyzer(CpuAnalyzerConfig config = {}); //`explicit` 修饰单参数构造函数
        //（或者除第一个参数外其余都有默认值的构造函数），禁止编译器自动隐式类型转换。

    /*
     * 接收 cpu.bpf.c 产生的调度事件。
     */
    void process(const cpu_event& event);

    /*
     * 接收一次已经计算完成的 /proc CPU 使用率，并更新 RCA 状态。
     */
    void process_usage(const CpuUsageObservation& observation);

    const std::unordered_map<uint32_t, CpuStats>& stats() const;

    /*
     * 查询指定 TID 的调度统计。
     */
    const CpuStats* find(uint32_t tid) const;

    std::size_t thread_count() const;

    /*
     * 返回当前 CPU 诊断结果。
     */
    const CpuDiagnosis& diagnosis() const;

    /*
     * 清空调度统计和 RCA 状态。
     */
    void reset();

    /*
     * 清理已经退出，并且超过 retention 时间没有新事件的线程。
     *
     * 返回本次删除的线程数量。
     */
    std::size_t cleanup_exited_threads(std::chrono::seconds retention);

private:
    /*
     * 根据当前 stats_ 计算整个窗口的平均和最大 runqueue delay。
     */
    void update_runqueue_evidence();

    /*
     * 从 /proc 线程使用率中选择责任线程，再关联当前 BPF 窗口证据。
     */
    void update_responsibility_evidence(
        const CpuUsageObservation& observation);

    CpuAnalyzerConfig config_;

    /*
     * 从程序启动后一直累计，用于最终 Summary。
     */
    std::unordered_map<uint32_t, CpuStats> stats_;

    /*
     * 两次 CPU 使用率采样之间的调度统计，
     * 用于本轮 RCA 判断。
     */
    std::unordered_map<uint32_t, CpuStats> window_stats_;

    /*
     * 记录每个 TID 最后一次收到 CPU 调度事件的用户态时间。
     */
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> last_seen_;

    CpuDiagnosis diagnosis_;

    /*
    * 当前正在累计的候选异常。
    *
    * 如果异常类型发生变化，连续计数必须重新开始，避免把
    * HighUsage 和 RunqueuePressure 混合计算成连续异常。
     */
    CpuDiagnosisState pending_abnormal_state_ = CpuDiagnosisState::Normal;

    std::size_t abnormal_sample_count_ = 0;
    std::size_t recovery_sample_count_ = 0;
};

#endif
