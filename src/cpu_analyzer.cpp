#include "cpu_analyzer.h"

#include <algorithm>
#include <cerrno>
#include <cmath>

#include <signal.h>
#include <sys/types.h>

namespace {

/*
 * 将一条 CPU 调度事件累加到指定 CpuStats。
 *
 * 生命周期累计统计和当前窗口统计都复用这个函数，
 * 避免两套聚合逻辑逐渐不一致。
 */
void update_cpu_stats(
    CpuStats& stat,
    const cpu_event& event)
{
    stat.pid = event.header.pid;
    stat.tid = event.header.tid;

    if (event.kind == CPU_EVENT_RUNQUEUE_DELAY) {

        stat.runqueue_count++;

        stat.total_runqueue_delay_ns +=
            event.runqueue_delay_ns;

        stat.max_runqueue_delay_ns =
            std::max(
                stat.max_runqueue_delay_ns,
                static_cast<uint64_t>(
                    event.runqueue_delay_ns));

    } else if (
        event.kind == CPU_EVENT_ONCPU_TIME) {

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

/*
 * 检查指定 TID 当前是否仍然存在。
 *
 * kill(tid, 0) 不发送真实信号，只做存在性和权限检查。
 */
bool thread_exists(uint32_t tid)
{
    errno = 0;

    const int result = ::kill(static_cast<pid_t>(tid), 0);

    if (result == 0)
        return true;

    /*
     * 没有权限意味着任务存在，只是当前进程无权发送信号。
     */
    if (errno == EPERM)
        return true;

    /*
     * ESRCH 表示对应任务已经不存在。
     */
    if (errno == ESRCH)
        return false;

    /*
     * 对未知错误采用保守策略，避免误删统计。
     */
    return true;
}

} // namespace

CpuAnalyzer::CpuAnalyzer(CpuAnalyzerConfig config) : config_(config) // 初始化列表：把入参config拷贝给成员config_
{
    /*
     * 连续样本数不能为0。
     *
     * 如果配置传入0，这里退化为至少需要1个样本，
     * 避免任何一次 process_usage() 都立即满足条件。
     */
    if (config_.alert_consecutive_samples == 0)
        config_.alert_consecutive_samples = 1;

    if (config_.recovery_consecutive_samples == 0)
        config_.recovery_consecutive_samples = 1;

    /*
     * 恢复阈值必须低于告警阈值，形成迟滞区间，
     * 避免 CPU 使用率在阈值附近波动时反复告警和恢复。
     */
    if (config_.recovery_threshold_percent >
        config_.high_usage_threshold_percent) {

        config_.recovery_threshold_percent =
            config_.high_usage_threshold_percent;
    }
}

void CpuAnalyzer::process(const cpu_event& event)
{
    /*
     * CpuAnalyzer 当前只接受两种 CPU 事件。
     */
    if (event.kind != CPU_EVENT_RUNQUEUE_DELAY &&
        event.kind != CPU_EVENT_ONCPU_TIME) {
        return;
    }

    /*
     * idle task 的 TID 为 0，不应该进入用户态聚合结果。
     */
    if (event.header.tid == 0) {
        return;
    }

    const uint32_t tid = event.header.tid;

    /*
     * 更新整个程序生命周期的累计统计。
     */
    update_cpu_stats(stats_[tid], event);

    /*
     * 同时更新当前 RCA 窗口。
     */
    if (event.header.timestamp_ns == 0) {
        // 兼容使用合成事件的单元测试。
        update_cpu_stats(window_stats_[tid], event);
    } else {
        // on-CPU 的实时窗口值来自快照，事件片段仅保留在生命周期统计中。
        if (event.kind == CPU_EVENT_RUNQUEUE_DELAY)
            pending_events_.push_back(event);
        // 极端积压时限制内存，压力证据只作为辅助；累计统计仍保留。
        if (pending_events_.size() > 100000)
            pending_events_.pop_front();
    }

    last_seen_[tid] = std::chrono::steady_clock::now();
}

void CpuAnalyzer::process_usage(
    const CpuUsageObservation& observation)
{
    /*
     * 系统 CPU 使用率必须位于0～100。
     *
     * 进程 CPU 使用率允许超过100，因为多线程进程可能同时
     * 使用多个逻辑核心，但不能是负数、NaN 或无穷大。
     */
    if (!std::isfinite(
            observation.system_usage_percent) ||
        !std::isfinite(
            observation.process_usage_percent) ||
        observation.system_usage_percent < 0.0 ||
        observation.system_usage_percent > 100.0 ||
        observation.process_usage_percent < 0.0 ||
        observation.pid < 0) {
        return;
    }

    /*
     * 汇总自上一次有效 CPU 使用率采样以来收集到的
     * runqueue delay，作为本轮 RCA 的调度证据。
     */
    if (observation.timestamp_ns) {
        for (auto it = pending_events_.begin(); it != pending_events_.end();) {
            if (it->header.timestamp_ns > observation.timestamp_ns) {
                ++it;
                continue;
            }
            if (it->header.timestamp_ns > observation.window_start_ns)
                update_cpu_stats(window_stats_[it->header.tid], *it);
            it = pending_events_.erase(it);
        }
    }
    update_runqueue_evidence();

    diagnosis_.pid =
        observation.pid;

    diagnosis_.system_usage_percent =
        observation.system_usage_percent;

    diagnosis_.process_usage_percent =
        observation.process_usage_percent;

    /*
     * 在清空 window_stats_ 之前完成责任线程和受害线程关联。
     */
    update_responsibility_evidence(observation);

    const bool system_high = observation.system_usage_percent >=
                             config_.high_usage_threshold_percent;
    const bool process_high = observation.processes.empty() && observation.pid > 0 &&
                              observation.process_usage_percent >=
                              config_.high_usage_threshold_percent;
    const bool high = system_high || process_high;
    const bool recovery = observation.system_usage_percent <
                          config_.recovery_threshold_percent &&
                          (observation.pid == 0 || observation.process_usage_percent <
                           config_.recovery_threshold_percent);

    // 不同压力证据可以交替出现，但高占用这个事实独立持续计数。
    abnormal_sample_count_ = high ? abnormal_sample_count_ + 1 : 0;
    if (abnormal_sample_count_ >= config_.alert_consecutive_samples)
        high_usage_active_ = true;
    recovery_sample_count_ = recovery ? recovery_sample_count_ + 1 : 0;
    if (recovery_sample_count_ >= config_.recovery_consecutive_samples)
        high_usage_active_ = false;

    if (observation.scheduling_evidence_valid) {
        const bool pressure = system_high && diagnosis_.max_runqueue_delay_ns >=
                              config_.runqueue_delay_threshold_ns;
        pressure_sample_count_ = pressure ? pressure_sample_count_ + 1 : 0;
        pressure_recovery_count_ = pressure ? 0 : pressure_recovery_count_ + 1;
        if (pressure_sample_count_ >= config_.alert_consecutive_samples)
            pressure_active_ = true;
        if (pressure_recovery_count_ >= config_.recovery_consecutive_samples)
            pressure_active_ = false;
    } else {
        // 缺失证据不等于正常；中断连续样本，并取消过期的压力结论。
        pressure_sample_count_ = 0;
        pressure_recovery_count_ = 0;
        pressure_active_ = false;
    }
    diagnosis_.state = pressure_active_ ? CpuDiagnosisState::RunqueuePressure :
                       high_usage_active_ ? CpuDiagnosisState::HighUsage :
                                            CpuDiagnosisState::Normal;
    diagnosis_.consecutive_samples = 0;
    if (diagnosis_.state == CpuDiagnosisState::Normal && high)
        diagnosis_.consecutive_samples = abnormal_sample_count_;
    else if (diagnosis_.state != CpuDiagnosisState::Normal && recovery)
        diagnosis_.consecutive_samples = recovery_sample_count_;

    /*
     * 当前窗口已经完成诊断。
     *
     * 生命周期累计 stats_ 保留；只清空 window_stats_，
     * 避免历史 runqueue 最大值污染下一轮判断。
     */
    window_stats_.clear();
}

const std::unordered_map<uint32_t, CpuStats>& CpuAnalyzer::stats() const
{
    return stats_;
}

const CpuStats* CpuAnalyzer::find(uint32_t tid) const
{
    const auto it = stats_.find(tid);

    if (it == stats_.end())
        return nullptr;

    return &it->second;
}

std::size_t CpuAnalyzer::thread_count() const
{
    return stats_.size();
}

const CpuDiagnosis& CpuAnalyzer::diagnosis() const
{
    return diagnosis_;
}

void CpuAnalyzer::reset()
{
    stats_.clear();
    window_stats_.clear();
    last_seen_.clear();

    diagnosis_ = CpuDiagnosis{};

    high_usage_active_ = false;
    pressure_active_ = false;
    pressure_sample_count_ = 0;
    pressure_recovery_count_ = 0;
    pending_events_.clear();

    abnormal_sample_count_ = 0;
    recovery_sample_count_ = 0;
}

std::size_t CpuAnalyzer::cleanup_exited_threads(
    std::chrono::seconds retention)
{
    const auto now =  std::chrono::steady_clock::now();

    std::size_t removed_count = 0;

    for (auto it = last_seen_.begin(); it != last_seen_.end();)
    {
        const uint32_t tid = it->first;
        const auto idle_time = now - it->second;

        /*
         * 必须同时满足：
         *
         * 1. 超过保留时间没有事件；
         * 2. 对应线程已经不存在。
         *
         * 仍然存活但暂时休眠的线程不能删除。
         */
        if (idle_time >= retention && !thread_exists(tid))
        {
            stats_.erase(tid);
            /*
             * 如果窗口中恰好还有该线程的事件，也一并删除。
             */
            window_stats_.erase(tid);
            it = last_seen_.erase(it);
            removed_count++;
        } else {
            ++it;
        }
    }
    return removed_count;
}

void CpuAnalyzer::update_runqueue_evidence()
{
    uint64_t total_delay_ns = 0;
    uint64_t total_count = 0;
    uint64_t max_delay_ns = 0;

    /*
     * 将窗口内所有 TID 的 runqueue 统计合并。
     *
     * 平均值必须使用：
     *
     *     所有延迟总和 / 所有事件总数
     *
     * 不能直接计算“各线程平均值的平均值”，因为每个线程的
     * 事件数量不同，那样会得到错误结果。
     */
    for (const auto& [tid, stat] : window_stats_) {
        /*
         * 当前只需要 stat，保留 tid 是为了以后输出责任线程。
         */
        (void)tid;

        total_delay_ns +=
            stat.total_runqueue_delay_ns;

        total_count +=
            stat.runqueue_count;

        max_delay_ns =
            std::max(
                max_delay_ns,
                stat.max_runqueue_delay_ns);
    }

    if (total_count == 0) {
        diagnosis_.average_runqueue_delay_ns = 0;
    } else {
        diagnosis_.average_runqueue_delay_ns =
            total_delay_ns / total_count;
    }

    diagnosis_.max_runqueue_delay_ns =
        max_delay_ns;

}
void CpuAnalyzer::update_responsibility_evidence(
    const CpuUsageObservation& observation)
{
    diagnosis_.culprit_pid = 0;
    diagnosis_.culprit_process_comm.clear();
    diagnosis_.culprit_process_usage_percent = 0.0;
    diagnosis_.culprit_tid = 0;
    diagnosis_.culprit_thread_comm.clear();
    diagnosis_.culprit_thread_usage_percent = 0.0;
    diagnosis_.culprit_oncpu_time_ns = 0;
    diagnosis_.culprit_runtime_valid = false;
    diagnosis_.culprit_runtime_window_ns = 0;
    diagnosis_.culprit_runtime_uncertainty_ns = 0;
    diagnosis_.culprit_runqueue_delay_ns = 0;

    diagnosis_.victim_pid = 0;
    diagnosis_.victim_tid = 0;
    diagnosis_.victim_max_runqueue_delay_ns = 0;

    if (observation.processes.empty()) {
        /*
         * 保留原有指定 PID 模式的兼容行为。该模式没有线程 CPU
         * 明细，因此只能报告进程，不能凭空猜测责任 TID。
         */
        if (observation.pid > 0) {
            diagnosis_.culprit_pid =
                static_cast<uint32_t>(observation.pid);
            diagnosis_.culprit_process_usage_percent =
                observation.process_usage_percent;
        }
    } else {
        const CpuProcessUsageObservation* culprit_process =
            nullptr;

        for (const CpuProcessUsageObservation& process :
             observation.processes) {
            if (!std::isfinite(
                    process.process_usage_percent) ||
                process.process_usage_percent < 0.0)
                continue;

            if (culprit_process == nullptr ||
                process.process_usage_percent >
                    culprit_process->
                        process_usage_percent) {
                culprit_process = &process;
            }
        }

        if (culprit_process != nullptr) {
            diagnosis_.culprit_pid =
                culprit_process->pid;
            diagnosis_.culprit_process_comm =
                culprit_process->comm;
            diagnosis_.culprit_process_usage_percent =
                culprit_process->process_usage_percent;

            const CpuThreadUsageObservation* culprit_thread =
                nullptr;

            for (const CpuThreadUsageObservation& thread :
                 culprit_process->threads) {
                if (!std::isfinite(thread.usage_percent) ||
                    thread.usage_percent < 0.0)
                    continue;

                if (culprit_thread == nullptr ||
                    thread.usage_percent >
                        culprit_thread->usage_percent) {
                    culprit_thread = &thread;
                }
            }

            if (culprit_thread != nullptr) {
                diagnosis_.culprit_tid =
                    culprit_thread->tid;
                diagnosis_.culprit_thread_comm =
                    culprit_thread->comm;
                diagnosis_.culprit_thread_usage_percent =
                    culprit_thread->usage_percent;
                if (observation.has_runtime_snapshots) {
                    diagnosis_.culprit_runtime_valid = culprit_thread->runtime_valid;
                    diagnosis_.culprit_oncpu_time_ns = culprit_thread->runtime_ns;
                    diagnosis_.culprit_runtime_window_ns = culprit_thread->runtime_window_ns;
                    diagnosis_.culprit_runtime_uncertainty_ns = culprit_thread->runtime_uncertainty_ns;
                }
            }

            /*
             * 在全系统模式中，pid/process_usage_percent 表示当前选出的
             * 责任进程，方便已有 Reporter 继续使用旧字段。
             */
            diagnosis_.pid =
                static_cast<int>(
                    diagnosis_.culprit_pid);
            diagnosis_.process_usage_percent =
                diagnosis_.
                    culprit_process_usage_percent;
        }
    }

    const auto culprit_stat =
        window_stats_.find(
            diagnosis_.culprit_tid);

    if (culprit_stat != window_stats_.end()) {
        // 快照模式禁止被“本轮收到的完整片段”覆盖，否则会再次跨窗口累计。
        if (!observation.has_runtime_snapshots)
            diagnosis_.culprit_oncpu_time_ns =
                culprit_stat->second.total_oncpu_time_ns;
        diagnosis_.culprit_runqueue_delay_ns =
            culprit_stat->second.
                total_runqueue_delay_ns;
    }

    /*
     * 最大 runqueue delay 对应的是最久没有获得 CPU 的线程，因此
     * 单独报告为 victim，不能把它错误地当成高 CPU 责任线程。
     */
    for (const auto& [tid, stat] : window_stats_) {
        if (stat.max_runqueue_delay_ns >
            diagnosis_.
                victim_max_runqueue_delay_ns) {
            diagnosis_.victim_pid = stat.pid;
            diagnosis_.victim_tid = tid;
            diagnosis_.victim_max_runqueue_delay_ns =
                stat.max_runqueue_delay_ns;
        }
    }
}