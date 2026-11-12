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
    update_cpu_stats(window_stats_[tid], event);

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

    /*
     * 确定本轮样本对应的候选异常。
     *
     * RunqueuePressure 的证据更具体，因此优先级高于
     * 普通 HighUsage。
     */
    CpuDiagnosisState candidate_state =
        CpuDiagnosisState::Normal;

    const bool system_high =
        observation.system_usage_percent >=
        config_.high_usage_threshold_percent;

    const bool process_high =
        observation.processes.empty() &&
        observation.pid > 0 &&
        observation.process_usage_percent >=
        config_.high_usage_threshold_percent;

    const bool runqueue_pressure =
        system_high &&
        diagnosis_.max_runqueue_delay_ns >=
        config_.runqueue_delay_threshold_ns;

    if (runqueue_pressure) {

        candidate_state =
            CpuDiagnosisState::RunqueuePressure;

    } else if (
        system_high ||
        process_high) {

        candidate_state =
            CpuDiagnosisState::HighUsage;
    }

    /*
     * 只有系统 CPU 和目标进程 CPU 都回落到恢复阈值以下，
     * 才认为本轮样本满足恢复条件。
     *
     * pid == 0 表示没有指定目标进程，此时只判断系统使用率。
     */
    const bool recovery_sample =
        observation.system_usage_percent <
            config_.recovery_threshold_percent &&
        (observation.pid == 0 ||
         observation.process_usage_percent <
            config_.recovery_threshold_percent);

    if (diagnosis_.state ==
        CpuDiagnosisState::Normal) {

        /*
         * 当前是 Normal：
         *
         * 连续出现相同异常类型达到配置次数后，才进入告警。
         */
        recovery_sample_count_ = 0;

        if (candidate_state ==
            CpuDiagnosisState::Normal) {

            pending_abnormal_state_ =
                CpuDiagnosisState::Normal;

            abnormal_sample_count_ = 0;
            diagnosis_.consecutive_samples = 0;

        } else {

            /*
             * 候选异常类型发生变化时重新计数，避免把
             * HighUsage 和 RunqueuePressure 混合累计。
             */
            if (pending_abnormal_state_ !=
                candidate_state) {

                pending_abnormal_state_ =
                    candidate_state;

                abnormal_sample_count_ = 1;

            } else {

                abnormal_sample_count_++;
            }

            diagnosis_.consecutive_samples =
                abnormal_sample_count_;

            if (abnormal_sample_count_ >=
                config_.alert_consecutive_samples) {

                diagnosis_.state =
                    candidate_state;

                pending_abnormal_state_ =
                    CpuDiagnosisState::Normal;

                abnormal_sample_count_ = 0;

                diagnosis_.consecutive_samples = 0;
            }
        }

    } else {

        /*
         * 当前已经处于异常状态：
         *
         * 连续出现恢复样本后才回到 Normal。
         */
        if (recovery_sample) {

            pending_abnormal_state_ =
                CpuDiagnosisState::Normal;

            abnormal_sample_count_ = 0;
            recovery_sample_count_++;

            diagnosis_.consecutive_samples =
                recovery_sample_count_;

            if (recovery_sample_count_ >=
                config_.recovery_consecutive_samples) {

                diagnosis_.state =
                    CpuDiagnosisState::Normal;

                recovery_sample_count_ = 0;
                diagnosis_.consecutive_samples = 0;
            }

        } else {

            recovery_sample_count_ = 0;

            /*
             * 已经处于一种异常，但当前连续观察到另一种异常时，
             * 也要求达到连续样本数才切换异常类型。
             */
            if (candidate_state !=
                    CpuDiagnosisState::Normal &&
                candidate_state !=
                    diagnosis_.state) {

                if (pending_abnormal_state_ !=
                    candidate_state) {

                    pending_abnormal_state_ =
                        candidate_state;

                    abnormal_sample_count_ = 1;

                } else {

                    abnormal_sample_count_++;
                }

                diagnosis_.consecutive_samples =
                    abnormal_sample_count_;

                if (abnormal_sample_count_ >=
                    config_.alert_consecutive_samples) {

                    diagnosis_.state =
                        candidate_state;

                    pending_abnormal_state_ =
                        CpuDiagnosisState::Normal;

                    abnormal_sample_count_ = 0;
                    diagnosis_.consecutive_samples = 0;
                }

            } else {

                /*
                 * 当前样本仍支持已有异常，或者处于迟滞区间。
                 * 保持当前诊断状态，但不累计状态切换次数。
                 */
                pending_abnormal_state_ =
                    CpuDiagnosisState::Normal;

                abnormal_sample_count_ = 0;
                diagnosis_.consecutive_samples = 0;
            }
        }
    }

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

    pending_abnormal_state_ = CpuDiagnosisState::Normal;

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