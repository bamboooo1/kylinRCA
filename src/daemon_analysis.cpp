#include "daemon_analysis.h"
#include "json_reporter.h"

#include <chrono>
#include <vector>

using namespace std::chrono_literals;

namespace {

// 在 tick 打开或结算窗口时，按到达顺序处理不晚于 cutoff_ns 的暂存记录，保留后续窗口的记录。
template <typename Event, typename Analyzer>
void process_pending_through(std::vector<Event>& pending, Analyzer& analysis, uint64_t cutoff_ns)
{
    auto remaining = pending.begin();
    for (const auto& event : pending) {
        if (event.header.timestamp_ns <= cutoff_ns)
            analysis.process(event);
        else
            *remaining++ = event;
    }
    pending.erase(remaining, pending.end());
}

} // 命名空间结束

DaemonSnapshot initial_daemon_snapshot(const DaemonAnalysisSettings& settings, uint64_t started_ns)
{
    AnalysisProgress progress;
    progress.started_ns = started_ns;
    progress.updated_ns = started_ns;
    IoSnapshot io_state;
    io_state.enabled = settings.common.enable_io;
    return make_daemon_snapshot(settings.common, progress, SyscallAnalyzer{}, SyscallAnalyzer{},
                                CpuUsageObservation{}, CpuAnalyzer(settings.cpu),
                                LockAnalyzer(settings.lock), io_state);
}

void analyze_events(EventQueue& queue, const DaemonAnalysisSettings& settings,
                    uint64_t started_ns, SnapshotStore& snapshots, std::ostream& reports)
{
    const auto& common = settings.common;
    SyscallAnalyzer syscall_totals;
    SyscallAnalyzer syscall_window;
    CpuAnalyzer cpu_analysis(settings.cpu);
    auto lock_settings = settings.lock;
    lock_settings.window_ns = uint64_t{common.window_ms} * 1'000'000;
    LockAnalyzer lock_analysis(lock_settings);
    if (common.enable_lock)
        lock_analysis.advance_window(started_ns);
    std::vector<kylinrca_lock_event> pending_lock_events;
    auto io_settings = settings.io;
    io_settings.window_ns = uint64_t{common.window_ms} * 1'000'000;
    IoAnalyzer io_analysis(started_ns, io_settings);
    std::vector<kylinrca_io_event> pending_io_events;
    IoProbeHealth io_health;
    CpuUsageObservation cpu_window;
    AnalysisProgress progress;
    progress.started_ns = started_ns;
    progress.updated_ns = started_ns;
    auto next_syscall_cleanup = std::chrono::steady_clock::now() + 60s;

    // 取出本次结算产生的 I/O 报告，包括退出时不足整窗的结果。
    const auto write_io_reports = [&] {
        for (const auto& io_report : io_analysis.take_reports())
            reports << JsonReporter::report_io(io_report) << '\n' << std::flush;
    };
    const auto publish_snapshot = [&] {
        snapshots.publish(make_daemon_snapshot(common, progress, syscall_totals, syscall_window,
                          cpu_window, cpu_analysis, lock_analysis,
                          make_io_snapshot(common.enable_io, io_analysis, io_health)));
    };

    while (auto message = queue.wait_pop()) {
        if (const auto* syscall = std::get_if<syscall_event>(&*message)) {
            syscall_totals.process(*syscall);
            syscall_window.process(*syscall);
            ++progress.syscall_events;
        } else if (const auto* schedule = std::get_if<cpu_event>(&*message)) {
            cpu_analysis.process(*schedule);
            ++progress.cpu_events;
        } else if (const auto* lock_wait = std::get_if<kylinrca_lock_event>(&*message)) {
            // 当前窗口包含左边界，右边界上的记录等下一窗打开再送入分析器。
            if (lock_wait->header.timestamp_ns < lock_analysis.next_window_end_ns())
                lock_analysis.process(*lock_wait);
            else
                pending_lock_events.push_back(*lock_wait);
            ++progress.lock_events;
        } else if (const auto* io_completion = std::get_if<kylinrca_io_event>(&*message)) {
            // I/O 当前窗口包含右边界，超过边界的记录留待 tick。
            if (io_completion->header.timestamp_ns <= io_analysis.next_window_end_ns())
                io_analysis.process(*io_completion);
            else
                pending_io_events.push_back(*io_completion);
            ++progress.io_events;
        } else {
            const auto& tick = std::get<AnalysisTick>(*message);
            if (tick.io) {
                io_health = *tick.io;
                reports << io_probe_health_json(io_health) << '\n' << std::flush;
            }
            if (tick.cpu) {
                cpu_window = *tick.cpu;
                cpu_analysis.process_usage(cpu_window);
                reports << JsonReporter::report_cpu(cpu_analysis.diagnosis(), cpu_window.window_start_ns,
                           cpu_window.timestamp_ns, progress.cpu_events, &cpu_analysis.config()) << std::flush;
                cpu_analysis.cleanup_exited_threads(60s);
            } else if (!tick.final) {
                cpu_window = CpuUsageObservation{};
            }
            const auto now = std::chrono::steady_clock::now();
            if (common.enable_syscall && now >= next_syscall_cleanup) {
                syscall_totals.cleanup_exited_processes(60s);
                next_syscall_cleanup = now + 60s;
            }
            progress.window_start_ns = progress.updated_ns;
            progress.updated_ns = tick.timestamp_ns;
            if (!tick.final)
                ++progress.completed_windows;

            // 每轮最多各结算一个完整窗口。tick 跨过多窗时，每轮发布后再继续，避免覆盖尚未发布的结果。
            bool published = false;
            for (;;) {
                const auto lock_end_ns = lock_analysis.next_window_end_ns();
                const auto io_end_ns = io_analysis.next_window_end_ns();
                const bool close_lock_window = common.enable_lock && lock_end_ns <= tick.timestamp_ns;
                const bool close_io_window = common.enable_io && io_end_ns <= tick.timestamp_ns;
                if (!close_lock_window && !close_io_window)
                    break;
                if (close_lock_window) {
                    process_pending_through(pending_lock_events, lock_analysis, lock_end_ns - 1);
                    lock_analysis.advance_window(lock_end_ns);
                    reports << JsonReporter::report_locks(lock_analysis) << std::flush;
                }
                if (close_io_window) {
                    process_pending_through(pending_io_events, io_analysis, io_end_ns);
                    io_analysis.advance_window(io_end_ns);
                    write_io_reports();
                }
                publish_snapshot();
                published = true;
            }
            if (tick.final) {
                if (common.enable_lock) {
                    process_pending_through(pending_lock_events, lock_analysis, tick.timestamp_ns);
                    if (lock_analysis.flush(tick.timestamp_ns))
                        reports << JsonReporter::report_locks(lock_analysis) << std::flush;
                }
                if (common.enable_io) {
                    process_pending_through(pending_io_events, io_analysis, tick.timestamp_ns);
                    io_analysis.flush(tick.timestamp_ns);
                    write_io_reports();
                }
                publish_snapshot();
            } else {
                // 刚打开窗口的暂存记录先入统计，后续收到同窗记录时仍能保持原到达顺序。
                if (common.enable_lock)
                    process_pending_through(pending_lock_events, lock_analysis, lock_analysis.next_window_end_ns() - 1);
                if (common.enable_io)
                    process_pending_through(pending_io_events, io_analysis, io_analysis.next_window_end_ns());
                if (!published)
                    publish_snapshot();
            }
            syscall_window = SyscallAnalyzer{};
        }
    }
    if (common.enable_syscall)
        reports << JsonReporter::report_syscalls(syscall_totals) << std::flush;
}
