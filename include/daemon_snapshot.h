#ifndef KYLINRCA_DAEMON_SNAPSHOT_H
#define KYLINRCA_DAEMON_SNAPSHOT_H

#include "config_manager.h"
#include "cpu_analyzer.h"
#include "lock_analyzer.h"
#include "syscall_analyzer.h"

#include <memory>
#include <mutex>
#include <string>

struct AnalysisProgress {
    uint64_t started_ns = 0; //本次运行从什么时候开始。
    uint64_t window_start_ns = 0; //当前窗口从什么时候开始
    uint64_t updated_ns = 0; // 窗口结束=最近一次更新的时间戳，既可以是有事件的窗口，也可以是空窗口。
    uint64_t completed_windows = 0; // 已经完成的窗口数量。
    uint64_t syscall_events = 0; // 已经处理的 syscall_event 数量。
    uint64_t cpu_events = 0;
    uint64_t lock_events = 0;
};

/*快照*/
struct DaemonSnapshot {
    std::string status_json;
    std::string top_json;
    std::string report_json;
};

class SnapshotStore {
public:
    explicit SnapshotStore(DaemonSnapshot initial_snapshot);
    void publish(DaemonSnapshot next_snapshot);
    std::shared_ptr<const DaemonSnapshot> read() const;

private:
    mutable std::mutex mutex_;
    std::shared_ptr<const DaemonSnapshot> current_snapshot_;
};

// Only the analysis thread reads the analyzers. JSON construction happens before publishing.
DaemonSnapshot make_daemon_snapshot(const kylinrca::AppConfig& settings,
                                  const AnalysisProgress& progress,
                                  const SyscallAnalyzer& syscall_totals,
                                  const SyscallAnalyzer& syscall_window,
                                  const CpuUsageObservation& cpu_window,
                                  const CpuAnalyzer& cpu_analysis,
                                  const LockAnalyzer& lock_analysis);

#endif
