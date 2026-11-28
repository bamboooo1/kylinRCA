#ifndef KYLINRCA_DAEMON_SNAPSHOT_H
#define KYLINRCA_DAEMON_SNAPSHOT_H

#include "config_manager.h"
#include "cpu_analyzer.h"
#include "io_snapshot.h"
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
    uint64_t io_events = 0;
};

/*快照*/
struct DaemonSnapshot {
    std::string status_json;
    std::string top_json;
    std::string report_json;
    IoSnapshot io; // 同批发布的 I/O 最终状态，供退出时输出 io_status，包含尾窗和健康计数。
};

class SnapshotStore {
public:
    // 启动时保存第一份只读快照；分析器仍由分析线程独占。
    explicit SnapshotStore(DaemonSnapshot initial_snapshot);
    // 锁外准备结果，仅替换指针时持锁；已有读者可继续使用旧快照。
    void publish(DaemonSnapshot next_snapshot);
    // 短暂加锁取得共享指针；序列化和 Socket 收发都在锁外完成。
    std::shared_ptr<const DaemonSnapshot> read() const;

private:
    mutable std::mutex mutex_;
    std::shared_ptr<const DaemonSnapshot> current_snapshot_;
};

// 分析线程读取各模块结果，生成同批查询字符串和最终 I/O 状态；不采集、不持仓库锁。
// 各模块保留自己的窗口边界；禁用模块和没有报告的窗口明确返回 null。
DaemonSnapshot make_daemon_snapshot(const kylinrca::AppConfig& settings,
                                  const AnalysisProgress& progress,
                                  const SyscallAnalyzer& syscall_totals,
                                  const SyscallAnalyzer& syscall_window,
                                  const CpuUsageObservation& cpu_window,
                                  const CpuAnalyzer& cpu_analysis,
                                  const LockAnalyzer& lock_analysis,
                                  const IoSnapshot& io_state);

#endif
