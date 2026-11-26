#ifndef KYLINRCA_IO_SNAPSHOT_H
#define KYLINRCA_IO_SNAPSHOT_H
#include "io_analyzer.h"
#include "io_probe_reader.h"
#include <mutex>
#include <optional>
#include <utility>

// 保存最近一次发布的 I/O 状态副本；未来查询线程读取副本，不直接访问分析线程中的分析器。
struct IoSnapshot {
    bool enabled = false; // 是否启用 I/O；关闭模块时不能把“没有报告”解释成“设备正常”。
    IoCounters counters; // 分析器提供的累计接收、字节和拒收计数。
    std::optional<IoReport> report; // 最近结算窗口的设备统计和持续告警；还没有窗口报告时为空。
    IoProbeHealth probe; // 最近一次主线程读取的探针健康计数，与窗口统计分别保存。
};

// 将状态副本转换为 io_status JSON，包含累计计数、探针健康和最近窗口；本函数不执行采集。
std::string io_snapshot_json(const IoSnapshot& snapshot);

// 管理分析线程发布的最近状态，为未来的查询线程提供带锁的副本读写。
class IoSnapshotStore {
public:
    // 分析线程调用：用新的完整状态替换旧副本；不累积历史报告，也不持有分析器引用。
    void publish(IoSnapshot value) {
        std::lock_guard<std::mutex> lock(mutex_);
        value_ = std::move(value);
    }
    // 查询方调用：复制最近状态后返回；调用方可在锁外序列化，避免长期阻塞分析线程。
    IoSnapshot read() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return value_;
    }
private:
    mutable std::mutex mutex_;
    IoSnapshot value_;
};

#endif
