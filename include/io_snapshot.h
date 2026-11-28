#ifndef KYLINRCA_IO_SNAPSHOT_H
#define KYLINRCA_IO_SNAPSHOT_H
#include "io_analyzer.h"
#include "io_probe_reader.h"
#include <optional>

// 保存最近一次发布的 I/O 状态副本；未来查询线程读取副本，不直接访问分析线程中的分析器。
struct IoSnapshot {
    bool enabled = false; // 是否启用 I/O；关闭模块时不能把“没有报告”解释成“设备正常”。
    IoCounters counters; // 分析器提供的累计接收、字节和拒收计数。
    std::optional<IoReport> report; // 最近结算窗口的设备统计和持续告警；还没有窗口报告时为空。
    IoProbeHealth probe; // 最近一次主线程读取的探针健康计数，与窗口统计分别保存。
};

// 将状态副本转换为 io_status JSON，包含累计计数、探针健康和最近窗口；本函数不执行采集。
std::string io_snapshot_json(const IoSnapshot& snapshot);

// 分析线程结算后复制模块的累计值、最近报告和探针健康数据；禁用时只保留 enabled=false。
// 数据随 DaemonSnapshot 统一发布，不另设模块仓库，不持有分析器引用。
IoSnapshot make_io_snapshot(bool enabled, const IoAnalyzer& analysis, const IoProbeHealth& health);

#endif
