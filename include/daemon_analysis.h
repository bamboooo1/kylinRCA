#ifndef KYLINRCA_DAEMON_ANALYSIS_H
#define KYLINRCA_DAEMON_ANALYSIS_H

#include "daemon_snapshot.h"
#include "event_queue.h"

#include <ostream>

// 分析线程使用的公共开关和模块规则；探针设备过滤、日志和参数解析由主线程管理。
struct DaemonAnalysisSettings {
    kylinrca::AppConfig common;
    CpuAnalyzerConfig cpu;
    LockAnalyzerConfig lock;
    IoAnalyzerConfig io;
};

// 启动 Socket 前生成零计数快照，保留真实模块开关；尚无窗口报告。
DaemonSnapshot initial_daemon_snapshot(const DaemonAnalysisSettings& settings, uint64_t started_ns);

// 分析线程独占四个 Analyzer，消费队列直至关闭并排空，逐窗输出并统一发布快照。
// 主线程停止采集后必须发送 final tick，结算 I/O 和 Lock 尾窗；reports 可为标准输出或测试流。
void analyze_events(EventQueue& queue, const DaemonAnalysisSettings& settings,
                    uint64_t started_ns, SnapshotStore& snapshots, std::ostream& reports);

#endif
