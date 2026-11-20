#include "json_reporter.h"
#include "lock_analyzer.h"

#include <sstream>

namespace {//匿名命名空间，用于把辅助函数write_address和write_stats限制在当前 .cpp 文件内部使用。

/*地址使用十六进制字符串，避免 JSON 使用者将 64 位地址转成浮点数后丢失精度。*/
void write_address(std::ostream& out, uint64_t address)
{
    out << "\"0x" << std::hex << address << std::dec << '"';
}

/*诊断证据和逐锁明细使用同一组字段，保证等待次数、线程数和平均值口径一致。*/
void write_stats(std::ostream& out, const LockStats& stat)
{
    out << "\"event_count\": " << stat.event_count
        << ", \"wait_count\": " << stat.wait_count
        << ", \"waiting_threads\": " << stat.waiting_tids.size()
        << ", \"avg_wait_ns\": " << stat.average_wait_ns()
        << ", \"max_wait_ns\": " << stat.max_wait_ns
        << ", \"total_wait_ns\": " << stat.total_wait_ns
        << ", \"short_wait_count\": " << stat.short_wait_count
        << ", \"eagain_count\": " << stat.eagain_count
        << ", \"timeout_count\": " << stat.timeout_count
        << ", \"interrupted_count\": " << stat.interrupted_count
        << ", \"other_error_count\": " << stat.other_error_count
        << ", \"waiting_tids\": [";
    bool first = true;
    for (uint32_t tid : stat.waiting_tids) {
        if (!first)
            out << ", ";
        first = false;
        out << tid;
    }
    out << ']';
}

}

/*输出最近结算窗口、阈值、当前诊断及其触发证据；每份报告占一行，便于流式读取。*/
std::string JsonReporter::report_locks(const LockAnalyzer& analyzer)
{
    std::ostringstream out;
    const auto& config = analyzer.config();
    const auto& diagnosis = analyzer.diagnosis();
    out << "{\"type\": \"lock_summary\", \"wait_metric\": \"completed_futex_wait_ns\""
        << ", \"window_start_ns\": " << analyzer.window_start_ns()
        << ", \"window_end_ns\": " << analyzer.window_end_ns()
        << ", \"received_events\": " << analyzer.received_events()
        << ", \"rejected_events\": " << analyzer.rejected_events()
        << ", \"late_events\": " << analyzer.late_events()
        << ", \"thresholds\": {\"window_ns\": " << config.window_ns
        << ", \"minimum_wait_ns\": " << config.minimum_wait_ns
        << ", \"average_wait_threshold_ns\": " << config.average_wait_threshold_ns
        << ", \"max_wait_threshold_ns\": " << config.max_wait_threshold_ns
        << ", \"minimum_waiting_threads\": " << config.minimum_waiting_threads
        << ", \"recovery_windows\": " << config.recovery_windows << '}';

    out << ", \"diagnosis\": {\"type\": \""
        << (diagnosis.state == LockDiagnosisState::Contention ? "LOCK_CONTENTION" : "NORMAL")
        << "\", \"pid\": " << diagnosis.pid << ", \"lock_addr\": ";
    write_address(out, diagnosis.lock_addr);
    out << ", \"evidence_window_start_ns\": " << diagnosis.window_start_ns
        << ", \"evidence_window_end_ns\": " << diagnosis.window_end_ns
        << ", \"recovery_windows\": " << diagnosis.recovery_windows << ", ";
    write_stats(out, diagnosis.evidence);
    out << "}, \"processes\": [";

    bool first_process = true;
    for (const auto& [pid, locks] : analyzer.stats()) {
        if (!first_process)
            out << ", ";
        first_process = false;
        out << "{\"pid\": " << pid << ", \"locks\": [";
        bool first_lock = true;
        for (const auto& [address, stat] : locks) {
            if (!first_lock)
                out << ", ";
            first_lock = false;
            out << "{\"lock_addr\": ";
            write_address(out, address);
            out << ", ";
            write_stats(out, stat);
            out << '}';
        }
        out << "]}";
    }
    out << "]}\n";
    return out.str();
}

/*
假设进程 1234 中，8 个不同线程在同一处 futex 地址上，各成功等待了 100 ms，并且这些等待都在同一个统计窗口内结束。
report_locks() 可能生成下面这样的报告。这里为了阅读做了换行，并省略阈值、逐锁明细等字段：
{
  "type": "lock_summary",
  "wait_metric": "completed_futex_wait_ns",
  "window_start_ns": 1000000000,
  "window_end_ns": 2000000000,
  "received_events": 8,
  "rejected_events": 0,
  "late_events": 0,
  "diagnosis": {
    "type": "LOCK_CONTENTION",
    "pid": 1234,
    "lock_addr": "0x7f1234567000",
    "evidence_window_start_ns": 1000000000,
    "evidence_window_end_ns": 2000000000,
    "recovery_windows": 0,
    "event_count": 8,
    "wait_count": 8,
    "waiting_threads": 8,
    "avg_wait_ns": 100000000,
    "max_wait_ns": 100000000,
    "total_wait_ns": 800000000,
    "waiting_tids": [
      1235, 1236, 1237, 1238,
      1239, 1240, 1241, 1242
    ]
  }
}
*/
