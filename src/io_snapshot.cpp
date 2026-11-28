#include "io_snapshot.h"
#include "json_reporter.h"
#include <sstream>

// 分析线程构造 I/O 的值副本；查询发布和加锁由统一仓库负责。
IoSnapshot make_io_snapshot(bool enabled, const IoAnalyzer& analysis, const IoProbeHealth& health)
{
    IoSnapshot state;
    state.enabled = enabled;
    if (enabled) {
        state.counters = analysis.counters();
        state.report = analysis.report();
        state.probe = health;
    }
    return state;
}

// 查询和退出输出复用相同 io_status 字段；尚无窗口时 report 为 null，不修改输入状态。
std::string io_snapshot_json(const IoSnapshot& snapshot)
{
    std::ostringstream out;
    out << "{\"type\":\"io_status\",\"enabled\":" << (snapshot.enabled ? "true" : "false")
        << ",\"received\":" << snapshot.counters.received << ",\"invalid\":" << snapshot.counters.invalid
        << ",\"late_events\":" << snapshot.counters.late << ",\"capacity_drops\":" << snapshot.counters.capacity_drops
        << ",\"reads\":" << snapshot.counters.reads << ",\"writes\":" << snapshot.counters.writes
        << ",\"bytes\":" << snapshot.counters.bytes
        << ",\"probe\":" << io_probe_health_json(snapshot.probe)
        << ",\"report\":" << (snapshot.report ? JsonReporter::report_io(*snapshot.report) : "null") << '}';
    return out.str();
}
