#include "io_snapshot.h"
#include "json_reporter.h"
#include <sstream>

// 把调用方取得的快照副本序列化为 io_status，供退出输出和未来查询接口复用。
// 尚未产生窗口时 report 输出 null；序列化过程不修改采集或诊断状态。
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
