#include "json_reporter.h"
#include <sstream>
std::string JsonReporter::report_io(const IoReport& r)
{
    std::ostringstream o;
    o << "{\"type\":\"io_summary\",\"window_start_ns\":" << r.window_start_ns
      << ",\"window_end_ns\":" << r.window_end_ns
      << ",\"latency_threshold_ns\":" << r.latency_threshold_ns
      << ",\"min_samples\":" << r.min_samples
      << ",\"alert_consecutive_windows\":" << r.alert_consecutive_windows
      << ",\"recovery_consecutive_windows\":" << r.recovery_consecutive_windows
      << ",\"window_complete\":" << (r.window_complete ? "true" : "false")
      << ",\"invalid_events\":" << r.invalid_events
      << ",\"late_events\":" << r.late_events
      << ",\"capacity_drops\":" << r.capacity_drops << ",\"devices\":[";
    bool first = true;
    for (const auto& s : r.devices) {
        if (!first) o << ',';
        first = false;
        o << "{\"device\":\"" << s.major << ':' << s.minor
          << "\",\"dev_major\":" << s.major << ",\"dev_minor\":" << s.minor
          << ",\"sample_count\":" << s.count << ",\"bytes\":" << s.bytes
          << ",\"reads\":" << s.reads << ",\"writes\":" << s.writes
          << ",\"error_count\":" << s.errors
          << ",\"avg_duration_ns\":" << s.avg_duration_ns
          << ",\"p95_duration_ns\":" << s.p95_duration_ns
          << ",\"p99_duration_ns\":" << s.p99_duration_ns
          << ",\"window_abnormal\":" << (s.window_abnormal ? "true" : "false")
          << ",\"abnormal_windows\":" << s.abnormal_windows
          << ",\"recovery_windows\":" << s.recovery_windows
          << ",\"diagnosis\":\"" << (s.io_latency ? "IO_LATENCY" : "NORMAL") << "\"}";
    }
    o << "],\"diagnoses\":[";
    first = true;
    for (const auto& d : r.diagnoses) {
        if (!first) o << ',';
        first = false;
        o << "{\"device\":\"" << d.major << ':' << d.minor
          << "\",\"diagnosis\":\"IO_LATENCY\",\"abnormal_windows\":" << d.abnormal_windows
          << ",\"recovery_windows\":" << d.recovery_windows << '}';
    }
    o << "]}";
    return o.str();
}
