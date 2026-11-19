#include "json_reporter.h"
#include <sstream>
std::string JsonReporter::report_io(const IoReport& r)
{
    std::ostringstream o;
    o << "{\"type\":\"io_summary\",\"window_start_ns\":" << r.window_start_ns
      << ",\"window_end_ns\":" << r.window_end_ns
      << ",\"latency_threshold_ns\":" << r.latency_threshold_ns
      << ",\"min_samples\":" << r.min_samples
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
          << ",\"diagnosis\":\"" << (s.io_latency ? "IO_LATENCY" : "NORMAL") << "\"}";
    }
    o << "]}";
    return o.str();
}
