#include "json_reporter.h"
#include "cpu_analyzer.h"

#include <sstream>

std::string JsonReporter::report_cpu(const CpuDiagnosis& d, uint64_t window_start_ns,
                                     uint64_t window_end_ns, uint64_t received_events)
{
    std::ostringstream out;
    out << "{\"type\":\"cpu_summary\",\"window_start_ns\":" << window_start_ns
        << ",\"window_end_ns\":" << window_end_ns
        << ",\"received_events\":" << received_events
        << ",\"diagnosis\":{\"type\":\"" << cpu_diagnosis_state_name(d.state) << '"'
        << ",\"system_usage_percent\":" << d.system_usage_percent
        << ",\"culprit_pid\":" << d.culprit_pid
        << ",\"culprit_tid\":" << d.culprit_tid
        << ",\"culprit_process_usage_percent\":" << d.culprit_process_usage_percent
        << ",\"culprit_thread_usage_percent\":" << d.culprit_thread_usage_percent
        << ",\"culprit_oncpu_time_ns\":" << d.culprit_oncpu_time_ns
        << ",\"runtime_valid\":" << std::boolalpha << d.culprit_runtime_valid
        << ",\"runtime_window_ns\":" << d.culprit_runtime_window_ns
        << ",\"runtime_uncertainty_ns\":" << d.culprit_runtime_uncertainty_ns
        << ",\"culprit_runqueue_delay_ns\":" << d.culprit_runqueue_delay_ns
        << ",\"victim_pid\":" << d.victim_pid
        << ",\"victim_tid\":" << d.victim_tid
        << ",\"victim_max_runqueue_delay_ns\":" << d.victim_max_runqueue_delay_ns
        << ",\"average_runqueue_delay_ns\":" << d.average_runqueue_delay_ns
        << ",\"max_runqueue_delay_ns\":" << d.max_runqueue_delay_ns
        << ",\"consecutive_samples\":" << d.consecutive_samples << "}}\n";
    return out.str();
}
