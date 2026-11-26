#include "json_reporter.h"
#include "cpu_analyzer.h"

#include <sstream>
#include <iomanip>
#include <limits>

// 输出当前 CPU 窗口诊断及可选的实际阈值；旧调用方可省略配置参数。
// 只读取输入，不采样，也不更改异常或恢复状态。
std::string JsonReporter::report_cpu(const CpuDiagnosis& d, uint64_t window_start_ns,
                                     uint64_t window_end_ns, uint64_t received_events,
                                     const CpuAnalyzerConfig* config)
{
    std::ostringstream out;
    out << "{\"type\":\"cpu_summary\",\"window_start_ns\":" << window_start_ns
        << ",\"window_end_ns\":" << window_end_ns
        << ",\"received_events\":" << received_events;
    if (config) {
        // 保留足够有效位数，使配置中的小数阈值能够从 JSON 精确回读。
        out << std::setprecision(std::numeric_limits<double>::max_digits10);
        out << ",\"thresholds\":{\"high_usage_threshold_percent\":" << config->high_usage_threshold_percent
            << ",\"recovery_threshold_percent\":" << config->recovery_threshold_percent
            << ",\"runqueue_delay_threshold_ns\":" << config->runqueue_delay_threshold_ns
            << ",\"alert_consecutive_samples\":" << config->alert_consecutive_samples
            << ",\"recovery_consecutive_samples\":" << config->recovery_consecutive_samples << '}';
    }
    out << ",\"diagnosis\":{\"type\":\"" << cpu_diagnosis_state_name(d.state) << '"'
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
