#include "cpu_config.h"
#include "lock_config.h"
#include "json_reporter.h"
#include <linux/futex.h>
#include <iostream>
#include <sstream>
#include <stdexcept>

// 条件不满足时让测试明确失败，不受 NDEBUG 影响。
void require(bool value) { if (!value) throw std::runtime_error("module config assertion failed"); }
// 确认某模块拒绝非法文本，而不是悄悄采用默认值或修正错误参数。
template<typename Config>
void rejects(const std::string& text) {
    std::istringstream input(text);
    try { Config::parse(input); }
    catch (const std::runtime_error&) { return; }
    throw std::runtime_error("invalid module config accepted: " + text);
}
// 构造同一进程、同一锁上的成功等待，供验证配置确实改变分类与告警。
kylinrca_lock_event wait_event(uint32_t tid) {
    kylinrca_lock_event e{};
    e.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_LOCK, sizeof(e), 1000000 + tid, 42, tid};
    e.lock_addr = 0x1000; e.duration_ns = 4000; e.futex_op = FUTEX_WAIT;
    return e;
}
// 验证默认值、文件读取、严格校验、单位转换，并用相同观测比较默认和自定义诊断行为。
int main(int argc, char** argv) {
    try {
        require(argc == 3);
        const auto cpu_default = CpuConfig::load(argv[1]).analyzer;
        const auto lock_default = LockConfig::load(argv[2]).analyzer;
        require(cpu_default.high_usage_threshold_percent == 80 &&
                cpu_default.recovery_threshold_percent == 50 &&
                cpu_default.runqueue_delay_threshold_ns == 10000000 &&
                cpu_default.alert_consecutive_samples == 3 && cpu_default.recovery_consecutive_samples == 3);
        require(lock_default.minimum_wait_ns == 1000000 && lock_default.average_wait_threshold_ns == 10000000 &&
                lock_default.max_wait_threshold_ns == 50000000 && lock_default.minimum_waiting_threads == 2 &&
                lock_default.recovery_windows == 2 && lock_default.window_ns == 1000000000);
        std::istringstream empty_cpu(""), empty_lock("");
        require(CpuConfig::parse(empty_cpu).analyzer.high_usage_threshold_percent == 80);
        require(LockConfig::parse(empty_lock).analyzer.recovery_windows == 2);
        std::istringstream cpu_text(
            "# 配置\r\n high_usage_threshold_percent=12.5\r\nrecovery_threshold_percent=5.25\n"
            "runqueue_delay_threshold_us=123\nalert_consecutive_samples=2\nrecovery_consecutive_samples=2");
        const auto cpu_config = CpuConfig::parse(cpu_text).analyzer;
        require(cpu_config.runqueue_delay_threshold_ns == 123000);
        CpuAnalyzer cpu(cpu_config), cpu_control;
        CpuUsageObservation usage{};
        usage.system_usage_percent = 20;
        cpu.process_usage(usage); cpu_control.process_usage(usage);
        require(cpu.diagnosis().state == CpuDiagnosisState::Normal);
        cpu.process_usage(usage); cpu_control.process_usage(usage);
        require(cpu.diagnosis().state == CpuDiagnosisState::HighUsage);
        require(cpu_control.diagnosis().state == CpuDiagnosisState::Normal);
        const auto json = JsonReporter::report_cpu(cpu.diagnosis(), 0, 1, 0, &cpu.config());
        require(json.find("\"high_usage_threshold_percent\":12.5") != std::string::npos);
        require(json.find("\"runqueue_delay_threshold_ns\":123000") != std::string::npos);
        usage.system_usage_percent = 4;
        cpu.process_usage(usage);
        require(cpu.diagnosis().state == CpuDiagnosisState::HighUsage);
        cpu.process_usage(usage);
        require(cpu.diagnosis().state == CpuDiagnosisState::Normal);

        // 配置阈值的小数精度不能在报告中被默认的六位有效数字截短。
        std::istringstream precise_text("high_usage_threshold_percent=80.123456789");
        CpuAnalyzer precise(CpuConfig::parse(precise_text).analyzer);
        require(JsonReporter::report_cpu(precise.diagnosis(), 0, 1, 0, &precise.config())
                    .find("80.123456789") != std::string::npos);

        std::istringstream lock_text("minimum_wait_us=1\naverage_wait_threshold_us=2\n"
                                    "max_wait_threshold_us=3\nminimum_waiting_threads=2\nrecovery_windows=1");
        const auto lock_config = LockConfig::parse(lock_text).analyzer;
        LockAnalyzer locks(lock_config), lock_control;
        locks.advance_window(0); lock_control.advance_window(0);
        for (uint32_t tid : {43, 44}) {
            require(locks.process(wait_event(tid)));
            require(lock_control.process(wait_event(tid)));
        }
        locks.advance_window(1000000000); lock_control.advance_window(1000000000);
        require(locks.diagnosis().state == LockDiagnosisState::Contention);
        require(lock_control.diagnosis().state == LockDiagnosisState::Normal);
        require(locks.stats().at(42).at(0x1000).wait_count == 2);
        locks.advance_window(2000000000);
        require(locks.diagnosis().state == LockDiagnosisState::Normal);

        for (auto value : {"-1", "+1", "NaN", "inf", "101", "1e1", "80%", ".", "1.2.3"})
            rejects<CpuConfig>(std::string("high_usage_threshold_percent=") + value);
        rejects<CpuConfig>("high_usage_threshold_percent=50\nrecovery_threshold_percent=50");
        rejects<CpuConfig>("high_usage_threshold_percent=20");
        rejects<CpuConfig>("recovery_threshold_percent=90");
        rejects<CpuConfig>("window_ms=100");
        rejects<LockConfig>("window_ms=100");
        for (auto key : {"runqueue_delay_threshold_us", "alert_consecutive_samples", "recovery_consecutive_samples"})
            for (auto value : {"0", "-1", "+1", "1.5", "4294967296", "1ms"})
                rejects<CpuConfig>(std::string(key) + "=" + value);
        for (auto key : {"minimum_wait_us", "average_wait_threshold_us", "max_wait_threshold_us",
                         "minimum_waiting_threads", "recovery_windows"})
            for (auto value : {"0", "-1", "+1", "1.5", "4294967296", "1ms"})
                rejects<LockConfig>(std::string(key) + "=" + value);
        rejects<LockConfig>("minimum_waiting_threads=1");
        rejects<LockConfig>("minimum_wait_us=20000");
        rejects<LockConfig>("max_wait_threshold_us=1");
        rejects<LockConfig>("recovery_windows=1\nrecovery_windows=2");
        rejects<CpuConfig>("alert_consecutive_samples=1\nalert_consecutive_samples=2");
        rejects<CpuConfig>("unknown=1");
        rejects<LockConfig>("enable_lock=true");
        rejects<CpuConfig>("high_usage_threshold_percent=80 # 注释");
        rejects<LockConfig>(std::string("recovery_windows=2\0", 19));
        std::istringstream maximum("runqueue_delay_threshold_us=4294967295\nalert_consecutive_samples=4294967295");
        require(CpuConfig::parse(maximum).analyzer.runqueue_delay_threshold_ns == 4294967295000ULL);
        std::istringstream bad_stream("");
        bad_stream.setstate(std::ios::badbit);
        bool rejected = false;
        try { CpuConfig::parse(bad_stream); } catch (const std::runtime_error&) { rejected = true; }
        require(rejected);
        rejected = false;
        try { LockConfig::load("/nonexistent/kylinrca-lock.conf"); }
        catch (const std::runtime_error&) { rejected = true; }
        require(rejected);
        std::cout << "CPU/Lock module config and diagnosis behavior passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
