#include "io_analyzer.h"
#include "json_reporter.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>
static void check(bool ok) { if (!ok) throw std::runtime_error("I/O assertion failed"); }
static kylinrca_io_event event(uint64_t t, uint64_t d, unsigned minor=1) {
    kylinrca_io_event e{};
    e.header.version=KYLINRCA_EVENT_VERSION; e.header.type=EVENT_TYPE_IO;
    e.header.size=sizeof(e); e.header.timestamp_ns=t;
    e.duration_ns=d; e.dev_major=8; e.dev_minor=minor;
    e.bytes=4096; e.operation=IO_OP_WRITE; return e;
}
int main() {
    // All protocol checks live in the analyzer and contribute to its report.
    IoAnalyzer validation(1000);
    for (int field = 0; field < 7; ++field) {
        auto bad = event(2000, 1);
        switch (field) {
        case 0: bad.header.version = 99; break;
        case 1: bad.header.type = EVENT_TYPE_CPU; break;
        case 2: bad.header.size = 1; break;
        case 3: bad.header.pid = 1; break;
        case 4: bad.header.tid = 1; break;
        case 5: bad.operation = IO_OP_OTHER + 1; break;
        case 6: bad.duration_ns = 2001; break;
        }
        check(validation.process_detailed(bad) == IoProcessResult::Invalid);
    }
    check(validation.process_detailed(event(1000, 1)) == IoProcessResult::Late);
    check(validation.process_detailed(event(2000, 1)) == IoProcessResult::Accepted);
    auto validation_report = validation.finish_window(3000);
    check(validation_report.invalid_events == 7 && validation_report.late_events == 1);
    check(validation_report.devices.size() == 1 && validation_report.devices[0].count == 1);
    IoAnalyzer bounded(1000, {1, 1, 1, 1, 1});
    check(bounded.process_detailed(event(2000, 1)) == IoProcessResult::Accepted);
    check(bounded.process_detailed(event(2001, 1)) == IoProcessResult::CapacityDropped);
    check(bounded.finish_window(3000).capacity_drops == 1);
    IoAnalyzer a(1000, {95, 10, 100, 2, 100000, 1, 1}); // 单窗口模式只用于原有指标测试
    for (unsigned i=1;i<=100;++i) check(a.process(event(2000+i,i)));
    auto other=event(2101,10,2); other.status=1; check(a.process(other));
    check(!a.process(event(1000,1)));
    auto bad=event(2200,1); bad.header.version=99; check(!a.process(bad));
    check(!a.process(event(2200,1))); // bounded capacity
    check(!a.process(event(2200,1,3))); // bounded devices
    auto r=a.finish_window(3000);
    check(r.devices.size()==2 && r.late_events==1 && r.invalid_events==1 && r.capacity_drops==2);
    auto s=r.devices[0];
    check(s.count==100 && s.bytes==409600 && s.writes==100);
    check(s.avg_duration_ns==50 && s.p95_duration_ns==95 && s.p99_duration_ns==99 && s.io_latency);
    check(r.devices[1].errors==1 && !r.devices[1].io_latency);
    check(JsonReporter::report_io(r).find("IO_LATENCY")!=std::string::npos);
    check(a.finish_window(4000).devices.empty());
    check(a.finish_window(5000).devices.empty());
    check(!a.process(event(4000,1)));
    check(a.process(event(5100,1)));
    r=a.finish_window(6000); check(!r.devices[0].io_latency && r.late_events==1);
    bool threw=false; try { a.finish_window(6000); } catch (const std::invalid_argument&) { threw=true; }
    check(threw);
    // 默认规则：三次连续异常触发，三次连续正常/空窗口恢复。
    IoAnalyzer stable(1000, {10, 1});
    auto slow_window = [&](unsigned minor = 1) {
        static uint64_t end = 2000;
        check(stable.process(event(end - 1, 20, minor)));
        auto report = stable.finish_window(end);
        end += 1000;
        return report;
    };
    auto first = slow_window();
    check(first.devices[0].window_abnormal && !first.devices[0].io_latency);
    check(first.devices[0].abnormal_windows == 1 && first.diagnoses.empty());
    check(!slow_window().devices[0].io_latency);
    auto triggered = slow_window();
    check(triggered.devices[0].io_latency && triggered.diagnoses.size() == 1);
    // 不足整窗的退出报告不能提前计作一次恢复。
    auto partial = stable.finish_window(4500, false);
    check(!partial.window_complete && partial.diagnoses[0].recovery_windows == 0);
    auto recovery1 = stable.finish_window(5000);
    check(recovery1.devices.empty() && recovery1.diagnoses[0].recovery_windows == 1);
    check(stable.finish_window(6000).diagnoses[0].recovery_windows == 2);
    auto recovered = stable.finish_window(7000);
    check(recovered.diagnoses.empty() && recovered.devices.empty());
    check(JsonReporter::report_io(recovery1).find("\"recovery_windows\":1") != std::string::npos);
    check(JsonReporter::report_io(recovered).find("\"diagnoses\":[]") != std::string::npos);

    // 交替异常不能累积；两个设备的异常序列独立。
    IoAnalyzer separate(1000, {10, 1});
    uint64_t end = 2000;
    auto step = [&](bool bad1, bool bad2, bool complete = true) {
        check(separate.process(event(end - 1, bad1 ? 20 : 1, 1)));
        check(separate.process(event(end - 1, bad2 ? 20 : 1, 2)));
        auto report = separate.finish_window(end, complete);
        end += 1000;
        return report;
    };
    check(step(true, false).diagnoses.empty());
    check(step(false, true).diagnoses.empty());
    check(step(true, true).diagnoses.empty());
    auto isolated = step(true, true);
    check(!isolated.devices[0].io_latency && isolated.devices[1].io_latency);
    auto both = step(true, false);
    check(both.devices[0].io_latency && both.devices[1].io_latency);
    check(both.devices[1].recovery_windows == 1);
    // 恢复期间再次异常会清除恢复计数，不需要重新等待三次才保持告警。
    auto relapse = step(false, true);
    check(relapse.devices[1].io_latency && relapse.devices[1].recovery_windows == 0);
    // 有样本的正常窗口也需要连续三次；恢复中断后从第一次重新计数。
    check(step(false, false).devices[1].recovery_windows == 1);
    check(step(false, false).devices[1].recovery_windows == 2);
    auto normal_samples = step(false, false);
    check(!normal_samples.devices[1].io_latency && normal_samples.diagnoses.empty());
    // 未触发前的部分窗口也不能增加异常次数。
    IoAnalyzer tail(1000, {10, 1});
    check(tail.process(event(1500, 20)));
    auto tail_report = tail.finish_window(2000, false);
    check(tail_report.devices[0].window_abnormal && tail_report.devices[0].abnormal_windows == 0);
    check(tail_report.diagnoses.empty());
    // 持续状态也占用设备容量，恢复后释放容量供新设备使用。
    IoAnalyzer limited(1000, {10, 1, 100, 1, 100, 1, 3});
    check(limited.process(event(1500, 20)));
    check(limited.finish_window(2000).diagnoses.size() == 1);
    check(limited.process_detailed(event(2500, 20, 2)) == IoProcessResult::CapacityDropped);
    limited.finish_window(3000);
    limited.finish_window(4000);
    check(limited.finish_window(5000).diagnoses.empty());
    check(limited.process(event(5500, 20, 2)));
    // 连续次数不允许配置为零。
    for (bool alert : {true, false}) {
        IoAnalyzerConfig config;
        if (alert) config.alert_consecutive_windows = 0;
        else config.recovery_consecutive_windows = 0;
        bool rejected = false;
        try { IoAnalyzer invalid(1000, config); }
        catch (const std::invalid_argument&) { rejected = true; }
        check(rejected);
    }
    std::cout << "I/O analyzer checks passed\n";
}
