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
    IoAnalyzer a(1000, {95, 10, 100, 2});
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
    std::cout << "I/O analyzer checks passed\n";
}
