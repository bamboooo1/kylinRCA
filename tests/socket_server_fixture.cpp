#include "daemon_snapshot.h"
#include "unix_socket_server.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <linux/futex.h>
#include <sys/syscall.h>

namespace {

constexpr uint64_t second_ns = 1'000'000'000;

DaemonSnapshot make_fixture_snapshot(const std::string& phase)
{
    kylinrca::AppConfig settings;
    AnalysisProgress progress;
    progress.started_ns = second_ns;
    progress.window_start_ns = second_ns;
    progress.updated_ns = second_ns;
    SyscallAnalyzer syscall_totals;
    SyscallAnalyzer syscall_window;
    CpuAnalyzer cpu_analysis;
    CpuUsageObservation cpu_window;
    LockAnalyzer lock_analysis;
    lock_analysis.advance_window(second_ns);

    if (phase == "busy") {
        progress.window_start_ns = 2 * second_ns;
        progress.updated_ns = 3 * second_ns;
        progress.completed_windows = 2;

        // A large historical syscall must appear in report, but not in this window's top.
        syscall_event historical_call{};
        historical_call.header.pid = 9999;
        historical_call.syscall_id = SYS_write;
        historical_call.duration_ns = second_ns;
        syscall_totals.process(historical_call);
        for (uint32_t pid = 100; pid < 113; ++pid) {
            syscall_event completed_call{};
            completed_call.header.pid = pid;
            completed_call.syscall_id = SYS_read;
            completed_call.duration_ns = (pid - 99) * 1'000'000;
            syscall_totals.process(completed_call);
            syscall_window.process(completed_call);
        }
        progress.syscall_events = 14;

        cpu_window.window_start_ns = 2 * second_ns;
        cpu_window.timestamp_ns = 3 * second_ns;
        cpu_window.system_usage_percent = 90;
        cpu_window.has_runtime_snapshots = true;
        CpuProcessUsageObservation first_process;
        first_process.pid = 200;
        first_process.process_usage_percent = 100;
        first_process.threads = {{201, "hot", 87.5, true, 875'000'000, second_ns, 1000},
                                 {202, "cool", 12.5, false, 0, 0, 0}};
        CpuProcessUsageObservation second_process;
        second_process.pid = 210;
        second_process.process_usage_percent = 87.5;
        second_process.threads = {{211, "tie", 87.5, true, 875'000'000, second_ns, 2000}};
        cpu_window.processes = {second_process, first_process};
        cpu_analysis.process_usage(cpu_window);

        for (uint32_t pid : {300, 301}) {
            for (uint32_t offset : {1, 2}) {
                kylinrca_lock_event lock_wait{};
                lock_wait.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_LOCK, sizeof(lock_wait),
                                    2 * second_ns + 100'000'000, pid, pid + offset};
                lock_wait.lock_addr = pid == 300 ? 0xaaa : 0xbbb;
                lock_wait.duration_ns = pid == 300 ? 60'000'000 : 30'000'000;
                lock_wait.futex_op = FUTEX_WAIT;
                if (!lock_analysis.process(lock_wait))
                    throw std::runtime_error("Fixture lock record was rejected");
            }
        }
        lock_analysis.advance_window(3 * second_ns);
        progress.lock_events = 4;
    } else if (phase == "idle") {
        progress.window_start_ns = 3 * second_ns;
        progress.updated_ns = 4 * second_ns;
        progress.completed_windows = 3;
        cpu_window.window_start_ns = 3 * second_ns;
        cpu_window.timestamp_ns = 4 * second_ns;
        cpu_analysis.process_usage(cpu_window);
        lock_analysis.advance_window(4 * second_ns);
    } else if (phase == "missing_cpu_sample") {
        progress.updated_ns = 2 * second_ns;
        progress.completed_windows = 1;
    } else if (phase == "disabled") {
        settings.enable_syscall = false;
        settings.enable_cpu = false;
        settings.enable_lock = false;
    }

    return make_daemon_snapshot(settings, progress, syscall_totals, syscall_window,
                                cpu_window, cpu_analysis, lock_analysis);
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2)
        return 1;
    try {
        SnapshotStore snapshots(make_fixture_snapshot("initial"));
        UnixSocketServer query_server(argv[1], snapshots);
        query_server.start();
        std::cout << "ready\n" << std::flush;
        std::string phase;
        while (std::getline(std::cin, phase) && phase != "stop") {
            const auto previous_snapshot = snapshots.read();
            const std::string previous_report = previous_snapshot->report_json;
            auto next_snapshot = make_fixture_snapshot(phase);
            if (phase == "large")
                next_snapshot.report_json = "{\"payload\":\"" + std::string(8 * 1024 * 1024, 'x') + "\"}";
            snapshots.publish(std::move(next_snapshot));
            if (previous_snapshot->report_json != previous_report)
                throw std::runtime_error("Publishing changed a snapshot held by a reader");
            std::cout << "published\n" << std::flush;
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
