#include "daemon_analysis.h"
#include "unix_socket_server.h"

#include <atomic>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <linux/futex.h>
#include <sys/syscall.h>

namespace {

constexpr uint64_t second_ns = 1'000'000'000;

// 测试失败统一抛异常，独立于编译器的 NDEBUG 设置，供 Python/CTest 判定非零退出。
void require(bool condition)
{
    if (!condition)
        throw std::runtime_error("daemon 队列、窗口或快照断言失败");
}

// 生成合法的设备 7:0 写入完成事件；调用方可调整字段验证迟到、无效或热点排序。
kylinrca_io_event make_io_event(uint64_t timestamp_ns)
{
    kylinrca_io_event completion{};
    completion.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_IO, sizeof(completion), timestamp_ns, 0, 0};
    completion.duration_ns = 10;
    completion.bytes = 4096;
    completion.dev_major = 7;
    completion.operation = IO_OP_WRITE;
    return completion;
}

// 合并原 EventQueue 与 I/O daemon 的重复用例：校验四类型分发、副本所有权、关闭排空和空队列唤醒。
void check_queue()
{
    EventQueue queue;
    syscall_event syscall{};
    syscall.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_SYSCALL, sizeof(syscall), 1, 42, 43};
    cpu_event schedule{};
    schedule.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_CPU, sizeof(schedule), 2, 42, 43};
    kylinrca_lock_event lock_wait{};
    lock_wait.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_LOCK, sizeof(lock_wait), 3, 42, 43};
    auto completion = make_io_event(4);
    require(!queue.push_record(nullptr, sizeof(completion)));
    require(!queue.push_record(&schedule, sizeof(schedule.header) - 1));
    schedule.header.type = EVENT_TYPE_UNKNOWN;
    require(!queue.push_record(&schedule, sizeof(schedule)));
    schedule.header.type = EVENT_TYPE_CPU;
    schedule.header.size = sizeof(schedule.header);
    require(!queue.push_record(&schedule, sizeof(schedule.header)));
    schedule.header.size = sizeof(schedule);
    schedule.header.version++;
    require(!queue.push_record(&schedule, sizeof(schedule)));
    schedule.header.version = KYLINRCA_EVENT_VERSION;
    require(!queue.push_record(&schedule, sizeof(schedule) - 1));

    std::vector<QueuedEvent> messages;
    std::thread worker([&] {
        while (auto message = queue.wait_pop())
            messages.push_back(std::move(*message));
    });
    const bool accepted = queue.push_record(&syscall, sizeof(syscall)) &&
        queue.push_record(&schedule, sizeof(schedule)) &&
        queue.push_record(&lock_wait, sizeof(lock_wait)) &&
        queue.push_record(&completion, sizeof(completion));
    syscall.header.tid = 0;
    completion.bytes = 0;
    queue.push(AnalysisTick{5, std::nullopt, std::nullopt, false});
    queue.close();
    worker.join();
    require(accepted && messages.size() == 5);
    for (std::size_t index = 0; index < messages.size(); ++index)
        require(messages[index].index() == index);
    require(std::get<syscall_event>(messages[0]).header.tid == 43);
    require(std::get<kylinrca_io_event>(messages[3]).bytes == 4096);
    require(std::get<AnalysisTick>(messages[4]).timestamp_ns == 5);
    require(!queue.wait_pop());

    EventQueue idle_queue;
    bool woke_without_message = false;
    std::thread waiting([&] { woke_without_message = !idle_queue.wait_pop(); });
    idle_queue.close();
    waiting.join();
    require(woke_without_message);
}

// 注入合成事件后运行真实分析线程，Socket 与 daemon 使用同一份分析和快照生成代码。
// 普通用例在已结算的边界关闭队列；尾窗用例显式发送 final tick，不依赖真实系统时钟。
DaemonSnapshot make_fixture_snapshot(const std::string& phase)
{
    DaemonAnalysisSettings settings;
    settings.io.latency_threshold_ns = 5;
    settings.io.min_samples = 1;
    settings.cpu.high_usage_threshold_percent = 80.5;
    EventQueue queue;
    IoProbeHealth health;
    health.pending = 2;
    if (phase == "disabled") {
        settings.common.enable_syscall = false;
        settings.common.enable_cpu = false;
        settings.common.enable_lock = false;
        settings.common.enable_io = false;
    }
    if (phase == "busy") {
        syscall_event historical_call{};
        historical_call.header.pid = 9999;
        historical_call.syscall_id = SYS_write;
        historical_call.duration_ns = second_ns;
        queue.push(historical_call);
        queue.push(AnalysisTick{2 * second_ns, std::nullopt, health, false});
        for (uint32_t pid = 100; pid < 113; ++pid) {
            syscall_event completed_call{};
            completed_call.header.pid = pid;
            completed_call.syscall_id = SYS_read;
            completed_call.duration_ns = (pid - 99) * 1'000'000;
            queue.push(completed_call);
        }
        for (uint32_t pid : {300, 301}) {
            for (uint32_t offset : {1, 2}) {
                kylinrca_lock_event lock_wait{};
                lock_wait.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_LOCK, sizeof(lock_wait),
                                    2 * second_ns + 100'000'000, pid, pid + offset};
                lock_wait.lock_addr = pid == 300 ? 0xaaa : 0xbbb;
                lock_wait.duration_ns = pid == 300 ? 60'000'000 : 30'000'000;
                lock_wait.futex_op = FUTEX_WAIT;
                queue.push(lock_wait);
            }
        }
        auto first_io = make_io_event(2 * second_ns + 100'000'000);
        queue.push(first_io);
        first_io.dev_minor = 1;
        first_io.duration_ns = 30;
        queue.push(first_io);
        CpuUsageObservation usage;
        usage.window_start_ns = 2 * second_ns;
        usage.timestamp_ns = 3 * second_ns;
        usage.system_usage_percent = 90;
        usage.has_runtime_snapshots = true;
        CpuProcessUsageObservation first_process;
        first_process.pid = 200;
        first_process.process_usage_percent = 100;
        first_process.threads = {{201, "hot", 87.5, true, 875'000'000, second_ns, 1000},
                                 {202, "cool", 12.5, false, 0, 0, 0}};
        CpuProcessUsageObservation second_process;
        second_process.pid = 210;
        second_process.process_usage_percent = 87.5;
        second_process.threads = {{211, "tie", 87.5, true, 875'000'000, second_ns, 2000}};
        usage.processes = {second_process, first_process};
        queue.push(AnalysisTick{3 * second_ns, usage, health, false});
    } else if (phase == "tick_first_window" || phase == "tick_second_window" ||
               phase == "tick_catch_up") {
        // 模拟三轮记录先到，定时消息稍后才入队。恰好在边界的记录按各模块原规则归属。
        for (uint32_t window = 0; window < 3; ++window) {
            kylinrca_lock_event lock_wait{};
            const uint64_t lock_timestamp = window == 0 ? second_ns + 100'000'000
                                                        : (window + 1) * second_ns;
            lock_wait.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_LOCK, sizeof(lock_wait),
                                lock_timestamp, 300, 301};
            lock_wait.lock_addr = 0xaaa + window;
            lock_wait.duration_ns = 50'000'000;
            lock_wait.futex_op = FUTEX_WAIT;
            queue.push(lock_wait);

            auto completion = make_io_event((window + 2) * second_ns);
            completion.dev_minor = window;
            queue.push(completion);
        }
        if (phase != "tick_catch_up")
            queue.push(AnalysisTick{2 * second_ns, std::nullopt, health, false});
        if (phase != "tick_first_window")
            queue.push(AnalysisTick{3 * second_ns, std::nullopt, health, false});
    } else if (phase == "io_rank") {
        queue.push(AnalysisTick{2 * second_ns, std::nullopt, health, false});
        for (uint32_t minor = 0; minor < 13; ++minor) {
            auto completion = make_io_event(2 * second_ns + 100'000'000);
            completion.dev_minor = minor;
            completion.duration_ns = (minor % 3 + 1) * 10;
            queue.push(completion);
        }
        queue.push(AnalysisTick{3 * second_ns, std::nullopt, health, false});
    } else if (phase == "lock_tail") {
        settings.common.enable_io = false;
        kylinrca_lock_event lock_wait{};
        lock_wait.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_LOCK, sizeof(lock_wait),
                            second_ns + 100'000'000, 300, 301};
        lock_wait.lock_addr = 0xaaa;
        lock_wait.duration_ns = 50'000'000;
        lock_wait.futex_op = FUTEX_WAIT;
        queue.push(lock_wait);
        queue.push(AnalysisTick{second_ns + 300'000'000, std::nullopt, std::nullopt, true});
    } else if (phase == "idle") {
        for (uint64_t end = 2; end <= 4; ++end) {
            CpuUsageObservation usage;
            usage.window_start_ns = (end - 1) * second_ns;
            usage.timestamp_ns = end * second_ns;
            queue.push(AnalysisTick{end * second_ns, usage, health, false});
        }
    } else if (phase == "missing_cpu_sample") {
        queue.push(AnalysisTick{2 * second_ns, std::nullopt, health, false});
    } else if (phase == "io_alert" || phase == "io_recovery") {
        for (uint64_t end = 2; end <= 4; ++end) {
            queue.push(make_io_event((end - 1) * second_ns + 100'000'000));
            queue.push(AnalysisTick{end * second_ns, std::nullopt, health, false});
        }
        if (phase == "io_recovery")
            queue.push(AnalysisTick{7 * second_ns, std::nullopt, health, false});
    } else if (phase == "io_tail") {
        queue.push(make_io_event(second_ns + 100'000'000));
        queue.push(AnalysisTick{second_ns + 300'000'000, std::nullopt, health, true});
    }
    queue.close();
    SnapshotStore snapshots(initial_daemon_snapshot(settings, second_ns));
    std::ostringstream reports;
    std::thread worker([&] { analyze_events(queue, settings, second_ns, snapshots, reports); });
    worker.join();
    return *snapshots.read();
}

// 保留同事的 I/O 窗口边界、迟到、拒收、连续告警、空窗恢复、尾窗和快照并发检查。
void check_io_windows()
{
    SnapshotStore snapshots(DaemonSnapshot{});
    IoAnalyzerConfig io_settings;
    io_settings.latency_threshold_ns = 5; io_settings.min_samples = 1;
    io_settings.window_ns = 100;
    IoAnalyzer io_analysis(100, io_settings);
    std::vector<IoReport> collected_reports;
    // 模拟 daemon：在调用分析器后取走报告，在外部构造快照，不把输出回调注入分析器。
    const auto collect = [&] {
        const auto finished_reports = io_analysis.take_reports();
        collected_reports.insert(collected_reports.end(), finished_reports.begin(), finished_reports.end());
        DaemonSnapshot frame;
        frame.io = make_io_snapshot(true, io_analysis, IoProbeHealth{});
        frame.report_json = io_snapshot_json(frame.io);
        snapshots.publish(std::move(frame));
    };
    EventQueue queue;
    auto completion = make_io_event(200);
    require(queue.push_record(&completion, sizeof(completion)));
    completion.bytes = 0; // 修改原始事件后，队列中的字节数仍应保持不变，以验证队列保存独立副本。
    auto item = queue.try_pop();
    require(item && std::get<kylinrca_io_event>(*item).bytes == 4096);
    io_analysis.process(std::get<kylinrca_io_event>(*item));
    collect();
    io_analysis.process(make_io_event(300)); // 新事件超过第一窗口边界，链路应先结算前窗，再接收此事件。
    collect();
    io_analysis.advance_window(200); // 已经过期的定时消息不得使窗口倒退或重复输出。
    collect();
    io_analysis.process(make_io_event(400));
    collect();
    io_analysis.advance_window(400);
    collect();
    require(collected_reports.size() == 3 && collected_reports[2].diagnoses.size() == 1);
    auto late = make_io_event(250);
    io_analysis.process(late);
    collect();
    io_analysis.advance_window(700); // 连续推进三个空窗口，验证原有持续告警按规则恢复。
    collect();
    require(collected_reports.size() == 6 && collected_reports.back().diagnoses.empty());
    require(collected_reports[3].late_events == 1);
    auto invalid = make_io_event(999999999);
    invalid.header.pid = 123;
    io_analysis.process(invalid);
    collect();
    require(collected_reports.size() == 6); // 字段不合法的事件即使带有很大的时间戳，也不能推进窗口。
    io_analysis.process(make_io_event(750));
    collect();
    io_analysis.flush(760); // 不足整窗的尾部只输出数据，不增加异常或恢复次数。
    collect();
    // 同一截止时间重复退出不得重复生成报告；累计字节保留迟到事件，窗口样本不回写。
    require(!io_analysis.flush(760));
    require(io_analysis.take_reports().empty());
    auto captured_snapshot = snapshots.read();
    require(captured_snapshot->io.counters.bytes == 5 * 4096 && captured_snapshot->io.counters.writes == 5);

    require(captured_snapshot->io.enabled && captured_snapshot->io.counters.received == 5 && captured_snapshot->io.counters.late == 1 && captured_snapshot->io.counters.invalid == 1);
    require(captured_snapshot->io.report && !captured_snapshot->io.report->window_complete);
    require(captured_snapshot->io.report->devices[0].abnormal_windows == 0);
    require(captured_snapshot->io.report->invalid_events == 1 && captured_snapshot->io.report->devices[0].bytes == 4096);
    // 同时重复发布和读取快照，确认读到的报告始终完整，并且读写互斥正常。
    std::atomic<bool> done{false};
    std::thread reader([&] { while (!done.load()) {
        const auto observed_snapshot = snapshots.read();
        if (!observed_snapshot->io.report || observed_snapshot->io.report->window_end_ns != 760) std::abort();
    }});
    for (int i=0; i<1000; ++i) collect();
    done = true; reader.join();
    // 分发前拒绝空地址、错误协议版本和长度不符的记录。
    require(!queue.push_record(nullptr, sizeof(completion)));
    completion = make_io_event(800); completion.header.version++;
    require(!queue.push_record(&completion, sizeof(completion)));
    completion = make_io_event(800); completion.header.size--;
    require(!queue.push_record(&completion, sizeof(completion)));
    completion = make_io_event(800);
    require(!queue.push_record(&completion, sizeof(completion)-1));
    require(captured_snapshot->io.report->devices[0].bytes == 4096); // 已经读出的快照持有独立报告，不受后续发布影响。
    IoAnalyzerConfig invalid_window;
    invalid_window.window_ns = 0;
    bool rejected = false;
    try { IoAnalyzer invalid_analyzer(100, invalid_window); }
    catch (const std::invalid_argument&) { rejected = true; }
    require(rejected);
}

} // 测试辅助代码命名空间结束

// --self-test 执行组件边界检查；传入 Socket 路径则提供可切换场景的真实分析/查询测试服务。
int main(int argc, char** argv)
{
    if (argc != 2)
        return 1;
    try {
        if (std::string(argv[1]) == "--self-test") {
            check_queue();
            check_io_windows();
            const auto tail = make_fixture_snapshot("io_tail");
            require(tail.io.report && !tail.io.report->window_complete);
            require(tail.io.counters.received == 1 && tail.io.probe.pending == 2);
            std::cout << "daemon 队列、窗口、尾窗和统一快照检查通过\n";
            return 0;
        }
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
            require(previous_snapshot->report_json == previous_report);
            std::cout << "published\n" << std::flush;
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
