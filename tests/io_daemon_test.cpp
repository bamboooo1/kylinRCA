#include "io_snapshot.h"
#include "event_queue.h"
#include <iostream>
#include <stdexcept>
#include <thread>
#include <atomic>
#include <vector>

// 测试断言入口：条件不成立时抛异常，使测试失败；不受编译时关闭标准断言的影响。
void require(bool value) { if (!value) throw std::runtime_error("I/O daemon analyzer assertion failed"); }
// 生成设备 7:0 的合成写事件，供调用方指定完成时间并修改字段，以构造边界、迟到和错误场景。
kylinrca_io_event event(uint64_t time) {
    kylinrca_io_event e{};
    e.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_IO, sizeof(e), time, 0, 0};
    e.duration_ns = 10; e.bytes = 4096; e.dev_major = 7; e.operation = IO_OP_WRITE;
    return e;
}
// 执行无需加载 BPF 的链路回归：检查四类型分发、队列副本、窗口边界、迟到、恢复、尾窗和并发快照。
// 任一断言失败返回非零值，供 CTest 判定失败；所有时间均为合成纳秒值。
int main() {
    try {
        // 按四模块事件和定时消息的顺序入队，关闭后仍应按原顺序全部取出。
        EventQueue mixed;
        syscall_event syscall{};
        syscall.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_SYSCALL, sizeof(syscall), 1, 42, 43};
        cpu_event cpu{};
        cpu.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_CPU, sizeof(cpu), 2, 42, 43};
        kylinrca_lock_event lock{};
        lock.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_LOCK, sizeof(lock), 3, 42, 43};
        auto io = event(4);
        require(mixed.push_record(&syscall, sizeof(syscall)));
        require(mixed.push_record(&cpu, sizeof(cpu)));
        require(mixed.push_record(&lock, sizeof(lock)));
        require(mixed.push_record(&io, sizeof(io)));
        mixed.push(AnalysisTick{5, std::nullopt, std::nullopt, false});
        mixed.close();
        for (std::size_t index = 0; index < 5; ++index) {
            const auto value = mixed.wait_pop();
            require(value && value->index() == index);
        }
        require(!mixed.wait_pop());
        IoSnapshotStore snapshots;
        IoAnalyzerConfig config;
        config.latency_threshold_ns = 5; config.min_samples = 1;
        config.window_ns = 100;
        IoAnalyzer analyzer(100, config);
        std::vector<IoReport> reports;
        // 模拟 daemon：在调用分析器后取走报告，在外部构造快照，不把输出回调注入分析器。
        const auto collect = [&] {
            const auto pending = analyzer.take_reports();
            reports.insert(reports.end(), pending.begin(), pending.end());
            IoSnapshot snapshot;
            snapshot.enabled = true;
            snapshot.counters = analyzer.counters();
            snapshot.report = analyzer.report();
            snapshots.publish(std::move(snapshot));
        };
        EventQueue queue;
        auto e = event(200);
        require(queue.push_record(&e, sizeof(e)));
        e.bytes = 0; // 修改原始事件后，队列中的字节数仍应保持不变，以验证队列保存独立副本。
        auto item = queue.try_pop();
        require(item && std::get<kylinrca_io_event>(*item).bytes == 4096);
        analyzer.process(std::get<kylinrca_io_event>(*item));
        collect();
        analyzer.process(event(300)); // 新事件超过第一窗口边界，链路应先结算前窗，再接收此事件。
        collect();
        analyzer.advance_window(200); // 已经过期的定时消息不得使窗口倒退或重复输出。
        collect();
        analyzer.process(event(400));
        collect();
        analyzer.advance_window(400);
        collect();
        require(reports.size() == 3 && reports[2].diagnoses.size() == 1);
        auto late = event(250);
        analyzer.process(late);
        collect();
        analyzer.advance_window(700); // 连续推进三个空窗口，验证原有持续告警按规则恢复。
        collect();
        require(reports.size() == 6 && reports.back().diagnoses.empty());
        require(reports[3].late_events == 1);
        auto invalid = event(999999999);
        invalid.header.pid = 123;
        analyzer.process(invalid);
        collect();
        require(reports.size() == 6); // 字段不合法的事件即使带有很大的时间戳，也不能推进窗口。
        analyzer.process(event(750));
        collect();
        analyzer.flush(760); // 不足整窗的尾部只输出数据，不增加异常或恢复次数。
        collect();
        // 同一截止时间重复退出不得重复生成报告；累计字节保留迟到事件，窗口样本不回写。
        require(!analyzer.flush(760));
        require(analyzer.take_reports().empty());
        auto snap = snapshots.read();
        require(snap.counters.bytes == 5 * 4096 && snap.counters.writes == 5);

        require(snap.enabled && snap.counters.received == 5 && snap.counters.late == 1 && snap.counters.invalid == 1);
        require(snap.report && !snap.report->window_complete);
        require(snap.report->devices[0].abnormal_windows == 0);
        require(snap.report->invalid_events == 1 && snap.report->devices[0].bytes == 4096);
        // 同时重复发布和读取快照，确认读到的报告始终完整，并且读写互斥正常。
        std::atomic<bool> done{false};
        std::thread reader([&] { while (!done.load()) {
            const auto value = snapshots.read();
            if (!value.report || value.report->window_end_ns != 760) std::abort();
        }});
        for (int i=0; i<1000; ++i) collect();
        done = true; reader.join();
        // 分发前拒绝空地址、错误协议版本和长度不符的记录。
        require(!queue.push_record(nullptr, sizeof(e)));
        e = event(800); e.header.version++;
        require(!queue.push_record(&e, sizeof(e)));
        e = event(800); e.header.size--;
        require(!queue.push_record(&e, sizeof(e)));
        e = event(800);
        require(!queue.push_record(&e, sizeof(e)-1));
        require(snap.report->devices[0].bytes == 4096); // 已经读出的快照持有独立报告，不受后续发布影响。
        IoAnalyzerConfig invalid_window;
        invalid_window.window_ns = 0;
        bool rejected = false;
        try { IoAnalyzer invalid_analyzer(100, invalid_window); }
        catch (const std::invalid_argument&) { rejected = true; }
        require(rejected);
        std::cout << "I/O daemon analyzer boundaries, recovery, copies and snapshots passed\n";
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
