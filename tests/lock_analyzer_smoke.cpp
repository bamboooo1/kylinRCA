/*通过可控事件检查聚合与诊断，不加载 BPF，也不依赖线程调度时机。*/
#include "lock_analyzer.h"
#include "json_reporter.h"

#include <linux/futex.h>

#include <cerrno>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

constexpr uint64_t second = 1'000'000'000;
constexpr uint64_t millisecond = 1'000'000;

/*检查失败时抛出异常，Release 构建也不会像 assert 一样省略检查。*/
void require(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

/*填写与探针一致的事件头；默认在第 1～2 秒窗口结束一次 100 毫秒等待。*/
kylinrca_lock_event make_event(uint32_t pid = 101, uint32_t tid = 1001,
    uint64_t address = 0x1000, uint64_t duration_ns = 100 * millisecond,
    uint64_t timestamp_ns = second + 500 * millisecond, int64_t ret = 0)
{
    kylinrca_lock_event event {};
    event.header.version = KYLINRCA_EVENT_VERSION;
    event.header.type = EVENT_TYPE_LOCK;
    event.header.size = sizeof(event);
    event.header.pid = pid;
    event.header.tid = tid;
    event.header.timestamp_ns = timestamp_ns;
    event.lock_addr = address;
    event.duration_ns = duration_ns;
    event.ret = ret;
    event.futex_op = FUTEX_WAIT_PRIVATE;
    return event;
}

/*这段测试是在验证：收到多条等待事件后，分析器有没有正确分组、统计，并找出竞争对象。 使用的是模拟事件，不会真的让线程等待。*/
void test_aggregation()
{
    LockAnalyzer analyzer;
    require(analyzer.process(make_event()), "first event rejected"); //进程 101 的线程 1001，在地址 0x1000 上等待了 100 ms。
    analyzer.process(make_event(101, 1001, 0x1000, 20 * millisecond)); //同一进程、同一线程、同一地址，再增加一次 20 ms 的等待。
    auto event = make_event(101, 1002, 0x1000, 60 * millisecond); //生成进程 101 的线程 1002 在同一地址等待 60 ms 的事件，暂存在变量 event 中。
    event.futex_op = FUTEX_WAIT_BITSET_PRIVATE | FUTEX_CLOCK_REALTIME; //修改这条事件的操作标志，检查：分析器能不能识别带这些标志的等待操作。
    analyzer.process(event); //现在，`101 / 0x1000` 这一组已经有三次等待：
    analyzer.process(make_event(202, 2001)); //加入另一个进程的事件
    analyzer.process(make_event(101, 1003, 0x2000)); //加入同一进程的另一个地址事件
    require(analyzer.advance_window(2 * second), "window did not close"); //把分析时间推进到第 2 秒，结算 [1秒, 2秒) 这个窗口。

    const auto& stat = analyzer.stats().at(101).at(0x1000); //从结果中找到“进程 101、地址 0x1000”的统计。
    require(stat.event_count == 3 && stat.wait_count == 3, "incorrect wait count");
    require(stat.waiting_tids == std::set<uint32_t>({1001, 1002}), "TID deduplication failed");
    require(stat.total_wait_ns == 180 * millisecond, "incorrect total wait");
    require(stat.average_wait_ns() == 60 * millisecond, "incorrect average wait");
    require(stat.max_wait_ns == 100 * millisecond, "incorrect maximum wait");
    require(analyzer.stats().size() == 2 && analyzer.stats().at(101).size() == 2,
        "PID or address groups were combined");
    require(analyzer.diagnosis().state == LockDiagnosisState::Contention,
        "multiple long waiters did not trigger");
    require(analyzer.diagnosis().pid == 101 && analyzer.diagnosis().lock_addr == 0x1000,
        "incorrect contention object");
}

/*验证：短等待和值不匹配等失败情况保留各自计数，不参与成功等待的平均值和线程集合。*/
void test_return_values()
{
    LockAnalyzer analyzer;
    analyzer.process(make_event());
    analyzer.process(make_event(101, 1002, 0x1000, 100));
    analyzer.process(make_event(101, 1003, 0x1000, 200 * millisecond, second + 500 * millisecond, -EAGAIN));
    analyzer.process(make_event(101, 1004, 0x1000, 200 * millisecond, second + 500 * millisecond, -ETIMEDOUT));
    analyzer.process(make_event(101, 1005, 0x1000, 200 * millisecond, second + 500 * millisecond, -EINTR));
    analyzer.process(make_event(101, 1006, 0x1000, 200 * millisecond, second + 500 * millisecond, -EINVAL));
    analyzer.advance_window(2 * second);
    const auto& stat = analyzer.stats().at(101).at(0x1000);
    require(stat.event_count == 6 && stat.wait_count == 1, "error returns counted as waits");
    require(stat.short_wait_count == 1 && stat.eagain_count == 1 && stat.timeout_count == 1 &&
        stat.interrupted_count == 1 && stat.other_error_count == 1, "return counters incorrect");
    require(stat.waiting_tids.size() == 1 && stat.average_wait_ns() == 100 * millisecond,
        "errors or short calls polluted wait evidence");
    require(analyzer.diagnosis().state == LockDiagnosisState::Normal, "one waiter triggered");
}

/*主要对象按累计等待选取，不能按单次最大值选择，也不能合并两个进程的相同地址。*/
void test_primary_object()
{
    LockAnalyzer analyzer;
    for (uint32_t tid = 1001; tid <= 1008; ++tid)
        analyzer.process(make_event(101, tid, 0x1000));
    analyzer.process(make_event(101, 1010, 0x2000, 300 * millisecond));
    analyzer.process(make_event(101, 1011, 0x2000, 300 * millisecond));
    analyzer.process(make_event(202, 2001, 0x1000, 900 * millisecond));
    analyzer.advance_window(2 * second);
    require(analyzer.diagnosis().pid == 101 && analyzer.diagnosis().lock_addr == 0x1000,
        "primary object was not selected by total qualified waiting time");
    require(analyzer.diagnosis().evidence.waiting_tids.size() == 8, "eight waiters missing");

    // 总耗时相同时以 PID、地址顺序决胜，与事件到达顺序无关。
    analyzer.reset();
    for (uint32_t pid : {202U, 101U}) {
        analyzer.process(make_event(pid, pid + 1, 0x2000));
        analyzer.process(make_event(pid, pid + 2, 0x2000));
    }
    analyzer.advance_window(2 * second);
    require(analyzer.diagnosis().pid == 101, "primary tie was not deterministic");
}

/*验证：判断现在有没有锁竞争，要看最近这个窗口里的等待，不能把以前发生的等待一直累加进来；一个线程反复等待也不是多人竞争。*/
void test_low_contention()
{
    LockAnalyzer analyzer;
    for (uint32_t tid = 1001; tid <= 1008; ++tid) {
        analyzer.process(make_event(101, tid, 0x1000, 500)); //	进程 101 的 8 个线程，在地址 0x1000 上各等待 500 纳秒。等待太短，没达到 1 ms 的统计门槛，不应触发告警。
        analyzer.process(make_event(101, tid, 0x2000, 2 * millisecond)); //	同样的 8 个线程，在地址 0x2000 上各等待 2 ms。线程虽然多，但平均和最大耗时都不够长，不应告警。
        analyzer.process(make_event(101, 1001, 0x3000)); //	每轮都给地址 0x3000 添加一次默认的 100 ms 等待。注意 TID 写死为 1001，所以最终是同一个线程等待 8 次，去重后仍只有 1 个等待线程，不满足多人等待门槛。
        analyzer.process(make_event(101, tid, 0x4000 + tid * 4)); //	地址使用 0x4000 + tid * 4，所以每个线程对应的地址都不同。每个地址只有一个等待线程，不能把它们合成同一把锁的竞争。
        analyzer.process(make_event(tid, tid, 0x5000)); //模拟的是 8 个不同进程，各有一个线程等待。地址虽然相同，也不能跨进程合并。
        analyzer.process(make_event(101, tid, 0x6000, 20 * millisecond)); //	8 个线程在地址 0x6000 上各等待 20 ms。平均值超过 10 ms 门槛，但最大值只有 20 ms，没有达到 50 ms，仍不应告警。
    }
    analyzer.advance_window(2 * second);
    require(analyzer.diagnosis().state == LockDiagnosisState::Normal, "low contention false alarm");
    analyzer.advance_window(3 * second);
    require(analyzer.stats().empty(), "old lock addresses were retained in an empty window");
    require(analyzer.diagnosis().state == LockDiagnosisState::Normal, "idle false alarm");

    // 下面验证两个线程在不同窗口各等待一次，不能合并成同窗的两个等待线程。
    analyzer.reset();
    analyzer.process(make_event()); //进程 101、线程 1001、地址 0x1000，等待 100 ms，在 1.5 秒结束。
    analyzer.process(make_event(101, 1002, 0x1000, 100 * millisecond, 2 * second + 500 * millisecond));
    analyzer.advance_window(3 * second);
    require(analyzer.diagnosis().state == LockDiagnosisState::Normal, "windows were combined");
}

/*连续正常窗口后恢复；新异常应重置恢复计数，旧证据必须保留其真实窗口时间。*/
void test_recovery()
{
    LockAnalyzer analyzer;
    analyzer.process(make_event());
    analyzer.process(make_event(101, 1002));
    analyzer.advance_window(2 * second);
    analyzer.advance_window(3 * second);
    require(analyzer.diagnosis().state == LockDiagnosisState::Contention &&
        analyzer.diagnosis().recovery_windows == 1, "alert did not wait for recovery");
    require(analyzer.diagnosis().window_end_ns == 2 * second &&
        analyzer.window_end_ns() == 3 * second, "old evidence was relabeled as current");

    analyzer.process(make_event(101, 1001, 0x1000, 100 * millisecond, 3 * second + 500 * millisecond));
    analyzer.process(make_event(101, 1002, 0x1000, 100 * millisecond, 3 * second + 500 * millisecond));
    analyzer.advance_window(4 * second);
    require(analyzer.diagnosis().recovery_windows == 0, "new contention did not cancel recovery");
    analyzer.advance_window(6 * second);
    require(analyzer.diagnosis().state == LockDiagnosisState::Normal &&
        analyzer.diagnosis().pid == 0 && analyzer.diagnosis().evidence.wait_count == 0,
        "idle windows did not clear old diagnosis");
    analyzer.advance_window(1'000'000'000 * second);
    require(analyzer.stats().empty(), "large time jump retained statistics");
}

/*检查三件事：坏事件要拒绝；同一窗口内允许乱序；已经结算的窗口不再接收迟到事件。*/
void test_validation_and_time()
{
    LockAnalyzer analyzer;
    auto reject = [&](const kylinrca_lock_event& event) {
        require(!analyzer.process(event), "invalid event was accepted");
    };
    auto event = make_event(); event.header.version = 99; reject(event); //版本号不符合当前协议。
    event = make_event(); event.header.type = EVENT_TYPE_CPU; reject(event); //传进来的是 CPU 事件，不是 Lock 事件。
    event = make_event(); event.header.size = 1; reject(event);//事件头的 size 字段不等于结构体大小。
    event = make_event(); event.header.pid = 0; reject(event);//进程 ID 为 0，表示内核线程，不是用户态的锁等待事件。
    event = make_event(); event.header.tid = 0; reject(event); //线程 ID 为 0，表示内核线程，不是用户态的锁等待事件。
    event = make_event(); event.lock_addr = 0; reject(event); //锁地址为 0，表示没有传入有效的 futex 地址。
    event = make_event(); event.reserved = 1; reject(event); //预留字段不为 0，表示事件格式不符合要求。
    event = make_event(); event.header.timestamp_ns = 0; reject(event); //时间戳为 0，表示没有传入有效的时间戳。
    event = make_event(); event.duration_ns = 2 * second; reject(event); //等待耗时超过 2 秒，表示事件不符合要求。
    event = make_event(); event.futex_op = FUTEX_WAKE_PRIVATE; reject(event); //传入的 futex 操作不是等待操作，而是唤醒操作，不符合要求。
    event = make_event(); event.ret = 1; reject(event); //传入的返回值不是 0 或负数，表示事件不符合要求。
    require(analyzer.rejected_events() == 11 && analyzer.received_events() == 0,
        "invalid event counters incorrect");

    analyzer.process(make_event()); //	先处理默认事件，它的结束时间是 1.5 秒。
    require(analyzer.process(make_event(101, 1002, 0x1000, 100 * millisecond,
        second + 400 * millisecond)), "same-window reordering rejected"); //	后收到另一条结束时间为 1.4 秒的事件，要求它仍被接受

    analyzer.process(make_event(202, 2001, 0x2000, 100 * millisecond, 2 * second));//	加入进程 202 的事件，结束时间恰好为 2 秒。处理时先结算旧窗口，再把事件放入新窗口。
    require(analyzer.stats().size() == 1 && analyzer.stats().count(101) == 1, //	检查刚结算的旧窗口只有进程 101，不能包含进程 202。
        "boundary event entered previous window");
    require(!analyzer.process(make_event()), "late event accepted");
    require(analyzer.late_events() == 1, "late event counter incorrect");
    require(!analyzer.advance_window(second), "backward clock advanced window");
    require(!analyzer.flush(second), "flush accepted a time before received events");
    analyzer.advance_window(3 * second);
    require(analyzer.stats().size() == 1 && analyzer.stats().count(202) == 1,
        "new window was polluted by late events");
}

/*检查：不足一秒能否结算、恰好达到阈值能否告警、重置是否有效、跨窗口等待如何统计，以及错误配置能否被拒绝。*/
void test_flush_and_thresholds()
{
    LockAnalyzerConfig config;
    config.average_wait_threshold_ns = 50 * millisecond; //	把平均等待告警阈值改成 50 ms，其他配置不变。最大等待阈值默认也是 50 ms。
    LockAnalyzer analyzer(config);
    analyzer.process(make_event(101, 1001, 0x1000, 50 * millisecond)); //模拟进程 101、线程 1001，在地址 0x1000 上等待 50 ms。
    analyzer.process(make_event(101, 1002, 0x1000, 50 * millisecond));
    require(analyzer.flush(second + 600 * millisecond), "partial window was not flushed"); //在 1.6 秒调用 flush()，要求成功结算。当前窗口原本要到第 2 秒才结束，这里提前结算 [1秒, 1.6秒)，模拟程序提前退出。
    require(analyzer.diagnosis().state == LockDiagnosisState::Contention,
        "equal thresholds did not trigger");
    require(!analyzer.flush(second + 600 * millisecond), "flush repeated a window"); //	再用相同的 1.6 秒调用 flush()，要求返回 false，不能把刚结算的窗口重复结算。
    
    analyzer.reset();
    require(analyzer.stats().empty() && analyzer.received_events() == 0 &&
        analyzer.diagnosis().state == LockDiagnosisState::Normal, "reset failed");
    analyzer.process(make_event(101, 1001, 0x1000, 1500 * millisecond, 2 * second));//模拟线程 1001 等待 1500 ms，在第 2 秒结束。因此等待开始时间是 0.5 秒，跨过了多个窗口边界。
    analyzer.process(make_event(101, 1002, 0x1000, millisecond, 2 * second));
    analyzer.advance_window(3 * second);
    require(analyzer.stats().at(101).at(0x1000).total_wait_ns == 1501 * millisecond,
        "cross-window wait was clipped or split"); //检查总等待必须为 1501 ms。说明跨窗口的等待保留完整耗时，没有被截短，也没有拆到其他窗口。

    config.window_ns = 0; //故意制造错误配置
    bool rejected = false;
    try { LockAnalyzer invalid(config); }
    catch (const std::invalid_argument&) { rejected = true; }
    require(rejected, "zero-length window accepted");
}

/*输出四份可解析的真实报告，交给 Python 检查 JSON 类型、64 位地址及恢复证据。*/
void print_json_fixtures()
{
    LockAnalyzer empty;
    empty.advance_window(second);//用第 1 秒初始化它的统计窗口。
    empty.flush(second + 100 * millisecond); // 用第 1 秒初始化它的统计窗口。
    std::cout << JsonReporter::report_locks(empty); //	生成并打印第一份 JSON：没有等待记录，状态为 NORMAL。

    LockAnalyzer analyzer;
    constexpr uint64_t address = 0xfedcba9876543210ULL; // 	定义一个固定的 64 位无符号地址数值。`constexpr` 表示编译时常量，`ULL` 表示无符号长长整数字面量。这个大数用于测试地址输出是否保持精度，不会真的访问该内存。
    for (uint32_t tid = 1008; tid >= 1001; --tid)
        analyzer.process(make_event(101, tid, address));
    analyzer.process(make_event(202, 2001, address, 200 * millisecond));
    analyzer.process(make_event(101, 1009, 0x2000, 200 * millisecond,
        second + 500 * millisecond, -EAGAIN)); // 虽然耗时很长，但返回值不表示成功等待，因此只计入 eagain_count，不计入合格等待指标。
    analyzer.advance_window(2 * second); //	推进到第 2 秒，结算 [1秒, 2秒) 窗口。进程 101 在 address 上的 8 个等待线程满足竞争条件。
    std::cout << JsonReporter::report_locks(analyzer);
    analyzer.advance_window(3 * second); //	推进到第 3 秒，结算下一个窗口。没有新事件，这是第一个正常空窗口，恢复计数增加到 1。
    std::cout << JsonReporter::report_locks(analyzer);
    analyzer.advance_window(4 * second); //	推进到第 4 秒。又经过一个空窗口，连续两个正常窗口，解除告警。
    std::cout << JsonReporter::report_locks(analyzer);
}

}

int main(int argc, char** argv)
{
    try {
        if (argc == 2 && std::string(argv[1]) == "--json") {
            print_json_fixtures();
            return 0;
        }
        test_aggregation();
        test_return_values();
        test_primary_object();
        test_low_contention();
        test_recovery();
        test_validation_and_time();
        test_flush_and_thresholds();
        std::cout << "Lock analyzer smoke OK\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Lock analyzer smoke failed: " << error.what() << '\n';
        return 1;
    }
}
