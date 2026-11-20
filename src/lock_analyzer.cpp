#include "lock_analyzer.h"

#include <linux/futex.h>

#include <algorithm>
#include <cerrno>
#include <stdexcept>
#include <utility>

/*构造函数：使用传入的 config 初始化成员变量 config_。
    检查配置关系，避免零窗口、单线程规则或反向阈值产生无意义的判断。
    struct LockAnalyzerConfig {
    uint64_t window_ns = 1'000'000'000;
    uint64_t minimum_wait_ns = 1'000'000;
    uint64_t average_wait_threshold_ns = 10'000'000;
    uint64_t max_wait_threshold_ns = 50'000'000;
    std::size_t minimum_waiting_threads = 2;
    std::size_t recovery_windows = 2; // 连续两个正常窗口后解除告警。
};*/
LockAnalyzer::LockAnalyzer(LockAnalyzerConfig config) : config_(config)
{
    if (!config_.window_ns || !config_.minimum_wait_ns ||
        config_.average_wait_threshold_ns < config_.minimum_wait_ns ||
        config_.max_wait_threshold_ns < config_.average_wait_threshold_ns ||
        config_.minimum_waiting_threads < 2 || !config_.recovery_windows)
        throw std::invalid_argument("Invalid lock analyzer configuration");
}

/*process() 把一条条记录归到对应对象。先校验事件，再按 PID 和地址更新当前窗口；
    不同进程中的相同虚拟地址分别统计。
    struct kylinrca_lock_event {
        struct kylinrca_event_header header; //	事件类型、时间戳、PID/TID 等公共信息
        __u64 lock_addr; //    锁地址，用户态传入的 futex 地址
        __u64 duration_ns; //    从调用开始到返回的耗时，单位纳秒
        __s64 ret;      //    futex 调用返回值，内核层返回的原始值
        __u32 futex_op; //	等待操作及其标志
        __u32 reserved;  // 	预留字段，发送时置零
    };*/
bool LockAnalyzer::process(const kylinrca_lock_event& event)
{
    const uint32_t command = event.futex_op & FUTEX_CMD_MASK;
    if (event.header.version != KYLINRCA_EVENT_VERSION ||
        event.header.type != EVENT_TYPE_LOCK || event.header.size != sizeof(event) ||
        !event.header.pid || !event.header.tid || !event.lock_addr || event.reserved ||
        !event.header.timestamp_ns || event.duration_ns > event.header.timestamp_ns || //检查等待时长是否超过结束时间戳，避免接受不合理的数据。
        event.ret > 0 || (command != FUTEX_WAIT && command != FUTEX_WAIT_BITSET)) {
        ++rejected_events_;
        return false;
    }
    // initialized_ 是一个 bool 类型的变量，用来表示：锁分析器是否已经初始化了第一个统计窗口。
    // 已经输出的窗口不回写，避免旧事件重新触发告警。
    if (initialized_ && event.header.timestamp_ns < current_start_ns_) {
        ++late_events_;
        return false;
    }
    advance_window(event.header.timestamp_ns);
    latest_event_ns_ = std::max(latest_event_ns_, uint64_t{event.header.timestamp_ns});
    ++received_events_;

    LockStats& stat = window_stats_[event.header.pid][event.lock_addr];
    ++stat.event_count;
    // 超时、信号中断等单独保留；即使 ret 为 0，也只表示等待返回，不代表已获得锁。
    if (event.ret == -EAGAIN) { //EAGAIN：Linux 错误码，表示当前条件不满足，需要重新尝试。
        ++stat.eagain_count;
    } else if (event.ret == -ETIMEDOUT) {
        ++stat.timeout_count;
    } else if (event.ret == -EINTR) {
        ++stat.interrupted_count;
    } else if (event.ret != 0) {
        ++stat.other_error_count;
    } else if (event.duration_ns < config_.minimum_wait_ns) {
        ++stat.short_wait_count;
    } else { //对于成功返回、耗时至少为默认 1 ms 的事件，执行：增加等待次数、累加耗时、更新最大值、记录等待线程。
        ++stat.wait_count;
        stat.total_wait_ns += event.duration_ns;
        stat.max_wait_ns = std::max(stat.max_wait_ns, uint64_t{event.duration_ns});
        stat.waiting_tids.insert(event.header.tid);
    }
    return true;
}

/*以单调时钟的固定边界分窗；即使跨过很多空窗口，也只做一次恢复计算。
    false 表示没有发生窗口切换；
    true 表示至少完成了一次窗口推进。*/
bool LockAnalyzer::advance_window(uint64_t timestamp_ns)
{
    //initialized_ = false时，表示锁分析器还没有初始化第一个统计窗口。
    // 此时，advance_window() 函数会根据传入的 timestamp_ns 参数计算出
    // 当前窗口的起始时间 current_start_ns_，并将 initialized_ 设置为 true，
    // 表示已经初始化了第一个统计窗口。然后返回 false，表示没有推进窗口。
    if (!initialized_) {
        current_start_ns_ = timestamp_ns - timestamp_ns % config_.window_ns;
        initialized_ = true;
        return false;
    } 
    if (timestamp_ns < current_start_ns_ ||
        timestamp_ns - current_start_ns_ < config_.window_ns)// 当前窗口还没结束，不进行结算
        return false;

    const uint64_t windows = (timestamp_ns - current_start_ns_) / config_.window_ns;
    const uint64_t end_ns = current_start_ns_ + windows * config_.window_ns;
    finish_window(current_start_ns_ + config_.window_ns);// 当前窗口结束，统计并判断锁竞争

    if (windows > 1) { //当windows>1时，说明此次到达的新事件已经跨越了多个窗口，则需要以下操作
        stats_.clear(); //清除旧窗口的统计数据。
        /*假设当前窗口是 [2s, 3s)，新事件在 4.5s 到达。
            执行：finish_window(3s);此时 stats_ 保存的是 [2s, 3s) 的统计数据。
            但是 [3s, 4s) 没有收到任何事件。
            所以执行：stats_.clear();
            目的是让 stats_ 不再保留 [2s, 3s) 的旧数据，避免调用方误以为这些数据属于最近的 [3s, 4s) 窗口。
            注意：stats_.clear() 只清除统计数据，不会直接清除 diagnosis_ 中的异常诊断和历史证据。
            异常是否解除由 recover() 决定。*/

        recover(windows - 1); //将跳过的空窗口计入异常恢复判断。
        report_start_ns_ = end_ns - config_.window_ns;
        report_end_ns_ = end_ns; //只记录最后一个空窗口：因为 stats_ 只保存最近一次结算结果，而不是所有历史窗口
        current_start_ns_ = end_ns; //直接把当前窗口推进到新事件所属的窗口。
    }
    return true;
}

/*结算当前窗口，按累计等待时间选择满足规则的主要竞争对象。*/
void LockAnalyzer::finish_window(uint64_t end_ns)
{
    report_start_ns_ = current_start_ns_;
    report_end_ns_ = end_ns;
    current_start_ns_ = end_ns;
    stats_ = std::move(window_stats_); //把当前窗口的统计数据移动到 stats_，以便调用方获取最近一次结算结果。
    window_stats_.clear();

    const LockStats* primary = nullptr;
    uint32_t primary_pid = 0;
    uint64_t primary_addr = 0;
    for (const auto& [pid, locks] : stats_) { //第一层 for：遍历所有进程。
        for (const auto& [address, stat] : locks) { //第二层 for：遍历该进程中的所有 futex 地址。
            if (stat.waiting_tids.size() < config_.minimum_waiting_threads ||
                stat.average_wait_ns() < config_.average_wait_threshold_ns ||
                stat.max_wait_ns < config_.max_wait_threshold_ns)
                continue; //continue：当前锁没有达到异常条件，就跳过它，继续检查下一个锁对象
            
            if (!primary || stat.total_wait_ns > primary->total_wait_ns) { //若当前窗口有多个锁对象，从中选择累计等待耗时最大的对象：
                primary = &stat;
                primary_pid = pid;
                primary_addr = address;
            }
        }
    }
    if (!primary) { //循环结束后，如果没有找到任何满足异常条件的锁对象，说明当前窗口没有发生锁竞争异常。
        recover(1);
        return;
    }

    /*  struct LockDiagnosis {
        LockDiagnosisState state = LockDiagnosisState::Normal;
        uint32_t pid = 0;
        uint64_t lock_addr = 0;
        LockStats evidence;
        uint64_t window_start_ns = 0;
        uint64_t window_end_ns = 0;
        std::size_t recovery_windows = 0;
        };*/
    diagnosis_.state = LockDiagnosisState::Contention;
    diagnosis_.pid = primary_pid;
    diagnosis_.lock_addr = primary_addr;
    diagnosis_.evidence = *primary;
    diagnosis_.window_start_ns = report_start_ns_;
    diagnosis_.window_end_ns = report_end_ns_;
    diagnosis_.recovery_windows = 0;
}

/*recover：当锁竞争异常消失，并且连续经过足够数量的正常或空窗口后，解除异常状态。
            默认连续 2 个正常或空窗口才会恢复正常。*/
void LockAnalyzer::recover(uint64_t windows)
{
    if (diagnosis_.state == LockDiagnosisState::Normal)
        return;
    const std::size_t remaining = config_.recovery_windows - diagnosis_.recovery_windows;
    if (windows >= remaining)
        diagnosis_ = {}; //经过的正常窗口数量已经达到要求，恢复
    else
        diagnosis_.recovery_windows += static_cast<std::size_t>(windows);
}

/*在程序停止采集时，把最后一个尚未结束的统计窗口也结算掉，避免丢失最后一部分锁等待数据。
  因此，在停止采集、排空 RingBuffer 中剩余事件之后，调用*/
bool LockAnalyzer::flush(uint64_t timestamp_ns)
{
    if (!initialized_ || timestamp_ns < latest_event_ns_ || timestamp_ns < current_start_ns_)
        return false; //	还没有初始化窗口，无数据需要结算||	传入的结算时间早于最新接收事件的时间||	结算时间早于当前窗口起点 都不执行结算
    const bool advanced = advance_window(timestamp_ns); //检查从当前窗口起点到 timestamp_ns 是否已经经过至少一个完整窗口。
    
    //第三部分：结算不足一秒的窗口。
    if (timestamp_ns > current_start_ns_ && (!window_stats_.empty() || !report_end_ns_)) { //当前窗口中有尚未结算的事件||还没有产生过任何窗口结算报告。
        finish_window(timestamp_ns);
        return true;
    }
    return advanced;
}

/*重新开始一次采集；保留配置，清空窗口、诊断和接收计数。*/
void LockAnalyzer::reset()
{
    window_stats_.clear();
    stats_.clear();
    diagnosis_ = {};
    initialized_ = false;
    current_start_ns_ = 0;
    latest_event_ns_ = 0;
    report_start_ns_ = 0;
    report_end_ns_ = 0;
    received_events_ = 0;
    rejected_events_ = 0;
    late_events_ = 0;
}
