#ifndef KYLINRCA_LOCK_ANALYZER_H
#define KYLINRCA_LOCK_ANALYZER_H

#include "event.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>

/*  针对同一个进程、同一个 futex 地址，统计：*/
struct LockStats {
    uint64_t event_count = 0; // 包括成功、短等待和失败返回。
    uint64_t wait_count = 0; // 达到最短等待时长的成功调用次数。
    uint64_t total_wait_ns = 0;
    uint64_t max_wait_ns = 0;
    uint64_t short_wait_count = 0;
    uint64_t eagain_count = 0; // 值不匹配，不能证明发生了阻塞。
    uint64_t timeout_count = 0;
    uint64_t interrupted_count = 0;
    uint64_t other_error_count = 0;
    std::set<uint32_t> waiting_tids; // 集合（Set），用来保存发生过锁等待的线程 ID（TID）。std::set：C++ 标准库中的集合容器，自动去重、自动排序，保证同一线程多次等待只计一个线程。

    uint64_t average_wait_ns() const
    {
        return wait_count ? total_wait_ns / wait_count : 0;
    }
};

/*默认每秒判断一次；同一地址需要多个线程和明显等待，才认为存在竞争。*/
struct LockAnalyzerConfig {
    uint64_t window_ns = 1'000'000'000;
    uint64_t minimum_wait_ns = 1'000'000;
    uint64_t average_wait_threshold_ns = 10'000'000;
    uint64_t max_wait_threshold_ns = 50'000'000;
    std::size_t minimum_waiting_threads = 2;
    std::size_t recovery_windows = 2; // 连续两个正常窗口后解除告警。
};

enum class LockDiagnosisState {
    Normal,
    Contention
};

/*主要竞争对象及其证据；恢复观察期间保留触发窗口，避免把旧证据标成当前数据。*/
struct LockDiagnosis {
    LockDiagnosisState state = LockDiagnosisState::Normal;
    uint32_t pid = 0;
    uint64_t lock_addr = 0;
    LockStats evidence;
    uint64_t window_start_ns = 0;
    uint64_t window_end_ns = 0;
    std::size_t recovery_windows = 0;
};

/* LockProcessStats window_stats_;结构相当于
    window_stats_
    │
    ├── PID = 100
    │   ├── futex地址 = 0xAAA → LockStats A
    │   └── futex地址 = 0xBBB → LockStats B
    │
    └── PID = 200
        ├── futex地址 = 0xCCC → LockStats C
        └── futex地址 = 0xDDD → LockStats D
    所以一个 window_stats_ 就能够保存当前窗口内所有被观察到的锁对象。*/
using LockProcessStats = std::map<uint32_t, std::map<uint64_t, LockStats>>;

/*LockAnalyzer 是我们自己起的类名，表示“锁事件分析器”。*/
class LockAnalyzer { 
public:
    explicit LockAnalyzer(LockAnalyzerConfig config = {});//config = {} 表示没有传入参数时，使用 LockAnalyzerConfig 的默认配置。

    /*接收已完成的 futex 等待；拒绝无效事件和已经结算窗口的迟到事件。
        同一窗口内允许乱序；等待跨越窗口时，完整耗时计入其结束时间所在窗口。*/
    bool process(const kylinrca_lock_event& event);

    /*调用方使用 CLOCK_MONOTONIC 定期推进窗口；无事件时也必须调用，才能恢复。*/
    bool advance_window(uint64_t timestamp_ns);

    /*停止采集并排空 RingBuffer 后，结算最后一个不足整秒的窗口。*/
    bool flush(uint64_t timestamp_ns);

    /*C++ 中的成员函数定义，作用是让外部代码能够读取 LockAnalyzer 内部的数据，但不能通过这些函数修改数据。*/
    const LockProcessStats& stats() const { return stats_; }
    const LockDiagnosis& diagnosis() const { return diagnosis_; }
    const LockAnalyzerConfig& config() const { return config_; }
    uint64_t window_start_ns() const { return report_start_ns_; }
    uint64_t window_end_ns() const { return report_end_ns_; }
    // 首次初始化后返回当前收集窗口的右边界；恰好在边界结束的等待属于下一窗。
    uint64_t next_window_end_ns() const { return current_start_ns_ + config_.window_ns; }
    uint64_t received_events() const { return received_events_; }
    uint64_t rejected_events() const { return rejected_events_; }
    uint64_t late_events() const { return late_events_; }

    void reset(); //头文件中这些带分号的函数声明告诉编译器：这个类有哪些函数、接收什么参数、返回什么类型。具体怎么执行，写在 .cpp 文件里。

private:
    void finish_window(uint64_t end_ns);
    void recover(uint64_t windows);

    LockAnalyzerConfig config_;
    LockProcessStats window_stats_; // 当前正在收集的窗口数据。
    LockProcessStats stats_; // 最近一次已经结算的窗口数据。
    LockDiagnosis diagnosis_; //当前的锁竞争诊断结果。
    bool initialized_ = false;
    uint64_t current_start_ns_ = 0;
    uint64_t latest_event_ns_ = 0;
    uint64_t report_start_ns_ = 0; //最近一次对外报告的统计窗口的起止时间，既可以是有事件的窗口，也可以是空窗口。
    uint64_t report_end_ns_ = 0;
    uint64_t received_events_ = 0;
    uint64_t rejected_events_ = 0;
    uint64_t late_events_ = 0;
};

#endif
