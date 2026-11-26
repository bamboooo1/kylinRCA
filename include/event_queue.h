#ifndef KYLINRCA_EVENT_QUEUE_H
#define KYLINRCA_EVENT_QUEUE_H

#include "cpu_analyzer.h"
#include "event.h"
#include "io_probe_reader.h"

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <queue>
#include <variant>

// 主线程生成的定时消息：携带截止时间和可选采样，通知分析线程推进窗口；不属于内核事件。
struct AnalysisTick {
    uint64_t timestamp_ns;
    std::optional<CpuUsageObservation> cpu; //CpuUsageObservation 是这份数据的类型，里面有系统 CPU 使用率、各进程和线程的使用情况等。
    std::optional<IoProbeHealth> io; // 最近读取的 I/O 内核健康计数，关闭模块时为空。
    bool final = false; // 退出前的最后一条定时消息，要求 I/O 结算不足整窗的尾部数据。
};

//一条队列消息在某一时刻保存其中一种类型，并记录自己当前属于哪种类型。
using QueuedEvent = std::variant<syscall_event, cpu_event, kylinrca_lock_event, kylinrca_io_event, AnalysisTick>;

class EventQueue {
public:
    // 接收内核原始记录，校验版本、类型和精确长度，再复制入队；回调返回后队列仍拥有独立数据。
    bool push_record(const void* data, std::size_t size);
    // 主线程把事件副本或定时消息放到队尾，并唤醒等待中的分析线程。
    void push(QueuedEvent event);
    // 立即尝试取出队首消息；没有消息就返回空，不等待。
    std::optional<QueuedEvent> try_pop();
    // 分析线程等待并取出队首消息；只有队列关闭且已排空时才返回空并结束处理循环。
    std::optional<QueuedEvent> wait_pop();
    // 主线程投递完所有尾部消息后关闭队列并唤醒分析线程；保留已入队消息，供其处理完再退出。
    void close();

private:
    // 在调用方已持有队列锁时移出队首消息；本函数自身不加锁、不等待。
    std::optional<QueuedEvent> pop_front();

    std::queue<QueuedEvent> queue_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool closed_ = false;
};

#endif
