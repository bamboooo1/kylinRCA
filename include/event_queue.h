#ifndef KYLINRCA_EVENT_QUEUE_H
#define KYLINRCA_EVENT_QUEUE_H

#include "cpu_analyzer.h"
#include "event.h"

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <optional>
#include <queue>
#include <variant>

struct AnalysisTick {
    uint64_t timestamp_ns;
    std::optional<CpuUsageObservation> cpu; //CpuUsageObservation 是这份数据的类型，里面有系统 CPU 使用率、各进程和线程的使用情况等。
};

using QueuedEvent = std::variant<syscall_event, cpu_event, kylinrca_lock_event, AnalysisTick>;

class EventQueue {
public:
    // The queue owns a copy of each record after the ring buffer callback returns.
    bool push_record(const void* data, std::size_t size);
    void push(QueuedEvent event);
    std::optional<QueuedEvent> try_pop();
    std::optional<QueuedEvent> wait_pop();
    // The producer closes after its final push. The worker drains before exiting.
    void close();

private:
    std::optional<QueuedEvent> pop_front();

    std::queue<QueuedEvent> queue_;
    std::mutex mutex_;
    std::condition_variable condition_;
    bool closed_ = false;
};

#endif
