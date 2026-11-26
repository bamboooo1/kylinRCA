#ifndef KYLINRCA_RING_BUFFER_CONSUMER_H
#define KYLINRCA_RING_BUFFER_CONSUMER_H

#include "event_queue.h"

#include <bpf/libbpf.h>
#include <memory>

class RingBufferConsumer {
public:
    // 保存公共队列引用；收到原始事件后将其复制到该队列，供分析线程处理。
    explicit RingBufferConsumer(EventQueue& queue) : queue_(queue) {}

    // 找到一个已加载 BPF 对象的 events 表，将其加入统一接收器；失败时返回 false。
    bool add(bpf_object* object);
    // 主线程等待并消费可读事件，等待上限为给定毫秒数；返回 libbpf 处理结果或负错误码。
    int poll(int timeout_ms);
    // 不额外等待，消费当前可读事件；在定时消息入队前及停止探针后调用。
    void drain();

private:
    // 由 libbpf 在接收线程中调用，将原始记录交给公共队列检查并复制。
    static int handle_event(void* context, void* data, size_t size);

    EventQueue& queue_;
    std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring_{nullptr, ring_buffer__free};
};

#endif
