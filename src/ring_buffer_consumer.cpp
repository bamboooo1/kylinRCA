#include "ring_buffer_consumer.h"

/*把某个 BPF 探针的 events 缓冲区登记到 RingBufferConsumer，
以后主线程就能通过它读取这个探针发来的事件。*/
bool RingBufferConsumer::add(bpf_object* object)
{
    const int fd = bpf_object__find_map_fd_by_name(object, "events");
    if (fd < 0)
        return false;

    if (ring_) //如果已经有接收器，就把这个缓冲区加进去。
        return ring_buffer__add(ring_.get(), fd, handle_event, &queue_) == 0;
    ring_.reset(ring_buffer__new(fd, handle_event, &queue_, nullptr));
    return bool(ring_);
}

// 主线程持续调用：等待事件并触发接收回调，回调只负责把记录交给公共队列。
int RingBufferConsumer::poll(int timeout_ms)
{
    return ring_buffer__poll(ring_.get(), timeout_ms);
}

// 主动消费已经可读的事件，使窗口推进或退出前尽量先处理已有记录；本函数不等待新事件。
void RingBufferConsumer::drain()
{
    // 回调即使拒收格式不合法的事件也返回零，避免单条坏记录中断整次接收。
    ring_buffer__consume(ring_.get());
}

// 将回调上下文还原为队列，把当前数据交给其校验和复制；返回零让接收过程继续。
int RingBufferConsumer::handle_event(void* context, void* data, size_t size)
{
    static_cast<EventQueue*>(context)->push_record(data, size);
    return 0;
}
