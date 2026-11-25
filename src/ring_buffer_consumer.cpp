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

int RingBufferConsumer::poll(int timeout_ms)
{
    return ring_buffer__poll(ring_.get(), timeout_ms);
}

void RingBufferConsumer::drain()
{
    // The callback returns zero even when a record is rejected.
    ring_buffer__consume(ring_.get());
}

int RingBufferConsumer::handle_event(void* context, void* data, size_t size)
{
    static_cast<EventQueue*>(context)->push_record(data, size);
    return 0;
}
