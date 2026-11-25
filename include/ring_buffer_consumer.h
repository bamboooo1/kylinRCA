#ifndef KYLINRCA_RING_BUFFER_CONSUMER_H
#define KYLINRCA_RING_BUFFER_CONSUMER_H

#include "event_queue.h"

#include <bpf/libbpf.h>
#include <memory>

class RingBufferConsumer {
public:
    explicit RingBufferConsumer(EventQueue& queue) : queue_(queue) {}

    bool add(bpf_object* object);
    int poll(int timeout_ms);
    void drain();

private:
    static int handle_event(void* context, void* data, size_t size);

    EventQueue& queue_;
    std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring_{nullptr, ring_buffer__free};
};

#endif
