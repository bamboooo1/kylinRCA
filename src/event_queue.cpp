#include "event_queue.h"

#include <cstring>
#include <utility>

namespace {

template<typename T>
bool copy_record(EventQueue& queue, const void* data, std::size_t size)
{
    if (size != sizeof(T))
        return false;

    T event;
    std::memcpy(&event, data, sizeof(event));
    queue.push(event);
    return true;
}

} // namespace

bool EventQueue::push_record(const void* data, std::size_t size)
{
    if (size < sizeof(kylinrca_event_header))
        return false;

    kylinrca_event_header header;
    std::memcpy(&header, data, sizeof(header));
    if (header.version != KYLINRCA_EVENT_VERSION || header.size != size)
        return false;

    switch (header.type) {
    case EVENT_TYPE_SYSCALL: return copy_record<syscall_event>(*this, data, size);
    case EVENT_TYPE_CPU: return copy_record<cpu_event>(*this, data, size);
    case EVENT_TYPE_LOCK: return copy_record<kylinrca_lock_event>(*this, data, size);
    default: return false;
    }
}

void EventQueue::push(QueuedEvent event)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(event));
    }
    condition_.notify_one();
}

std::optional<QueuedEvent> EventQueue::pop_front()
{
    if (queue_.empty())
        return std::nullopt;
    QueuedEvent event = std::move(queue_.front());
    queue_.pop();
    return event;
}

std::optional<QueuedEvent> EventQueue::try_pop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return pop_front();
}

std::optional<QueuedEvent> EventQueue::wait_pop()
{
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this] { return closed_ || !queue_.empty(); });
    return pop_front();
}

void EventQueue::close()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
    }
    condition_.notify_one();
}
