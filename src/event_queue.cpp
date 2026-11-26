#include "event_queue.h"

#include <cstring>
#include <utility>

namespace {

// 按已识别的事件类型检查完整长度，复制原始字节并入队，避免分析线程引用已被复用的内核缓冲区。
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

} // 本文件辅助函数命名空间结束

// 公共事件入口：拒绝空地址、残缺头部、错误版本、未知类型和长度不符的记录，合法记录按类型复制。
bool EventQueue::push_record(const void* data, std::size_t size)
{
    if (!data || size < sizeof(kylinrca_event_header))
        return false;

    kylinrca_event_header header;
    std::memcpy(&header, data, sizeof(header));
    if (header.version != KYLINRCA_EVENT_VERSION || header.size != size)
        return false;

    switch (header.type) {
    case EVENT_TYPE_SYSCALL: return copy_record<syscall_event>(*this, data, size);
    case EVENT_TYPE_CPU: return copy_record<cpu_event>(*this, data, size);
    case EVENT_TYPE_LOCK: return copy_record<kylinrca_lock_event>(*this, data, size);
    case EVENT_TYPE_IO: return copy_record<kylinrca_io_event>(*this, data, size);
    default: return false;
    }
}

// 在锁内把消息放到队尾，解锁后通知分析线程；事件和定时消息通过同一个队列保持入队顺序。
void EventQueue::push(QueuedEvent event)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(std::move(event));
    }
    condition_.notify_one();
}

// 由已持锁的取出函数调用：移走最早入队的消息；没有消息时返回空。
std::optional<QueuedEvent> EventQueue::pop_front()
{
    if (queue_.empty())
        return std::nullopt;
    QueuedEvent event = std::move(queue_.front());
    queue_.pop();
    return event;
}

// 非阻塞取出入口：获取锁后尝试取一条，适合测试或不需要等待的调用方。
std::optional<QueuedEvent> EventQueue::try_pop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return pop_front();
}

// 分析线程的阻塞入口：等待时释放队列锁，唤醒后检查“已有消息或已经关闭”，再尝试取出。
std::optional<QueuedEvent> EventQueue::wait_pop()
{
    std::unique_lock<std::mutex> lock(mutex_);
    condition_.wait(lock, [this] { return closed_ || !queue_.empty(); });
    return pop_front();
}

// 生产方完成最后一次入队后调用：标记关闭并通知等待者，不清空仍待分析的消息。
void EventQueue::close()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
    }
    condition_.notify_one();
}
