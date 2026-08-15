#include "ring_buffer_consumer.h"

#include <cerrno>
#include <iostream>

// 这是一个构造函数用于创建对象，创建对象时必须接受外部传递的queue并绑定到自己的成员变量上
RingBufferConsumer:: RingBufferConsumer(EventQueue& queue)
    :queue_(queue){} // RingBufferConsumer不是自己凭空造队列，而是绑定了外部已经存在的队列

RingBufferConsumer:: ~RingBufferConsumer(){
    if(ring_buffer_ != nullptr){
        ring_buffer__free(ring_buffer_);
    }
}

bool RingBufferConsumer::init(struct bpf_object* obj){
// 初始化Ring Buffer 消费者对象ring_buffer_，
// eBPF 程序          = 厨师，把寿司放上传送带
// Ring Buffer map    = 回转寿司传送带
// 事件               = 一盘盘寿司
// ring_buffer_       = 负责盯着传送带取寿司的工作人员
// handle_event()     = 取到寿司后执行的处理动作
// EventQueue         = 把寿司暂存起来的餐盒

    struct bpf_map* events_map = bpf_object__find_map_by_name(obj, "events");
    if (events_map == nullptr) {
        std::cerr << "Failed to find BPF map: events" << std::endl;
        return false;
    }

    int map_fd = bpf_map__fd(events_map);
    if (map_fd < 0) {
        std::cerr << "Failed to get events map fd" << std::endl;
        return false;
    }

    ring_buffer_ = ring_buffer__new(map_fd, handle_event, this, nullptr); //this 会在回调时变成 ctx。回调中再转换回来RingBufferConsumer
    if (ring_buffer_ == nullptr) {
        std::cerr << "Failed to create ring buffer consumer" << std::endl;
        return false;
    }// 由 ring_buffer__new(map_fd, ...) 创建的用户态消费者，负责监听这块内核 Ring Buffer，并在事件到达时调用回调函数。

    return true;
}

int RingBufferConsumer::poll(int timeout_ms)
{
    if (ring_buffer_ == nullptr) {
        return -EINVAL; // EINVAL 是系统定义的错误码，意思是 Invalid argument
    }

    return ring_buffer__poll(ring_buffer_, timeout_ms); 
    // ring_buffer__poll()负责发现事件后，自动调用注册的回调函数handle_event处理事件，处理事件后，把 libbpf 返回的结果直接交给调用者。
    // timeout_ms：最多等待多少毫秒。
    // 返回值：正数：成功处理的事件数量；0：等待超时，没有收到事件；负数：发生错误。
}

int RingBufferConsumer::handle_event(void* ctx, void* data, size_t size)
// void* ctx：用户自定义的上下文指针，用来找到当前的 RingBufferConsumer 对象。
// void* data：指向本次 Ring Buffer 事件数据的地址，void*表示 libbpf 不知道里面具体是什么类型。
// size_t size: 表示 data 指向的事件占多少字节。
{
    auto* consumer = static_cast<RingBufferConsumer*>(ctx); //ctx转换回指向RingBufferConsumer的指针

    if (size != sizeof(syscall_event)) {
        std::cerr << "Unexpected syscall event size: " << size << std::endl;
        return 0;
    }

    const auto* event = static_cast<const syscall_event*>(data); // 根据项目约定，需要把data转换成 syscall_event

    if (event->header.version != KYLINRCA_EVENT_VERSION) {
        std::cerr << "Unsupported event version" << std::endl;
        return 0;
    }

    if (event->header.type != EVENT_TYPE_SYSCALL) {
        std::cerr << "Unexpected event type" << std::endl;
        return 0;
    }

    if (event->header.size != sizeof(syscall_event)) {
        std::cerr << "Invalid event header size" << std::endl;
        return 0;
    }

    consumer->queue_.push(*event);

    return 0;
}