#ifndef KYLINRCA_RING_BUFFER_CONSUMER_H
#define KYLINRCA_RING_BUFFER_CONSUMER_H

#include "event_queue.h" //因为后面使用了EventQueue& queue，编译器必须先知道 EventQueue 是什么类型。

#include <bpf/libbpf.h> //struct bpf_object，struct ring_buffer

class RingBufferConsumer{ 
public: //表示下面的成员可以在类外部调用
    explicit RingBufferConsumer(EventQueue& queue); //"构造函数“的名字必须与类一摸一样。explicit：禁止编译器把一个 EventQueue 自动转换成 RingBufferConsumer。
    ~RingBufferConsumer(); //~ 表示析构函数。当对象生命周期结束时，它会被自动调用：

    bool init(struct bpf_object* obj); //成员函数 init() 的声明。函数返回布尔值：true/false。参数 obj 是一个指针，指向已经由 libbpf 打开的 BPF 对象。
    int poll(int timeout_ms);

private: // 表示下面的成员只能由 RingBufferConsumer 自己的函数访问。
    static int handle_event(void* ctx, void* data, size_t size); // static表示这是静态成员函数，声明回调函数

    EventQueue& queue_;
    struct ring_buffer* ring_buffer_ = nullptr; // 表示它是一个指针，指向 libbpf 管理的 ring_buffer 对象。初始化为空指针。
};

#endif