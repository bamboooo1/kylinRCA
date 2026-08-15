#ifndef KYLINRCA_EVENT_QUEUE_H
#define KYLINRCA_EVENT_QUEUE_H

#include "event.h"

#include <condition_variable>
#include <mutex>
#include <queue>

class EventQueue {
public:
    void push(const syscall_event& event); // 声明一个名为 push 的成员函数，向队列放入一个事件。const：函数只读取传入的事件，不修改它
    syscall_event pop(); // 声明一个名为 pop 的成员函数，从队列取出一个事件并返回。返回的是一个 syscall_event 对象

private:
    std::queue<syscall_event> queue_;  //真正存事件的 FIFO 队列。std::queue：C++ 标准库的队列；<syscall_event>：队列中每一项都是 syscall_event；
    std::mutex mutex_;  //互斥锁，防止两个线程同时乱改队列queue_。例如一个线程正在 push()，另一个线程同时 pop()；没有锁时可能出现数据错乱。谁先获得 mutex_，谁才能暂时操作队列。
    std::condition_variable condition_;  // 条件变量，用于让analyzer等待consumer push新事件的条件满足再工作。让consumer无事件时可以“睡觉等待”,而不是疯狂循环检查
};

#endif