#include "event_queue.h"

//属于EventQueue的push函数，&表示”引用“，类似c的*指针，传地址
void EventQueue::push(const syscall_event& event){
    { //RAII
        std::lock_guard<std::mutex> lock(mutex_); //定义一个”锁管家“对象”lock“，将锁”mutex_"交给管家lock，他负责上锁和解锁
        queue_.push(event); //把event塞入队列的末尾
    }// 局部作用域结束，IIlock被销毁，触发RAII，自动解锁mutex_
    condition_.notify_one(); //唤醒正在睡觉的线程
}

syscall_event EventQueue::pop(){
    std::unique_lock<std::mutex> lock(mutex_); //定义一个”特殊的锁管家“对象”lock“，可以临时解锁再重新上锁
    condition_.wait(lock, [this]{return !queue_.empty();}); // .wait(,)会在队列为空时暂时释放 lock 并等待；被 notify_one() 唤醒后重新获得锁，再检查队列是否非空。只有条件成立才继续执行。。[this]{...}是C++的匿名函数，理解成一个临时小函数
    syscall_event event = queue_.front(); //将queue最前面的元素赋值给event
    queue_.pop(); //删除最前面的元素
    return event;
}