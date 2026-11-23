#include "logger.h"

#include <iostream>
#include <string>
#include <thread>

int main()
{
    using kylinrca::Logger;
    using kylinrca::LogLevel;

    Logger logger(LogLevel::Info); // 初始最低级别设为 Info

    logger.log(LogLevel::Debug, "demo", "hidden-debug");
    logger.log(LogLevel::Info, "demo", "visible-info");
    logger.log(LogLevel::Warn, "demo", "visible-warn");

    logger.set_level(LogLevel::Debug); // 动态降低级别门槛为 Debug
    logger.log(LogLevel::Debug, "demo", "visible-debug");

    /*多线程并发与线程安全测试*/
    //定义了一个 Lambda 表达式 worker，它接收一个 id，然后循环 100 次打印日志。日志内容类似 id=1 seq=0、id=1 seq=1。
    auto worker = [&logger](int id) {
        for (int i = 0; i < 100; ++i) {
            logger.log(
                LogLevel::Info,
                "worker",
                "id=" + std::to_string(id)
                    + " seq=" + std::to_string(i));
        }
    };

    //创建了两个线程 first 和 second，分别传入 id=1 和 id=2 并发执行这个 Lambda
    std::thread first(worker, 1);
    std::thread second(worker, 2);

    //join() 阻塞主线程，直到两个子线程都执行完毕
    first.join();
    second.join();

    logger.log(LogLevel::Error, "demo", "first\nsecond");

    std::cout << "{\"type\":\"logger_demo\",\"ok\":true}\n";
}


// 2023-10-27T10:00:00+0800 [INFO] [demo] visible-info
// 2023-10-27T10:00:00+0800 [WARN] [demo] visible-warn
// 2023-10-27T10:00:00+0800 [DEBUG] [demo] visible-debug
// 2023-10-27T10:00:00+0800 [INFO] [worker] id=1 seq=0
// 2023-10-27T10:00:00+0800 [INFO] [worker] id=2 seq=0
// 2023-10-27T10:00:00+0800 [INFO] [worker] id=2 seq=1
// 2023-10-27T10:00:00+0800 [INFO] [worker] id=1 seq=1
// ... (中间省略 196 行，注意 id=1 和 id=2 是交替出现的，但每一行都是完整没有交错的)
// 2023-10-27T10:00:00+0800 [INFO] [worker] id=1 seq=99
// 2023-10-27T10:00:00+0800 [INFO] [worker] id=2 seq=99
// 2023-10-27T10:00:00+0800 [ERROR] [demo] first\nsecond
// {"type":"logger_demo","ok":true}