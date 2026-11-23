#include "logger.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>

namespace kylinrca {

namespace {

const char* level_name(LogLevel level)
{
    switch (level) {
    case LogLevel::Debug:
        return "DEBUG";
    case LogLevel::Info:
        return "INFO";
    case LogLevel::Warn:
        return "WARN";
    case LogLevel::Error:
        return "ERROR";
    }

    return "UNKNOWN";
}

} // namespace

Logger::Logger(LogLevel minimum)
    : minimum_(minimum)
{
}

/*
 *1.调用 mutex_.lock() 给互斥量加锁。
 *2.在 lock 对象离开其所在的作用域（即遇到 } 或函数结束/抛出异常）时，自动调用它的析构函数，从而调用 mutex_.unlock() 解锁。
 */
void Logger::set_level(LogLevel minimum)
{
    std::lock_guard<std::mutex> lock(mutex_);
    minimum_ = minimum;
}

void Logger::log(LogLevel level,
                 std::string_view module,
                 std::string_view message)
{
    std::lock_guard<std::mutex> lock(mutex_); //获取互斥锁

    if (level < minimum_) { //检查日志级别
        return;
    }

    //记录事件发生的事件
    const auto now = std::chrono::system_clock::now();
    const std::time_t seconds =
        std::chrono::system_clock::to_time_t(now);

    std::tm local_time{};

    //转换为本地年月日、时分秒
    //普通 localtime() 使用共享静态存储；
    //`localtime_r()` 使用调用者提供的结果存储，更适合多线程程序。
    if (::localtime_r(&seconds, &local_time) != nullptr)
    {
        std::cerr
            << std::put_time(&local_time, "%Y-%m-%dT%H:%M:%S%z");
    } else {
        std::cerr << "time-unavailable";
    }

    std::cerr << " [" << level_name(level) << "]"
              << " [" << module << "] ";

    // 将消息中的换行转成文本，保持一条日志占一行。
    for (char ch : message) {
        if (ch == '\n') {
            std::cerr << "\\n";
        } else if (ch == '\r') {
            std::cerr << "\\r";
        } else {
            std::cerr << ch;
        }
    }

    std::cerr << '\n';
    std::cerr.flush();
}

} // namespace kylinrca
