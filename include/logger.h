#ifndef KYLINRCA_LOGGER_H
#define KYLINRCA_LOGGER_H

#include <mutex>
#include <string_view>

namespace kylinrca {

enum class LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3
};

class Logger {
public:
    explicit Logger(LogLevel minimum = LogLevel::Info);

    void set_level(LogLevel minimum);

    void log(LogLevel level,
             std::string_view module,
             std::string_view message);

private:
    LogLevel minimum_;
    std::mutex mutex_;
};

} // namespace kylinrca

#endif
