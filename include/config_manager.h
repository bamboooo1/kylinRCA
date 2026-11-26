#ifndef KYLINRCA_CONFIG_MANAGER_H
#define KYLINRCA_CONFIG_MANAGER_H

#include "logger.h"

#include <cstdint>
#include <istream>
#include <string>

namespace kylinrca {

// 值类型：每次解析先建立候选配置，成功后一次性返回。
struct AppConfig {
    LogLevel log_level = LogLevel::Info;
    std::string socket_path = "/run/kylinrca/kylinrca.sock"; //设定本机 CLI 和 daemon 通信时使用的 Socket 路径。
    std::uint32_t window_ms = 1000; //默认每隔约 1 秒采样一次 CPU，Lock 也按 1 秒划分统计窗口。
    bool enable_syscall = true;
    bool enable_cpu = true;
    bool enable_lock = true;
    bool enable_io = true;

};

class ConfigManager {
public:
    // load()：负责打开文件，调用解析函数。
    // 显式指定的文件打不开时抛出异常，不静默退回默认配置。
    static AppConfig load(const std::string& path);

    // parse()：负责读取内容、检查并生成配置。
    // 接受文件流或字符串流，便于独立验证。
    static AppConfig parse(std::istream& input);
};

} // kylinrca 命名空间结束

#endif
