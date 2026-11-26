#include "config_manager.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

// 测试断言：条件不满足时抛异常，不受 NDEBUG 编译选项影响。
void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

// 验证非法配置被拒绝，且错误消息包含 expected 指定的信息。
void rejects(const std::string& text, const std::string& expected)
{
    std::istringstream input(text); // 内存文本模拟输入文件，不需要创建临时文件。
    try {
        (void)kylinrca::ConfigManager::parse(input);
    } catch (const std::runtime_error& error) {
        require(std::string(error.what()).find(expected) != std::string::npos,
                "unexpected error: " + std::string(error.what()));
        return; //当非法错误被拒绝，并且错误信息包含预期原因时就返回
    }
    throw std::runtime_error("invalid config accepted: " + text);
}

} // 本文件测试辅助函数命名空间结束

// 覆盖默认值、合法输入、错误校验，以及解析失败时旧配置不被覆盖。
int main()
{
    using kylinrca::ConfigManager;
    using kylinrca::LogLevel;
    try {
        std::istringstream empty(""); //检验空配置是否保存默认值
        const auto defaults = ConfigManager::parse(empty);
        require(defaults.log_level == LogLevel::Info && defaults.window_ms == 1000 &&
                defaults.socket_path == "/run/kylinrca/kylinrca.sock" &&
                defaults.enable_syscall && defaults.enable_cpu &&
                defaults.enable_lock && defaults.enable_io, "bad defaults");

        // 同时覆盖注释、空行、首尾空白、CRLF，以及末行没有换行的情况。
        std::istringstream valid(
            "# comment\r\n\r\n log_level = debug \r\n"
            "socket_path=/tmp/kylinrca.sock\nwindow_ms=2000\n"
            "enable_syscall=false\nenable_cpu=false\nenable_lock=false\nenable_io=false");
        const auto config = ConfigManager::parse(valid);
        require(config.log_level == LogLevel::Debug && config.window_ms == 2000 &&
                config.socket_path == "/tmp/kylinrca.sock" &&
                !config.enable_syscall && !config.enable_cpu &&
                !config.enable_lock && !config.enable_io, "valid parse failed");

        for (const auto* level : {"debug", "info", "warn", "error"}) {
            std::istringstream input(std::string("log_level=") + level);
            (void)ConfigManager::parse(input);
        }
        for (const auto* window : {"1", "60000"}) {
            std::istringstream input(std::string("window_ms=") + window);
            (void)ConfigManager::parse(input);
        }
        // 越界、符号、小数、尾随字符和整数溢出都必须被拒绝。
        for (const auto* value : {"0", "60001", "-1", "+1", "1.5", "1000ms",
                                  "999999999999999999999999999999"}) {
            rejects(std::string("window_ms=") + value, "line 1");
        }
        rejects("log_level=INFO", "log_level"); //大写等级不符合本版语法
        rejects("log_level=info\nlog_level=debug", "line 2: duplicate key");//重复键应该在第二行报错。
        rejects("log_levle=debug", "unknown key");//拼错的键不能静默忽略
        rejects("enable_io=1", "true/false"); //检查严格布尔值
        rejects("enable_io=true # comment", "true/false"); //本版不支持行尾注释
        rejects("enable_io=", "must not be empty"); //空值
        rejects("=true", "must not be empty"); //空键
        rejects("enable_io", "expected key=value"); //缺少等号
        rejects("socket_path=relative.sock", "absolute"); //Socket 路径必须是绝对路径
        rejects("socket_path=/" + std::string(107, 'a'), "sun_path");
        rejects(std::string("socket_path=/tmp/a\0b", 20), "NUL"); // 显式长度保留内嵌空字节。
        rejects("[daemon]\nlog_level=info", "expected key=value");

        // 公共配置不接收模块专用参数，防止 CPU、Lock、I/O 的规则再次平铺到 AppConfig。
        for (const auto* key : {"io_threshold_us", "io_min_samples", "io_device",
                                "high_usage_threshold_percent", "minimum_wait_us", "recovery_windows"})
            rejects(std::string(key) + "=1", "unknown key");

        // 模拟底层读取故障；logic_error 不会被预期的 runtime_error 分支吞掉。
        std::istringstream broken("");
        broken.setstate(std::ios::badbit);
        try {
            (void)ConfigManager::parse(broken);
            throw std::logic_error("bad stream accepted");
        } catch (const std::runtime_error&) {
            // 预期的读取错误。
        }

        kylinrca::AppConfig active{}; // 模拟调用方正在使用的旧配置。
        active.window_ms = 500;
        std::istringstream partial("window_ms=2000\nenable_io=invalid");
        try {
            // 第二行失败后函数无法返回，赋值不发生，旧窗口必须保持为 500。
            active = ConfigManager::parse(partial);
            throw std::logic_error("partial config accepted");
        } catch (const std::runtime_error&) {
            require(active.window_ms == 500, "active config changed after failure");
        }
        std::cout << "config_manager tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
