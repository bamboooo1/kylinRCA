#include "config_manager.h"
#include "logger.h"

#include <exception>
#include <iostream>
#include <string_view>

// 独立验证配置读取与日志等级联动；不启动 daemon，也不创建 Socket。
int main(int argc, char** argv)
{
    // argc 包含程序名；本演示最多接受一个配置文件参数。
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        std::cout << "Usage: kylinrca_config_demo [config-file]\n"
                  << "No file: use defaults. Explicit file: require it to load.\n";
        return 0;
    }
    if (argc > 2) {
        std::cerr << "Usage: kylinrca_config_demo [config-file]\n";
        return 2;
    }

    kylinrca::Logger logger;
    try {
        kylinrca::AppConfig config{};
        if (argc == 2) {
            // 右侧完整解析成功后才赋值；没传文件时保留默认配置。
            config = kylinrca::ConfigManager::load(argv[1]);
        }
        logger.set_level(config.log_level);
        logger.log(kylinrca::LogLevel::Debug, "config", "debug enabled");
        logger.log(kylinrca::LogLevel::Info, "config", "configuration loaded");

        // stdout 展示解析结果，运行日志走 stderr；boolalpha 将布尔值显示为 true/false。
        std::cout << std::boolalpha
                  << "socket_path=" << config.socket_path << '\n'
                  << "window_ms=" << config.window_ms << '\n'
                  << "enable_syscall=" << config.enable_syscall << '\n'
                  << "enable_cpu=" << config.enable_cpu << '\n'
                  << "enable_lock=" << config.enable_lock << '\n'
                  << "enable_io=" << config.enable_io << '\n';
        return 0;
    } catch (const std::exception& error) {
        // 配置解析失败时未应用候选等级，默认 Logger 仍能输出错误；非零退出码供脚本判断。
        logger.log(kylinrca::LogLevel::Error, "config", error.what());
        return 1;
    }
}
