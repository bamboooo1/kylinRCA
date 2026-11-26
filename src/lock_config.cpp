#include "lock_config.h"
#include "module_config_reader.h"

// 打开 Lock 模块文件并保留错误路径；文件解析成功后才返回完整规则。
LockConfig LockConfig::load(const std::string& path)
{
    return module_config::load<LockConfig>(path);
}

// 将微秒阈值转换为分析器使用的纳秒，核对等待阈值顺序、线程数和恢复次数。
// 不接收 window_ms；daemon 与 I/O 一样从公共配置传入实际窗口长度。
LockConfig LockConfig::parse(std::istream& input)
{
    LockConfig config;
    for (const auto& field : module_config::read(input)) {
        const auto& key = field.key;
        if (key == "minimum_wait_us")
            config.analyzer.minimum_wait_ns = uint64_t{module_config::integer(field.value, false, field.line)} * 1000;
        else if (key == "average_wait_threshold_us")
            config.analyzer.average_wait_threshold_ns = uint64_t{module_config::integer(field.value, false, field.line)} * 1000;
        else if (key == "max_wait_threshold_us")
            config.analyzer.max_wait_threshold_ns = uint64_t{module_config::integer(field.value, false, field.line)} * 1000;
        else if (key == "minimum_waiting_threads") {
            const auto value = module_config::integer(field.value, false, field.line);
            if (value < 2) module_config::fail(field.line, "minimum_waiting_threads must be at least 2");
            config.analyzer.minimum_waiting_threads = value;
        } else if (key == "recovery_windows")
            config.analyzer.recovery_windows = module_config::integer(field.value, false, field.line);
        else
            module_config::fail(field.line, "unknown Lock key: " + key);
    }
    if (config.analyzer.average_wait_threshold_ns < config.analyzer.minimum_wait_ns ||
        config.analyzer.max_wait_threshold_ns < config.analyzer.average_wait_threshold_ns)
        throw std::runtime_error("require minimum_wait_us <= average_wait_threshold_us <= max_wait_threshold_us");
    return config;
}
