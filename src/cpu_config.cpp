#include "cpu_config.h"
#include "module_config_reader.h"

// 打开 CPU 模块文件并调用本模块解析器；复用公共读取工具，不改变 daemon 公共配置。
CpuConfig CpuConfig::load(const std::string& path)
{
    return module_config::load<CpuConfig>(path);
}

// 把外部参数转换成现有 CpuAnalyzerConfig，严格检查范围和迟滞关系后一次性返回。
// 外部连续次数为零或恢复阈值不合理时直接失败，不依赖分析器旧有的自动修正行为。
CpuConfig CpuConfig::parse(std::istream& input)
{
    CpuConfig config;
    for (const auto& field : module_config::read(input)) {
        const auto& key = field.key;
        if (key == "high_usage_threshold_percent")
            config.analyzer.high_usage_threshold_percent = module_config::percent(field.value, field.line);
        else if (key == "recovery_threshold_percent")
            config.analyzer.recovery_threshold_percent = module_config::percent(field.value, field.line);
        else if (key == "runqueue_delay_threshold_us")
            config.analyzer.runqueue_delay_threshold_ns =
                uint64_t{module_config::integer(field.value, false, field.line)} * 1000;
        else if (key == "alert_consecutive_samples")
            config.analyzer.alert_consecutive_samples = module_config::integer(field.value, false, field.line);
        else if (key == "recovery_consecutive_samples")
            config.analyzer.recovery_consecutive_samples = module_config::integer(field.value, false, field.line);
        else
            module_config::fail(field.line, "unknown CPU key: " + key);
    }
    if (config.analyzer.recovery_threshold_percent >= config.analyzer.high_usage_threshold_percent)
        throw std::runtime_error("recovery_threshold_percent must be lower than high_usage_threshold_percent");
    return config;
}
