#include "io_config.h"
#include "module_config_reader.h"

// 打开 I/O 文件并调用本模块解析器；三个模块共用文本格式与文件错误处理。
IoConfig IoConfig::load(const std::string& path)
{
    return module_config::load<IoConfig>(path);
}

// 只识别 I/O 设备条件和分析规则，复用基础校验；省略字段仍保留产品默认值。
IoConfig IoConfig::parse(std::istream& input)
{
    IoConfig config;
    for (const auto& field : module_config::read(input)) {
        const auto& key = field.key;
        if (key == "latency_threshold_us")
            config.analyzer.latency_threshold_ns = uint64_t{module_config::integer(field.value, false, field.line)} * 1000;
        else if (key == "min_samples")
            config.analyzer.min_samples = module_config::integer(field.value, false, field.line);
        else if (key == "device") {
            const auto colon = field.value.find(':');
            if (colon == std::string::npos) module_config::fail(field.line, "device must be MAJOR:MINOR");
            module_config::integer(std::string_view(field.value).substr(0, colon), true, field.line);
            module_config::integer(std::string_view(field.value).substr(colon + 1), true, field.line);
            config.device = field.value;
        } else
            module_config::fail(field.line, "unknown I/O key: " + key);
    }
    return config;
}
