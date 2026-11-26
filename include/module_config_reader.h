#ifndef KYLINRCA_MODULE_CONFIG_READER_H
#define KYLINRCA_MODULE_CONFIG_READER_H
#include <charconv>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <istream>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <utility>

// 三类模块共用文本格式和数字校验；模块字段与诊断规则仍由各自解析器管理。
namespace module_config {
struct Field {
    std::string key, value;
    std::size_t line;
};
// 给字段错误附加行号，显式配置错误时中止启动，不静默采用默认值。
[[noreturn]] inline void fail(std::size_t line, const std::string& message)
{
    throw std::runtime_error("line " + std::to_string(line) + ": " + message);
}
// 去掉配置行或字段两端空白，字段内部保持原样交给类型校验。
inline std::string trim(std::string_view text)
{
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return std::string(text.substr(first, last - first + 1));
}
// 从输入流读取键值和行号，统一拒绝重复项、空值、空字节及读取故障；返回值拥有独立文本。
inline std::vector<Field> read(std::istream& input)
{
    std::vector<Field> fields;
    std::set<std::string> seen;
    std::string raw;
    std::size_t line = 0;
    while (std::getline(input, raw)) {
        ++line;
        const auto text = trim(raw);
        if (text.empty() || text.front() == '#') continue;
        if (text.find('\0') != std::string::npos) fail(line, "NUL byte is not allowed");
        const auto separator = text.find('=');
        if (separator == std::string::npos) fail(line, "expected key=value");
        auto key = trim(std::string_view(text).substr(0, separator));
        auto value = trim(std::string_view(text).substr(separator + 1));
        if (key.empty() || value.empty()) fail(line, "key and value must not be empty");
        if (!seen.insert(key).second) fail(line, "duplicate key: " + key);
        fields.push_back({std::move(key), std::move(value), line});
    }
    if (input.bad() || (input.fail() && !input.eof()))
        throw std::runtime_error("module config stream read failed");
    return fields;
}
// 整个字段必须是 uint32 十进制整数；设备号允许零，阈值和连续次数要求正数。
inline uint32_t integer(std::string_view text, bool allow_zero, std::size_t line)
{
    uint32_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        (!allow_zero && !value))
        fail(line, "expected " + std::string(allow_zero ? "uint32" : "positive uint32") + " integer");
    return value;
}
// 解析 0..100 的有限百分比，可含小数；拒绝符号、指数、单位后缀和非数值。
inline double percent(std::string_view text, std::size_t line)
{
    double value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value,
                                        std::chars_format::fixed);
    if (text.empty() || text.find_first_not_of("0123456789.") != std::string_view::npos ||
        parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
        !std::isfinite(value) || value < 0 || value > 100)
        fail(line, "expected finite decimal percent in [0, 100]");
    return value;
}
// 各模块的 load 入口共用文件打开和错误路径包装，再调用对应模块自己的 parse。
template<typename Config>
Config load(const std::string& path)
{
    std::ifstream input(path);
    if (!input.is_open()) throw std::runtime_error("cannot open module config file: " + path);
    try {
        return Config::parse(input);
    } catch (const std::runtime_error& error) {
        throw std::runtime_error(path + ": " + error.what());
    }
}
} // 模块配置基础读取函数结束
#endif
