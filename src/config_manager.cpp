#include "config_manager.h"

#include <charconv>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <sys/un.h>

namespace kylinrca {
namespace {

// 去掉首尾空白；返回拥有独立内存的字符串，避免依赖传入视图的生命周期。
std::string trim(std::string_view value)
{
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return std::string(value.substr(first, last - first + 1));
}

// 抛出带配置行号的错误；[[noreturn]] 表示函数不会正常返回。
[[noreturn]] void fail(std::size_t line, const std::string& message)
{
    throw std::runtime_error(
        "line " + std::to_string(line) + ": " + message);
}

// 将配置文本转换成 Logger 的日志等级，严格区分大小写。
LogLevel parse_level(const std::string& value, std::size_t line)
{
    if (value == "debug") return LogLevel::Debug;
    if (value == "info") return LogLevel::Info;
    if (value == "warn") return LogLevel::Warn;
    if (value == "error") return LogLevel::Error;
    fail(line, "log_level must be debug/info/warn/error");
}

// 开关只接受 true/false，避免把拼写错误或其他约定当成合法值。
bool parse_bool(const std::string& value, std::size_t line)
{
    if (value == "true") return true;
    if (value == "false") return false;
    fail(line, "boolean value must be true/false");
}

// 解析窗口毫秒数；1..60000 是本项目的首版取值约定。
std::uint32_t parse_window(const std::string& value, std::size_t line)
{
    std::uint32_t result = 0;
    const auto* begin = value.data();
    const auto* end = begin + value.size(); // 解析范围为 [begin, end)，end 指向末字符后一位。
    const auto parsed = std::from_chars(begin, end, result);

    // ec 检查格式和溢出；ptr 检查完整消费，防止把 1000ms 误当成 1000。
    if (parsed.ec != std::errc{} || parsed.ptr != end ||
        result < 1 || result > 60000) {
        fail(line, "window_ms must be an integer in [1, 60000]");
    }
    return result;
}

// 验证路径型 Unix Socket 的地址表示；不创建 Socket，不检查目录和运行时权限。
void validate_socket(const std::string& value, std::size_t line)
{
    const sockaddr_un address{}; // 仅用于取得系统定义的 sun_path 数组容量。
    if (value.empty() || value.front() != '/') {
        fail(line, "socket_path must be an absolute pathname");
    }

    // C 路径不能含内嵌空字节，数组容量还需给结尾的 '\0' 留一个字节。
    if (value.find('\0') != std::string::npos ||
        value.size() >= sizeof(address.sun_path)) {
        fail(line, "socket_path contains NUL or exceeds sun_path capacity");
    }
}

} // namespace

// 打开指定文件并解析；出错时补充文件路径，显式指定的文件打不开就报错。
AppConfig ConfigManager::load(const std::string& path)
{
    // 相对路径以进程当前工作目录为起点；input 析构时自动关闭文件。
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("cannot open config file: " + path);
    }
    //如果解析成功就返回config，跳过catch；如果解析失败则不返回，进入catch
    try {
        return parse(input); //把内容交给解析函数
    } catch (const std::runtime_error& error) {
        throw std::runtime_error(path + ": " + error.what());
    }
}

// 从文件流或字符串流读取配置；全部成功才返回候选值，不向调用者泄漏部分解析结果。
AppConfig ConfigManager::parse(std::istream& input)
{
    AppConfig candidate{}; // 以默认值为基础，文件中出现的字段才会覆盖它。
    std::set<std::string> seen; // 本次已出现的键，用于拒绝重复配置。
    std::string raw; // 当前读入的原始行。
    std::size_t line = 0; // 实际行号，包括空行和注释行。

    while (std::getline(input, raw)) {
        ++line;
        const std::string text = trim(raw); //清理首尾空白
        if (text.empty() || text.front() == '#') { //空行和以 # 开头的行不参与解析
            continue;
        }
        if (text.find('\0') != std::string::npos) {
            fail(line, "NUL byte is not allowed"); //拒绝有效配置行中的空字节
        }
        const auto separator = text.find('='); //寻找第一个等号的位置，用它划分键和值。
        if (separator == std::string::npos) {
            fail(line, "expected key=value");
        }

        const std::string key = trim(text.substr(0, separator)); //取等号之前的部分
        const std::string value = trim(text.substr(separator + 1));
        if (key.empty() || value.empty()) {
            fail(line, "key and value must not be empty");
        }
        // insert 返回的 second 表示是否新插入；false 说明这个键已出现过。
        if (!seen.insert(key).second) {
            fail(line, "duplicate key: " + key);
        }

        // 按字段转换并校验；模块开关在此仅保存，实际启停由 daemon 集成层处理。
        if (key == "log_level") {
            candidate.log_level = parse_level(value, line);
        } else if (key == "socket_path") {
            validate_socket(value, line);
            candidate.socket_path = value;
        } else if (key == "window_ms") {
            candidate.window_ms = parse_window(value, line);
        } else if (key == "enable_syscall") {
            candidate.enable_syscall = parse_bool(value, line);
        } else if (key == "enable_cpu") {
            candidate.enable_cpu = parse_bool(value, line);
        } else if (key == "enable_lock") {
            candidate.enable_lock = parse_bool(value, line);
        } else if (key == "enable_io") {
            candidate.enable_io = parse_bool(value, line);
        } else {
            fail(line, "unknown key: " + key);
        }
    }
    // 正常 EOF 也可能置 failbit；只有严重错误或非 EOF 的失败才算读取故障。
    if (input.bad() || (input.fail() && !input.eof())) {
        throw std::runtime_error("config stream read failed");
    }
    return candidate;
}

} // namespace kylinrca
