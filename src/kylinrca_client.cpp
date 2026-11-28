#include "config_manager.h"

#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

struct Options {
    std::string command;
    std::string socket_path = kylinrca::AppConfig{}.socket_path;
    bool help = false;
};

// 参数错误或请求帮助时显示查询用法，默认路径取自 daemon 的公共配置。
void print_usage(std::ostream& output)
{
    output << "用法：kylinrca_client [--socket PATH] <status|top|report>\n"
           << "      kylinrca_client --help\n"
           << "  status  查看守护进程的运行状态和已启用的模块\n"
           << "  top     查看最近一个统计周期内排名靠前的系统调用、线程、锁和设备\n"
           << "  report  查看最新的分析报告\n"
           << "  --socket PATH  指定 Unix Socket 路径（默认：" << Options{}.socket_path << "）\n";
}

// 将命令行转换成一次查询所需的命令和路径。缺少参数、重复选项或未知命令时抛出异常，
// 调用方在建立连接前处理这些错误。
Options parse_options(int argc, char* argv[])
{
    Options options;
    bool socket_specified = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            options.help = true;
        } else if (arg == "--socket") {
            if (socket_specified)
                throw std::invalid_argument("--socket may only be specified once");
            if (++i == argc || argv[i][0] == '\0')
                throw std::invalid_argument("--socket requires a path");
            options.socket_path = argv[i];
            socket_specified = true;
        } else if (options.command.empty() && (arg == "status" || arg == "top" || arg == "report")) {
            options.command = arg;
        } else {
            throw std::invalid_argument("Unexpected argument: " + std::string(arg));
        }
    }
    if (!options.help && options.command.empty())
        throw std::invalid_argument("Expected one of status, top, or report");
    return options;
}

// 一个 Socket 对应一次请求。创建失败抛出系统错误，正常返回或异常退出时都关闭描述符。
struct QuerySocket {
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    QuerySocket()  // 创建一个 Unix Socket，SOCK_CLOEXEC 表示在执行其他程序时自动关闭这个连接编号
    {
        if (fd < 0)
            throw std::system_error(errno, std::generic_category(), "Cannot create Unix socket");
    }

    ~QuerySocket() { close(fd); }

    /*QuerySocket a;
      QuerySocket b = a; // 拷贝构造：用 a 创建一个新对象，编译报错
      QuerySocket c;
      c = a;            // 拷贝赋值：把 a 赋给已经存在的 c，编译报错*/
    QuerySocket(const QuerySocket&) = delete; // 禁止调用拷贝构造函数
    QuerySocket& operator=(const QuerySocket&) = delete; // 禁止调用拷贝赋值运算符
};

// 连接成功后发送命令和行尾。短写从已发送位置继续，发送失败通过异常交给主函数报告。
void send_request(int fd, const std::string& command)
{
    const std::string request = command + '\n';
    std::size_t sent = 0;
    while (sent < request.size()) {
        const auto written = send(fd, request.data() + sent, request.size() - sent, MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0)
            throw std::system_error(errno, std::generic_category(), "Cannot send query to kylinrcad");
        if (written == 0)
            throw std::runtime_error("Connection closed while sending query to kylinrcad");
        sent += static_cast<std::size_t>(written);
    }
}

// Socket 可能分多次交付快照。读到 LF 才返回完整响应，超时或提前断开时抛出异常。
std::string receive_response(int fd)
{
    std::string response;
    char buffer[16384];
    for (;;) {
        /*假设你查 status，daemon 返回的 JSON 分成两次收到。
        `chunk` 是这一次收到的片段，`response` 是到目前为止拼起来的内容。
        最终返回的 response 是下面这个字符串，末尾的 \n 已经去掉了。
        {"ok":true,"command":"status","data":{"state":"running"}}*/
        const auto received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            throw std::runtime_error("Timed out waiting for a response from kylinrcad");
        if (received < 0)
            throw std::system_error(errno, std::generic_category(), "Cannot read response from kylinrcad");
        if (received == 0)
            throw std::runtime_error("kylinrcad closed the connection before sending a complete response");

        const std::string_view chunk(buffer, static_cast<std::size_t>(received));
        const auto newline = chunk.find('\n');
        response += chunk.substr(0, newline);
        if (newline != std::string_view::npos)
            return response; 
    }
}

// 用命令行选定的路径完成一次连接和查询。限制无进展的等待时间，连接失败时给出路径和系统原因。
std::string query_daemon(const Options& options)
{
    sockaddr_un address{}; //创建一个用来保存 Unix Socket 地址的结构体
    address.sun_family = AF_UNIX; //告诉 Linux 这是一个本机 Unix Socket 地址。
    if (options.socket_path.size() >= sizeof(address.sun_path))
        throw std::runtime_error("Socket path is too long: " + options.socket_path);
    //将命令行指定的路径复制到地址结构体中。注意要加上结尾的 '\0'，所以长度要 +1。
    std::memcpy(address.sun_path, options.socket_path.c_str(), options.socket_path.size() + 1);

    const QuerySocket connection;// 创建客户端自己的 Socket
    const timeval timeout{3, 0};
    if (setsockopt(connection.fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(connection.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        throw std::system_error(errno, std::generic_category(), "Cannot set Unix socket timeout");

    if (connect(connection.fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
        const int error = errno;
        std::string message = "Cannot connect to Unix socket '" + options.socket_path + '\'';
        if (error == ENOENT || error == ECONNREFUSED)
            message += " (is kylinrcad running?)";
        throw std::system_error(error, std::generic_category(), message);
    }

    send_request(connection.fd, options.command);
    return receive_response(connection.fd);
}

// 检查 daemon 发出的固定响应结构和回显命令。错误响应带上 daemon 的错误码，
// 成功响应保留完整 JSON，快照字段和数值直接交给调用者。
void print_response(std::string_view response, const std::string& command)
{
    constexpr std::string_view error_prefix = "{\"ok\":false,\"error\":\"";
    if (response.substr(0, error_prefix.size()) == error_prefix && //开头是 {"ok":false,"error":"。
        response.size() > error_prefix.size() + 2 && //开头和结尾之间至少有一个字符，也就是错误内容。
        response.substr(response.size() - 2) == "\"}") //末尾两个字符是"}。
        { 
        const auto error = response.substr(error_prefix.size(), response.size() - error_prefix.size() - 2); //提取出 unknown_command
        throw std::runtime_error("kylinrcad returned an error: " + std::string(error));
    }

    //成功响应的预期开头：{"ok":true,"command":"status","data":{
    const std::string success_prefix = "{\"ok\":true,\"command\":\"" + command + "\",\"data\":{";
    if (response.substr(0, success_prefix.size()) != success_prefix ||
        response.size() < success_prefix.size() + 2 || response.substr(response.size() - 2) != "}}")
        throw std::runtime_error("Unexpected response format from kylinrcad");

    std::cout << response << '\n' << std::flush;
    if (!std::cout)
        throw std::runtime_error("Cannot write query result to standard output");
}

}

// 客户端入口负责串起参数、查询和终端输出。参数错误退出码为 2，查询或输出失败为 1。
int main(int argc, char* argv[])
{
    /*
    比如你在终端输入：./build/kylinrca_client --socket /tmp/demo.sock top
    解析出来的 options 就相当于：
    Options options{
    "top",            // command，要执行的查询
    "/tmp/demo.sock", // socket_path，要连接的 Socket 路径
    false             // help，是否显示帮助
    };
    */
    try {
        const auto options = parse_options(argc, argv);
        if (options.help)
            print_usage(std::cout);
        else
            print_response(query_daemon(options), options.command);
        return 0;
    } catch (const std::invalid_argument& error) {
        std::cerr << "kylinrca_client: " << error.what() << '\n';
        print_usage(std::cerr);
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "kylinrca_client: " << error.what() << '\n';
        return 1;
    }
}
