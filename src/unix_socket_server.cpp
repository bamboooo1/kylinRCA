/*利用 Linux 提供的本机通信功能，
    开一个接收查询的入口，再用独立线程接收命令、读取快照、发送答案。*/
#include "unix_socket_server.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

constexpr std::size_t request_limit = 64;

void send_response(int client_fd, const std::string& response,
                   const std::atomic<bool>& stopping)
{
    std::size_t sent_bytes = 0;//表示这份答案已经成功发送了多少字节。
    while (sent_bytes < response.size() && !stopping.load()) {
        const auto written = send(client_fd, response.data() + sent_bytes,
                                  response.size() - sent_bytes, MSG_NOSIGNAL);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return;
        sent_bytes += static_cast<std::size_t>(written);
    }
}

} // namespace

/*记住“窗口地址”和“快照仓库”。*/
UnixSocketServer::UnixSocketServer(std::string socket_path, const SnapshotStore& snapshots)
    : socket_path_(std::move(socket_path)), snapshots_(snapshots)
{
}

UnixSocketServer::~UnixSocketServer()
{
    stop();
}

void UnixSocketServer::start()
{
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path_.size() >= sizeof(address.sun_path))
        throw std::invalid_argument("Socket path is too long");
    std::memcpy(address.sun_path, socket_path_.c_str(), socket_path_.size() + 1);
    std::filesystem::create_directories(std::filesystem::path(socket_path_).parent_path());
    //创建一个本机通信入口，申请内核中的通信对象，取得操作编号。
    listener_fd_ = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (listener_fd_ < 0)
        throw std::system_error(errno, std::generic_category(), "Create Unix socket");
    try {
        //把listener_fd_入口绑定到指定路径，像挂上门牌
        //reinterpret_cast<目标类型>(要转换的值)：显式类型转换。在这里，它的意思是：把同一个内存地址，按照另一种指针类型交给函数使用。
        if (bind(listener_fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0)
            throw std::system_error(errno, std::generic_category(), "Bind " + socket_path_);
        owns_socket_path_ = true;
        // chmod(..., 0600) 把 Socket 的权限设为拥有者可读写。、
        // listen(listener_fd_, 8) 开始监听客户端连接；`8` 是等待接通的连接队列长度设置。
        if (chmod(socket_path_.c_str(), 0600) < 0 || listen(listener_fd_, 8) < 0)
            throw std::system_error(errno, std::generic_category(), "Listen on " + socket_path_);
        stopping_.store(false); //false 表示现在还不停止。这个标志可以由不同线程安全地读取或更新。

        //创建一个独立线程，专门接收客户端连接、读取快照、发送答案
        /*这里的 this 指向 run() 中创建的 query_server 对象：
            UnixSocketServer query_server(config.socket_path, snapshots);
            query_server.start();
        即创建一个新线程，让它执行 query_server 这个对象的 serve() 方法。*/
        server_thread_ = std::thread(&UnixSocketServer::serve, this);
    } catch (...) {
        stop();
        throw; //把try中出现的异常继续交给调用者
    }
}

/*先通知 Socket 接待线程收工，等线程结束，再关闭监听入口、删除 Socket 路径。*/
void UnixSocketServer::stop()
{
    stopping_.store(true); //接待线程UnixSocketServer::serve下次检查这个标志时，就会退出循环
    /*如果这个线程对象还关联着一个需要收尾的线程，就调用 join() 等待并收尾。*/
    if (server_thread_.joinable())
        server_thread_.join();
    if (listener_fd_ >= 0) {
        close(listener_fd_); //关闭监听入口，释放这个操作编号。
        listener_fd_ = -1;
    }
    if (owns_socket_path_) {//检查 Socket 路径是否由本对象创建。
        unlink(socket_path_.c_str()); //删除文件目录里的 Socket 路径，例如：
        owns_socket_path_ = false;
    }
}

/*serve() 的工作是：等待客户端连接，接通一个客户端，处理它的查询
    再关闭这次连接，然后继续等下一位。*/
void UnixSocketServer::serve()
{
    while (!stopping_.load()) {
        pollfd pending{listener_fd_, POLLIN, 0};//pollfd{fd，events, revents} 是系统提供的结构体，{监听的入口，希望等待客户端连接接通，revents稍后填写}
        const int ready_count = poll(&pending, 1, 100);//poll把登记表交给系统，等待事件。poll完成时会填写revents，并返回一个数给ready_count ，大于 0：有入口报告了事件。等于 0：等待超时。小于 0：等待过程中发生错误。
        if (ready_count < 0 && errno == EINTR) //失败原因是等待被信号打断。
            continue;
        if (ready_count < 0 || (pending.revents & (POLLERR | POLLHUP | POLLNVAL)))
            return; //失败原因是等待过程中发生错误，或者入口被关闭、挂起或无效。
        if (!(pending.revents & POLLIN)) //如果没有客户端连接等待接通，就开始下一轮等待。
            continue;

        // 从listener_fd_接通客户端，不需要取得客户端地址，不需要接收地址长度，	执行其他程序时自动关闭这个连接编号
        const int client_fd = accept4(listener_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (client_fd < 0)
            continue;
        // 准备一个 1 秒的超时设置
        const timeval timeout{1, 0};

        //设置接收和发送的等待超时。setsockopt() 表示“设置 Socket 的选项”，它的五个参数是：
        // 1. socket 文件描述符
        // 2. socket 层级（SOL_SOCKET）
        // 3. 选项名称（SO_RCVTIMEO 或 SO_SNDTIMEO）接收超时或发送超时
        // 4. 超时值的指针
        // 5. 超时值这份设置占多少字节
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0)
            handle_client(client_fd); //读取命令、取得快照、选择答案并发送。
        close(client_fd);
    }
}

void UnixSocketServer::handle_client(int client_fd)
{
    std::string request;
    char received[request_limit];
    while (!stopping_.load()) {
        const auto received_bytes = recv(client_fd, received, sizeof(received), 0);
        if (received_bytes < 0 && errno == EINTR)
            continue;
        if (received_bytes <= 0)
            return;
        request.append(received, static_cast<std::size_t>(received_bytes));
        const auto newline = request.find('\n');//找到换行字符'\n'时，`newline` 保存它的位置
        // 还没找到换行，但已经收到至少 64 字节||找到了换行，但位置已经达到 64 或更大
        if ((newline == std::string::npos && request.size() >= request_limit) ||
            (newline != std::string::npos && newline >= request_limit)) {
            send_response(client_fd, "{\"ok\":false,\"error\":\"request_too_long\"}\n", stopping_);
            return;
        }
        if (newline == std::string::npos)
            continue;
        request.resize(newline); //保留换行前面的命令。

        const auto captured_snapshot = snapshots_.read();
        const std::string* payload = nullptr; //准备一个指针，用来指向选中的答案。
        if (request == "status")
            payload = &captured_snapshot->status_json;
        else if (request == "top")
            payload = &captured_snapshot->top_json;
        else if (request == "report")
            payload = &captured_snapshot->report_json;
        else {
            send_response(client_fd, "{\"ok\":false,\"error\":\"unknown_command\"}\n", stopping_);
            return;
        }
        /*假设命令为 "top"，选中的答案暂时简化为 {"limit":10}，拼出来就是：
            {"ok":true,"command":"top","data":{"limit":10}}*/
        std::string response = "{\"ok\":true,\"command\":\"" + request + "\",\"data\":" + *payload + '}';
        //删除响应内部用于排版的换行
        auto new_end = std::remove(response.begin(), response.end(), '\n');
        response.erase(new_end, response.end());
        //在整个响应末尾加一个换行。以判断答案接收完整。
        response += '\n';
        send_response(client_fd, response, stopping_);
        return;
    }
}
