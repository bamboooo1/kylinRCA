#ifndef KYLINRCA_UNIX_SOCKET_SERVER_H
#define KYLINRCA_UNIX_SOCKET_SERVER_H

#include "daemon_snapshot.h"

#include <atomic>
#include <string>
#include <thread>

class UnixSocketServer {
public:
    UnixSocketServer(std::string socket_path, const SnapshotStore& snapshots);
    ~UnixSocketServer();
    UnixSocketServer(const UnixSocketServer&) = delete;
    UnixSocketServer& operator=(const UnixSocketServer&) = delete;

    // 主线程启动服务：绑定失败抛异常；已有路径保留，避免覆盖另一进程或普通文件。
    void start();
    void stop();

private:
    void serve();
    void handle_client(int client_fd);

    std::string socket_path_;
    const SnapshotStore& snapshots_;
    int listener_fd_ = -1;
    bool owns_socket_path_ = false;
    std::atomic<bool> stopping_{false}; //是一个“是否该收工”的开关，用来通知 Socket 接待线程停止。false	继续接待查询
    std::thread server_thread_;
};

#endif
