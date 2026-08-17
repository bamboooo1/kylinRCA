#include "syscall_analyzer.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <sys/syscall.h>
#include <sys/types.h>

namespace { // namespace在这里表示 process_exists() 只允许在当前 syscall_analyzer.cpp 文件中使用，不对其他 .cpp 文件公开。
// 检查一个 PID 当前是否还存在。
// kill(pid, 0) 不会真的给目标进程发送信号。
// 它只是让内核帮我们检查这个 PID 是否存在、是否有权限访问。
bool process_exists(uint32_t pid)
{
    errno = 0;
    int result = ::kill(static_cast<pid_t>(pid), 0);

    if (result == 0) {
        return true; // kill(pid, 0) 成功：说明这个 PID 目前存在。
    }

    if (errno == EPERM) { 
        return true; // EPERM = Permission denied。虽然我们没有权限向它发信号，但恰恰说明这个进程确实存在。
    }

    if (errno == ESRCH) {
        return false;// ESRCH = No such process。说明这个 PID 已经不存在了。
    }
    return true;// 对其它意外错误采取保守策略：不轻易删除统计。
}

} // namespace

void SyscallAnalyzer::process(const syscall_event& event)
{
    auto& stat = stats_[event.header.pid][event.syscall_id];// auto 会根据等号右边表达式的类型自动推导。这里表示SyscallStats

    stat.count++;

    stat.total_duration_ns += event.duration_ns;

    stat.max_duration_ns = std::max(stat.max_duration_ns, static_cast<uint64_t>(event.duration_ns)); // 保留事件协议中的 __u64 是合理的，因为它用于内核与用户态共享数据；在用户态统计时显式转换为 uint64_t 即可

    if (event.ret < 0) {
        stat.error_count++;
    }

    last_seen_[event.header.pid] = std::chrono::steady_clock::now(); //每收到这个 PID 的一个真实 syscall event，就更新它最后出现的时间。
}

const std::unordered_map<uint32_t, std::unordered_map<int64_t, SyscallStats>>&SyscallAnalyzer::stats() const
{
    return stats_;
}

std::size_t SyscallAnalyzer::cleanup_exited_processes(std::chrono::seconds retention)
{
    const auto now = std::chrono::steady_clock::now();
    std::size_t removed_count = 0;

    // 注意：
    // 删除 unordered_map 元素时不能普通 ++it 后再 erase，
    // erase(it) 会返回删除之后的下一个有效 iterator。
    for (auto it = last_seen_.begin(); it != last_seen_.end();) 
    {
        const uint32_t pid = it->first;
        const auto idle_time = now - it->second;

        // 我们只有同时满足两个条件才删除：
        //
        // 1. PID 已经不存在
        // 2. 它最后一次出现已经超过 retention
        //
        // 这样不会误删只是暂时安静、但仍然存活的进程。
        if (idle_time >= retention && !process_exists(pid)) {
            stats_.erase(pid);// 删除真正的 syscall 统计。
            it = last_seen_.erase(it); // 删除 last_seen 记录。
            removed_count++;
        } 
        else {
            ++it;
        }
    }

    return removed_count;
}

std::size_t SyscallAnalyzer::process_count() const
{
    return stats_.size();
}

const char* SyscallAnalyzer::syscall_name(int64_t syscall_id)
{
    switch (syscall_id) {

#ifdef SYS_read // 系统有没有定义 SYS_read 这个名字？如果定义了，才编译下面的代码。
    case SYS_read: // 如果 syscall_id 等于 SYS_read 所代表的数字，就执行这里。
        return "read";
#endif

#ifdef SYS_write
    case SYS_write:
        return "write";
#endif

#ifdef SYS_futex  // futex 是 Linux 用来实现线程同步的底层系统调用，全称是 Fast Userspace Mutex。比如线程在等待或唤醒、处理锁竞争
    case SYS_futex:
        return "futex";
#endif

#ifdef SYS_openat // openat 用于打开文件或目录
    case SYS_openat:
        return "openat";
#endif

#ifdef SYS_close
    case SYS_close:
        return "close";
#endif

#ifdef SYS_getpid
    case SYS_getpid:
        return "getpid";
#endif

    default:
        return "unknown";
    }
}