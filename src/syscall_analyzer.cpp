#include "syscall_analyzer.h"

#include <algorithm>
#include <sys/syscall.h>

void SyscallAnalyzer::process(const syscall_event& event)
{
    auto& stat = stats_[event.header.pid][event.syscall_id];// auto 会根据等号右边表达式的类型自动推导。这里表示SyscallStats

    stat.count++;

    stat.total_duration_ns += event.duration_ns;

    stat.max_duration_ns = std::max(stat.max_duration_ns, static_cast<uint64_t>(event.duration_ns)); // 保留事件协议中的 __u64 是合理的，因为它用于内核与用户态共享数据；在用户态统计时显式转换为 uint64_t 即可

    if (event.ret < 0) {
        stat.error_count++;
    }
}

const std::unordered_map<uint32_t, std::unordered_map<int64_t, SyscallStats>>&SyscallAnalyzer::stats() const
{
    return stats_;
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