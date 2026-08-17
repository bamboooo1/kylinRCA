#ifndef KYLINRCA_SYSCALL_ANALYZER_H
#define KYLINRCA_SYSCALL_ANALYZER_H

#include "event.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <unordered_map>

struct SyscallStats {
    uint64_t count = 0;
    uint64_t total_duration_ns = 0;
    uint64_t max_duration_ns = 0;
    uint64_t error_count = 0;
};

class SyscallAnalyzer {
public:
    void process(const syscall_event& event); //const：不允许修改传入的事件。接收一个 syscall_event，并更新：stats_[PID][syscall_id]

    const std::unordered_map< uint32_t, std::unordered_map<int64_t, SyscallStats> >& stats() const; // 开头的 const：调用者只能查看结果，不能修改内部统计表。末尾的 const：这个函数承诺不会修改 SyscallAnalyzer 对象。
   
    std::size_t cleanup_exited_processes(std::chrono::seconds retention); // 删除已经退出、并且已经超过 retention 时间没有事件的 PID。防止全系统长期运行时 stats_ 无限增长。返回值表示这一次一共清理了多少个 PID。

    std::size_t process_count() const;  // 当前 Analyzer 里一共还保存了多少个 PID。主要用于稳定性测试和以后做运行状态监控。
    
    static const char* syscall_name(int64_t syscall_id);// static：函数不依赖某个具体分析器对象，可以直接通过类名调用。
    
private:
    std::unordered_map<uint32_t, std::unordered_map<int64_t, SyscallStats>> stats_; // stats_[1234][0]表示：PID 1234 的 syscall 0（read）的统计信息

    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> last_seen_; // 记录每个 PID 最后一次收到 syscall event 的用户态时间。key   = PID，value = 最后一次看到这个 PID 的时间。
};
// std::unordered_map 是 C++ 标准库提供的“键—值”容器
// std::unordered_map<int, std::string> names;
// 键的类型：int，值的类型：std::string
// 可以存入：names[0] = "read";names[1] = "write";
// 再通过键查找：std::cout << names[0];  // 输出 read

#endif