#ifndef KYLINRCA_SYSCALL_ANALYZER_H
#define KYLINRCA_SYSCALL_ANALYZER_H

#include "event.h"

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
    void process(const syscall_event& event); //const：不允许修改传入的事件。

    const std::unordered_map< uint32_t, std::unordered_map<int64_t, SyscallStats> >& stats() const; // 开头的 const：调用者只能查看结果，不能修改内部统计表。末尾的 const：这个函数承诺不会修改 SyscallAnalyzer 对象。
   
    static const char* syscall_name(int64_t syscall_id);// static：函数不依赖某个具体分析器对象，可以直接通过类名调用。
    
private:
    std::unordered_map<uint32_t, std::unordered_map<int64_t, SyscallStats>> stats_; // stats_[1234][0]表示：PID 1234 的 syscall 0（read）的统计信息
};
// std::unordered_map 是 C++ 标准库提供的“键—值”容器
// std::unordered_map<int, std::string> names;
// 键的类型：int，值的类型：std::string
// 可以存入：names[0] = "read";names[1] = "write";
// 再通过键查找：std::cout << names[0];  // 输出 read

#endif