#ifndef KYLINRCA_JSON_REPORTER_H
#define KYLINRCA_JSON_REPORTER_H

#include "syscall_analyzer.h"
#include "io_analyzer.h"

#include <cstdint>
#include <string>

struct CpuDiagnosis;
class LockAnalyzer; //类的前向声明。它只是告诉编译器：后面会用到一个叫 LockAnalyzer 的类，具体定义在其他地方（lock_analyzer.h）。

class JsonReporter {
public:
    static std::string report_io(const IoReport& report);
    static std::string report_syscalls(const SyscallAnalyzer& analyzer); //要求输入SyscallAnalyzer class对象
    static std::string report_cpu(const CpuDiagnosis& diagnosis, uint64_t window_start_ns,
                                  uint64_t window_end_ns, uint64_t received_events);
    static std::string report_locks(const LockAnalyzer& analyzer);
};

#endif
