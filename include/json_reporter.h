#ifndef KYLINRCA_JSON_REPORTER_H
#define KYLINRCA_JSON_REPORTER_H

#include "syscall_analyzer.h"

#include <string>

class JsonReporter {
public:
    static std::string report_syscalls(const SyscallAnalyzer& analyzer); //要求输入SyscallAnalyzer class对象
};

#endif