#include "json_reporter.h"
#include "syscall_analyzer.h"

#include <iostream>
#include <string>
#include <sys/syscall.h>

int main()
{
    SyscallAnalyzer analyzer;

    syscall_event event1{}; // syscall_analyzer.h 包含 event.h → 获得 syscall_event 定义
    event1.header.pid = 1234;
    event1.syscall_id = SYS_read;
    event1.ret = 128; // return value（返回值）
    event1.duration_ns = 1000;

    syscall_event event2{};
    event2.header.pid = 1234;
    event2.syscall_id = SYS_read;
    event2.ret = 64;
    event2.duration_ns = 3000;

    syscall_event event3{};
    event3.header.pid = 1234;
    event3.syscall_id = SYS_write;
    event3.ret = -1;
    event3.duration_ns = 2000;

    analyzer.process(event1);
    analyzer.process(event2);
    analyzer.process(event3);

    std::string json = JsonReporter::report_syscalls(analyzer);

    std::cout << json;

    if (json.find("\"pid\": 1234") == std::string::npos) {
        std::cerr << "Missing PID in JSON" << std::endl;
        return 1; // std::string::npos 表示“没有找到对应字符串”。
    }

    if (json.find("\"name\": \"read\"") == std::string::npos) {
        std::cerr << "Missing read syscall in JSON" << std::endl;
        return 1;
    }

    if (json.find("\"count\": 2") == std::string::npos) {
        std::cerr << "Unexpected read count" << std::endl;
        return 1;
    }

    if (json.find("\"avg_duration_ns\": 2000") == std::string::npos) {
        std::cerr << "Unexpected average duration" << std::endl;
        return 1;
    }

    std::cout << "JSON reporter smoke OK" << std::endl;

    return 0;
}