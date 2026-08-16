#include "json_reporter.h"
#include<sstream>

std::string JsonReporter::report_syscalls(const SyscallAnalyzer& analyzer){
    std::ostringstream out; // C++ 标准库中的“字符串输出流”，用于像使用 std::cout 一样，逐段拼接字符串。

    out << "{\n";
    out << "  \"type\": \"syscall_summary\",\n";
    out << "  \"processes\": [\n"; // 这些内容不会显示到终端，而是暂存在 output 内部。最后通过：return output.str();取得普通的 std::string：

    const auto& all_stats = analyzer.stats();

    bool first_process = true;  // 确保第一个process前不输出逗号

    for (const auto& [pid, syscall_map] : all_stats) {

        if (!first_process) {
            out << ",\n";
        }

        first_process = false;

        out << "    {\n";
        out << "      \"pid\": " << pid << ",\n";
        out << "      \"syscalls\": [\n";

        bool first_syscall = true;

        for (const auto& [syscall_id, stat] : syscall_map) {

            if (!first_syscall) {
                out << ",\n";
            }

            first_syscall = false;

            uint64_t avg_duration_ns =
                stat.count == 0
                    ? 0
                    : stat.total_duration_ns / stat.count;

            out << "        {\n";
            out << "          \"id\": "
                << syscall_id << ",\n";

            out << "          \"name\": \""
                << SyscallAnalyzer::syscall_name(syscall_id)
                << "\",\n";

            out << "          \"count\": "
                << stat.count << ",\n";

            out << "          \"avg_duration_ns\": "
                << avg_duration_ns << ",\n";

            out << "          \"max_duration_ns\": "
                << stat.max_duration_ns << ",\n";

            out << "          \"error_count\": "
                << stat.error_count << "\n";

            out << "        }";
        }

        out << "\n";
        out << "      ]\n";
        out << "    }";
    }

    out << "\n";
    out << "  ]\n";
    out << "}\n";

    return out.str();
}