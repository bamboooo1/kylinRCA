#ifndef KYLINRCA_CPU_CONFIG_H
#define KYLINRCA_CPU_CONFIG_H
#include "cpu_analyzer.h"
#include <istream>
#include <string>

// Cpu 模块配置只持有现有分析规则；公共窗口、日志和模块开关仍由 AppConfig 管理。
struct CpuConfig {
    CpuAnalyzerConfig analyzer;
    // 主线程处理 --cpu-config 时读取文件；缺失或非法配置明确报错，包含文件路径。
    static CpuConfig load(const std::string& path);
    // 读取模块字段，检查单项范围和阈值关系；省略的参数保留分析器已有默认值。
    static CpuConfig parse(std::istream& input);
};
#endif
