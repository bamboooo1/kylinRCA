#ifndef KYLINRCA_IO_CONFIG_H
#define KYLINRCA_IO_CONFIG_H
#include "io_analyzer.h"
#include <istream>
#include <string>

// I/O 模块专用配置：探针设备条件与分析规则各自保存，不扩展 daemon 的公共 AppConfig。
struct IoConfig {
    std::string device; // 空字符串表示全部设备，否则为经过校验的“主设备号:次设备号”。
    IoAnalyzerConfig analyzer; // 默认 10ms、最低 10 样本；窗口长度由 daemon 的公共设置覆盖。

    // 主线程在显式指定 --io-config 时调用，打开文件并解析；错误包含文件路径，不静默回退默认值。
    static IoConfig load(const std::string& path);
    // 解析模块的三个配置项，检查重复键、整数范围和设备格式；返回完整值或抛出带行号的错误。
    static IoConfig parse(std::istream& input);
};
#endif
