#ifndef KYLINRCA_IO_PROBE_READER_H
#define KYLINRCA_IO_PROBE_READER_H
#include "io_probe_stats.h"
#include "../bpf/include/io_request_state.h"
#include <array>
#include <string>
#include <bpf/libbpf.h>

// 一次读取到的内核累计健康数据；用于检查采集链路，与每设备每窗口的性能统计分开。
struct IoProbeHealth {
    std::array<uint64_t, IO_STAT_MAX> stats{}; // 请求处理、事件发出、丢失及错误计数。
    std::array<uint64_t, IO_LIFE_MAX> lifecycle{}; // 重排完成、最大重排次数和释放清理等生命周期统计。
    uint64_t pending = 0; // io_starts 中仍保留开始记录的数量；运行中遍历得到的是近似值。
};
// 加载前读取内核 BTF，确认三个块请求跟踪点的参数符合探针预期；不可读取或不兼容时返回 false。
bool io_probe_compatible();
// 加载后、挂载前写入设备过滤条件；device 为空采集全部设备，否则使用已经校验的“主设备号:次设备号”。
// 找不到配置表或写入失败时返回 false。
bool configure_io_probe(bpf_object* object, const std::string& device);
// 主线程周期或退出时读取健康表，汇总各 CPU 计数并估计未清理请求数量。
// 成功时填充 health；读取失败返回 false，调用方不应发布可能只更新了一部分的数据。
bool read_io_probe_health(bpf_object* object, IoProbeHealth& health);
// 将健康数据转换为 io_probe_stats JSON；只负责输出格式，不访问内核或重置计数。
std::string io_probe_health_json(const IoProbeHealth& health);
#endif
