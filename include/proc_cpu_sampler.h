#ifndef KYLINRCA_PROC_CPU_SAMPLER_H
#define KYLINRCA_PROC_CPU_SAMPLER_H

#include <cstdint>
#include <string>

struct CpuStatSample {
    std::uint64_t user = 0; //用户态普通进程运行时间
    std::uint64_t nice = 0; //调整过 nice 的用户态进程运行时间
    std::uint64_t system = 0; //内核态运行时间
    std::uint64_t idle = 0; //CPU 空闲时间
    std::uint64_t iowait = 0; //等待 I/O 的时间
    std::uint64_t irq = 0; //处理硬中断时间
    std::uint64_t softirq = 0; //处理软中断时间
    std::uint64_t steal = 0; //虚拟机被宿主机抢走的 CPU 时间
};

struct ProcessCpuStatSample {
    int pid = 0;
    std::string comm;
    char state = '?';

    std::uint64_t utime = 0;
    std::uint64_t stime = 0;
};

/*
 * 读取 /proc/stat 第一行。
 *
 * 成功：
 *     返回 true
 *     sample 中保存 CPU 累计时间
 *
 * 失败：
 *     返回 false
 */
bool read_system_cpu_stat(CpuStatSample& sample);

bool read_process_cpu_stat(int pid, ProcessCpuStatSample& sample);

std::uint64_t cpu_total_time(const CpuStatSample& sample);

std::uint64_t cpu_idle_time(const CpuStatSample& sample);

bool calculate_system_cpu_usage(
    const CpuStatSample& previous,
    const CpuStatSample& current,
    double& usage_percent);

bool calculate_process_cpu_usage(
    const ProcessCpuStatSample& previous,
    const ProcessCpuStatSample& current,
    double elapsed_seconds,  // 两次采样之间现实世界过去了多少秒。
    long clock_ticks_per_second, // '''getconf CLK_TCK''' **系统每秒内核节拍（jiffies/tick）数量**
				 // 代表内核统计时间的单位换算系数
    double& usage_percent);

/*
 * struct CpuUsageResult {
    double system_usage_percent = 0.0;

    int pid = 0;
    std::string comm;
    char state = '?';

    double process_usage_percent = 0.0;
};
*/

#endif
