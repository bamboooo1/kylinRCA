#ifndef KYLINRCA_PROC_CPU_SAMPLER_H
#define KYLINRCA_PROC_CPU_SAMPLER_H

#include <cstdint>
#include <string>
#include <unordered_map>
#include <functional>

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
 * 全系统线程 CPU 快照中的一条记录。
 *
 * pid 是线程组 ID（进程 ID），tid 是具体线程 ID。utime/stime 来自
 * /proc/<pid>/task/<tid>/stat，用于计算每个线程在采样窗口内的 CPU
 * 使用率。
 */
struct ThreadCpuStatSample {
    int pid = 0;
    int tid = 0;
    std::string comm;
    char state = '?';
    std::uint64_t utime = 0;
    std::uint64_t stime = 0;
    /* stat 第 22 字段；识别数字 PID/TID 是否已被内核复用。 */
    std::uint64_t starttime_ticks = 0;
    std::uint64_t sampled_at_ns = 0;

    /* 独立的 BPF 累计运行快照，不用 /proc 使用率伪造运行证据。 */
    bool bpf_valid = false;
    std::uint64_t bpf_total_ns = 0;
    std::uint64_t bpf_birth_ns = 0;
    std::uint64_t bpf_sample_ns = 0;
    std::uint64_t bpf_uncertainty_ns = 0;
};

using ThreadCpuStatMap =
    std::unordered_map<std::uint32_t, ThreadCpuStatSample>;

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

/*
 * 扫描 /proc/<pid>/task/<tid>/stat，建立当前全系统线程 CPU 快照。
 *
 * 扫描过程中进程或线程随时可能退出；单个条目读取失败时跳过，只有最终
 * 一个线程都没有读到时才返回 false。
 */
using ThreadSnapshotHook = std::function<void(ThreadCpuStatSample&)>;
bool read_all_thread_cpu_stats(
    ThreadCpuStatMap& samples,
    const ThreadSnapshotHook& hook = {});

std::uint64_t cpu_total_time(const CpuStatSample& sample);

std::uint64_t cpu_idle_time(const CpuStatSample& sample);

bool calculate_system_cpu_usage(
    const CpuStatSample& previous,
    const CpuStatSample& current,
    double& usage_percent);

bool calculate_thread_cpu_usage(
    const ThreadCpuStatSample& previous,
    const ThreadCpuStatSample& current,
    double elapsed_seconds,
    long clock_ticks_per_second,
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
