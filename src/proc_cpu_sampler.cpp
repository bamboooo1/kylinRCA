#include "proc_cpu_sampler.h"

#include <fstream>
#include <sstream>
#include <string>


bool read_system_cpu_stat(CpuStatSample& sample)
{
    std::ifstream file("/proc/stat"); //打开 Linux 提供的 /proc/stat

    if (!file.is_open()) {
        return false;
    }

    std::string line;

    if (!std::getline(file, line)) { //读取第一行数据
        return false;
    }

    std::istringstream iss(line);

    std::string cpu_label;

    if (!(iss >> cpu_label)) {
        return false;
    }

    /*
     * 第一行必须是：
     *
     * cpu  user nice system ...
     */
    if (cpu_label != "cpu") {
        return false;
    }

    if (!(iss
          >> sample.user
          >> sample.nice
          >> sample.system
          >> sample.idle
          >> sample.iowait
          >> sample.irq
          >> sample.softirq
          >> sample.steal)) {
        return false;
    }

    return true;
}

/*
 *  /proc/<pid>/stat 输出形式：
 *  "2667 (sleep) S 326 2667 326 34816 2721 4194304 510 0 0 0 0 0 0 20 0 1 0 1675508 ..."
 */

bool read_process_cpu_stat(
    int pid,
    ProcessCpuStatSample& sample)
{
    std::string path =
        "/proc/" + std::to_string(pid) + "/stat";

    std::ifstream file(path);

    if (!file.is_open()) {
        return false;
    }

    std::string line;

    if (!std::getline(file, line)) {
        return false;
    }

    // 定位进程名
    std::size_t left_paren = line.find('('); //从左往右寻找第一个 '(' 出现的位置

    std::size_t right_paren = line.rfind(')'); //从右往左找最后一个 ')'。

    if (left_paren == std::string::npos ||
        right_paren == std::string::npos ||
        right_paren <= left_paren) {
        return false;
    }

    try {
        sample.pid = std::stoi(line.substr(0, left_paren));
	    //从位置 0 开始，截取 left_paren 个字符，并转换成整数得到pid
    } catch (...) { //如果捕获到异常，返回false
        return false;
    }

    sample.comm = line.substr(left_paren + 1, right_paren - left_paren - 1); //截取括号内的进程名

    if (right_paren + 2 >= line.size()) {
        return false;
    }

    std::string rest =
        line.substr(right_paren + 2); //从右括号之后的第二个位置开始截取，因为括号后紧接着是空格

    std::istringstream iss(rest);

    /*
     * ')' 后面的字段从 stat 的第 3 字段开始：
     *
     * 3  state
     * 4  ppid
     * 5  pgrp
     * 6  session
     * 7  tty_nr
     * 8  tpgid
     * 9  flags
     * 10 minflt
     * 11 cminflt
     * 12 majflt
     * 13 cmajflt
     * 14 utime
     * 15 stime
     */

    long long ppid;
    long long pgrp;
    long long session;
    long long tty_nr;
    long long tpgid;

    unsigned long long flags;
    unsigned long long minflt;
    unsigned long long cminflt;
    unsigned long long majflt;
    unsigned long long cmajflt;

    if (!(iss
          >> sample.state
          >> ppid
          >> pgrp
          >> session
          >> tty_nr
          >> tpgid
          >> flags
          >> minflt
          >> cminflt
          >> majflt
          >> cmajflt
          >> sample.utime
          >> sample.stime)) {
        return false;
    }

    return true;
}

std::uint64_t cpu_total_time(const CpuStatSample& sample)
{
    return sample.user
         + sample.nice
         + sample.system
         + sample.idle
         + sample.iowait
         + sample.irq
         + sample.softirq
         + sample.steal;
}


std::uint64_t cpu_idle_time(const CpuStatSample& sample)
{
    return sample.idle
         + sample.iowait;
}

bool calculate_system_cpu_usage(
    const CpuStatSample& previous,
    const CpuStatSample& current,
    double& usage_percent)
{
    std::uint64_t previous_total =
        cpu_total_time(previous);

    std::uint64_t current_total =
        cpu_total_time(current);

    std::uint64_t previous_idle =
        cpu_idle_time(previous);

    std::uint64_t current_idle =
        cpu_idle_time(current);


    if (current_total < previous_total ||
        current_idle < previous_idle) {
        return false;
    }


    std::uint64_t total_delta =
        current_total - previous_total;

    std::uint64_t idle_delta =
        current_idle - previous_idle;


    if (total_delta == 0) {
        return false;
    }


    if (idle_delta > total_delta) {
        return false;
    }


    std::uint64_t busy_delta =
        total_delta - idle_delta;


    usage_percent =
        static_cast<double>(busy_delta)
        * 100.0
        / static_cast<double>(total_delta);


    return true;
}

bool calculate_process_cpu_usage(
    const ProcessCpuStatSample& previous,
    const ProcessCpuStatSample& current,
    double elapsed_seconds,
    long clock_ticks_per_second,
    double& usage_percent)
{
    if (previous.pid != current.pid) {
        return false;
    }

    if (elapsed_seconds <= 0.0) {
        return false;
    }

    if (clock_ticks_per_second <= 0) {
        return false;
    }


    std::uint64_t previous_cpu_time =
        previous.utime + previous.stime; //用户态进程使用时间与内核时间

    std::uint64_t current_cpu_time =
        current.utime + current.stime;


    if (current_cpu_time < previous_cpu_time) {
        return false;
    }


    std::uint64_t cpu_delta_ticks =
        current_cpu_time - previous_cpu_time;


    double cpu_seconds =
        static_cast<double>(cpu_delta_ticks)
        / static_cast<double>(clock_ticks_per_second);


    usage_percent =
        cpu_seconds
        / elapsed_seconds
        * 100.0;


    return true;
}

