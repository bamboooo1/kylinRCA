#include "proc_cpu_sampler.h"

#include <chrono>
#include <iostream>
#include <thread>
#include <unistd.h>

int main()
{
    CpuStatSample previous;
    CpuStatSample current;

    if (!read_system_cpu_stat(previous)) {
        std::cerr
            << "Failed to read first /proc/stat sample"
            << std::endl;

        return 1;
    }


    std::this_thread::sleep_for(
        std::chrono::seconds(1)); //当前线程暂停 1 秒钟。


    if (!read_system_cpu_stat(current)) {
        std::cerr
            << "Failed to read second /proc/stat sample"
            << std::endl;

        return 1;
    }


    double usage_percent = 0.0;


    if (!calculate_system_cpu_usage(
            previous,
            current,
            usage_percent)) {

        std::cerr
            << "Failed to calculate CPU usage"
            << std::endl;

        return 1;
    }


    std::cout
        << "CPU usage: "
        << usage_percent
        << "%"
        << std::endl;

// 测试process_proc_cpu_sampler

    int pid;

    std::cout << "Enter PID: ";
    std::cin >> pid;

    ProcessCpuStatSample process_previous;
    ProcessCpuStatSample process_current;

    auto start_time = std::chrono::steady_clock::now();

    if (!read_process_cpu_stat(
        pid,
        process_previous)) {

        std::cerr
            << "Failed to read first process sample"
            << std::endl;

        return 1;}

    std::this_thread::sleep_for(std::chrono::seconds(1));

    if (!read_process_cpu_stat(
        pid,
        process_current)) {

         std::cerr
            << "Failed to read second process sample"
            << std::endl;

        return 1;}
    
    auto end_time = std::chrono::steady_clock::now();

    double elapsed_seconds = std::chrono::duration<double>(
		    end_time - start_time).count();

    long clock_ticks = sysconf(_SC_CLK_TCK); //查询当前系统的运行参数。

    if (clock_ticks <= 0) {
        std::cerr
            << "Failed to get CLK_TCK"
            << std::endl;

        return 1;}

    double process_usage = 0.0;

    if (!calculate_process_cpu_usage(
        process_previous,
        process_current,
        elapsed_seconds,
        clock_ticks,
        process_usage)) {

    std::cerr
        << "Failed to calculate process CPU usage"
        << std::endl;

    return 1;}

    std::cout
        << "Process: "
        << process_current.comm
        << '\n'
        << "PID: "
        << process_current.pid
        << '\n'
        << "CPU usage: "
        << process_usage
        << "%"
        << std::endl;

    return 0;
}
