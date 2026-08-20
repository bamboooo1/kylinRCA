#include "proc_cpu_sampler.h"

#include <chrono>
#include <iostream>
#include <thread>
#include <unistd.h>


int main()
{
    /*
     * getpid() 返回当前这个测试程序自己的 PID。
     *
     * 这样我们就可以持续读取：
     *
     * /proc/<当前程序PID>/stat
     *
     * 不需要依赖外部进程。
     */
    int pid = static_cast<int>(getpid());

    std::cout
        << "Sampler stability test PID: "
        << pid
        << std::endl;


    for (int i = 0; i < 10000; ++i) {

        CpuStatSample system_sample;

        if (!read_system_cpu_stat(system_sample)) {
            std::cerr
                << "Failed to read /proc/stat"
                << std::endl;

            return 1;
        }


        ProcessCpuStatSample process_sample;

        if (!read_process_cpu_stat(
                pid,
                process_sample)) {

            std::cerr
                << "Failed to read process stat"
                << std::endl;

            return 1;
        }


        /*
         * 每 100 次稍微停一下，
         * 方便我们在另一个终端观察这个进程。
         */
        if (i % 50 == 0) {

            std::cout
                << "iteration="
                << i
                << std::endl;}

        std::this_thread::sleep_for(
            std::chrono::milliseconds(100));
        
    }


    std::cout
        << "Stability test completed"
        << std::endl;

    return 0;
}
