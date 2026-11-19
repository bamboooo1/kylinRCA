/*制造真实的 pthread_mutex 竞争和无竞争对照场景。
    竞争时多个工作线程共用一把锁；对照时每个线程使用自己的锁。
    输出锁对象范围、线程编号和应用层加锁耗时，供探针验收脚本核对。*/
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <numeric>
#include <string>
#include <system_error>
#include <thread>
#include <vector>
#include <time.h>

namespace {

/*保存启动参数，默认使用 8 个工作线程制造竞争，主线程额外持锁 100 毫秒。*/
struct Options {
    int threads = 8; // 工作线程数量，不包含主线程。
    int hold_ms = 100; // 竞争场景中，主线程在工作线程准备加锁后继续持锁的时长。
    bool automatic = false; // 为 false 时等待回车，为 true 时直接开始。
    std::string scenario = "contention"; // contention 为竞争，uncontended 为无竞争对照。
};

/*管理一组互斥锁，记录成功初始化的数量，并在结束时自动销毁。*/
struct Mutexes {
    std::vector<pthread_mutex_t> values; // 保存各个 pthread_mutex_t 对象。
    std::size_t initialized = 0; // 仅统计成功初始化的锁，便于部分失败时正确清理。

    // 构造函数:接收一个整数参数 count,使用 count 初始化成员变量 values.创建对象时自动调用。
    explicit Mutexes(std::size_t count) : values(count) {}

    /*普通成员函数 init()： 使用普通互斥锁属性初始化全部对象；返回 true 表示全部成功。必须手动调用。*/
    bool init()
    {
        // 创建属性对象，并将锁类型设为 PTHREAD_MUTEX_NORMAL。
        pthread_mutexattr_t attributes;
        if (pthread_mutexattr_init(&attributes) != 0)
            return false;
        if (pthread_mutexattr_settype(&attributes, PTHREAD_MUTEX_NORMAL) != 0) {
            pthread_mutexattr_destroy(&attributes);
            return false;
        }
        // 逐个初始化，遇到失败时停止，保留已成功的数量供析构清理。
        for (auto& mutex : values) {
            if (pthread_mutex_init(&mutex, &attributes) != 0)
                break;
            ++initialized;
        }
        // 属性已经应用到锁对象，释放属性对象本身即可。
        pthread_mutexattr_destroy(&attributes);
        return initialized == values.size();
    }

    /*析构函数:当对象结束使用时，只销毁那些已成功初始化的锁。对象生命周期结束时自动调用。*/
    ~Mutexes()
    {
        for (std::size_t i = 0; i < initialized; ++i)
            pthread_mutex_destroy(&values[i]);
    }
};

/*保存一个工作线程的执行结果，等线程全部退出后由主线程统一读取。*/
struct WorkerResult {
    long tid = 0; // Linux 线程编号。
    int lock_ret = -1; // pthread_mutex_lock 的返回码，0 表示成功。
    int unlock_ret = -1; // pthread_mutex_unlock 的返回码，0 表示成功。
    uint64_t wait_start_ns = 0; // 调用加锁前的单调时钟时间，单位纳秒。
    uint64_t acquired_ns = 0; // 加锁调用返回后的时间；返回成功时表示已经获得锁。
};

/*读取单调时钟并换算为纳秒；读取失败时返回 0。*/
uint64_t monotonic_ns()
{
    timespec now {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return static_cast<uint64_t>(now.tv_sec) * 1'000'000'000ULL + now.tv_nsec;
}

/*解析场景、线程数、持锁时长和自动启动选项，拒绝未知参数及无效数值。*/
bool parse_options(int argc, char** argv, Options& options)
{
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--auto") {
            options.automatic = true;
        } else if (argument == "--scenario") {
            if (++i == argc)
                return false;
            options.scenario = argv[i];
        } else if (argument == "--threads" || argument == "--hold-ms") {
            if (++i == argc)
                return false;
            int value = 0;
            const char* end = argv[i] + std::strlen(argv[i]);
            // 整个字符串都必须能转换为整数，不能接受 8abc 这样的内容。
            const auto parsed = std::from_chars(argv[i], end, value);
            if (parsed.ec != std::errc{} || parsed.ptr != end)
                return false;
            if (argument == "--threads")
                options.threads = value;
            else
                options.hold_ms = value;
        } else {
            return false;
        }
    }
    // 限定测试规模，并确认场景名称有效。
    return options.threads >= 2 && options.threads <= 64 &&
           options.hold_ms >= 20 && options.hold_ms <= 1000 &&
           (options.scenario == "contention" || options.scenario == "uncontended");
}

/*准备锁、启动线程、制造或避免竞争，再核对加锁结果和受保护计数。*/
int run(const Options& options)
{
    // 竞争场景只有一把共享锁；对照场景为每个工作线程分配一把锁。
    const bool contention = options.scenario == "contention";  // bool contention的值为true or false，表示是否为竞争场景。
    Mutexes mutexes(contention ? 1 : options.threads); //true就创建1把锁，否则就每个线程各一把锁
    if (!mutexes.init()) {
        std::cerr << "Cannot initialize pthread mutexes.\n";
        return 1;
    }

    // 打印锁对象数组的起始地址、单个对象大小和数量，不假定其等于 futex 地址。
    std::cout << "[MUTEX WORKLOAD] ready pid=" << getpid()
              << " scenario=" << options.scenario
              << " threads=" << options.threads
              << " mutex_addr=0x" << std::hex
              << reinterpret_cast<uintptr_t>(mutexes.values.data()) << std::dec
              << " mutex_size=" << sizeof(pthread_mutex_t)
              << " mutex_count=" << mutexes.values.size()
              << " hold_ms=" << options.hold_ms << std::endl;
    // 手动测试等待回车；自动验收脚本在探针就绪后，通过标准输入放行。
    if (!options.automatic) {
        std::cout << "Press Enter after the lock probe is ready." << std::endl;
        std::string command;
        if (!std::getline(std::cin, command))
            return 1;
    }

    // 每个线程保存一份结果；每把锁保护一个计数，避免对照场景的数据竞争。
    std::vector<WorkerResult> results(options.threads);
    std::vector<uint64_t> counters(mutexes.values.size(), 0); // 为每个互斥锁创建一个计数器
    std::vector<std::thread> workers;
    workers.reserve(options.threads); // 提前为 workers（线程数组）预先分配能够容纳 options.threads 个线程对象的内存空间。

    // 使用原子变量：因为多个线程可能同时读取或修改这些变量。std::atomic 能保证对变量的原子操作，避免数据竞争。
    std::atomic<bool> start {false}; // 控制工作线程统一开始。
    std::atomic<bool> cancelled {false}; // 创建线程失败时，通知已有线程取消任务。
    std::atomic<int> attempts {0}; // 已到达加锁调用前位置的线程数，不等于已阻塞线程数。

    // 主线程提前持有共享锁，使随后尝试加锁的工作线程需要等待。
    if (contention && pthread_mutex_lock(&mutexes.values[0]) != 0)
        return 1;

    try {
        for (int index = 0; index < options.threads; ++index) {
            // index 按值捕获，保证各线程使用自己的索引；其余数据按引用访问。
            workers.emplace_back([&, index] {
                // 线程任务
                WorkerResult& result = results[index];
                result.tid = syscall(SYS_gettid);
                // 启动阶段先让出 CPU，等待主线程统一放行。
                while (!start.load())//原子读取start的值，start == false 时，循环持续执行。
                    std::this_thread::yield();//表示当前线程主动提示操作系统调度器：可以先让其他线程运行。
                if (cancelled.load()) //true：直接退出当前 Lambda，工作线程结束。
                    return;
                // contention == true：所有线程使用 slot = 0，竞争同一把锁。contention == false：每个线程使用自己的 index，操作不同的锁。
                const std::size_t slot =  contention ? 0 : index;
                // 在真实 pthread_mutex_lock 调用前后取时，便于核对 BPF 事件区间。
                result.wait_start_ns = monotonic_ns();
                attempts.fetch_add(1);
                result.lock_ret = pthread_mutex_lock(&mutexes.values[slot]);//尝试获取这把互斥锁，如果锁已经被其他线程持有，对于这里的普通互斥锁，当前线程通常会阻塞，直到锁可用。
                result.acquired_ns = monotonic_ns();
                // 获得锁后更新其保护的计数，并持锁 1 毫秒后释放。
                if (result.lock_ret == 0) {
                    ++counters[slot];
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    result.unlock_ret = pthread_mutex_unlock(&mutexes.values[slot]);
                }
            });
        }
    }

    catch (const std::system_error& error) {
        // 创建失败时取消任务、放行已有线程，并释放主线程持有的锁后回收线程。
        cancelled.store(true);
        start.store(true);
        if (contention)
            pthread_mutex_unlock(&mutexes.values[0]);
        for (auto& worker : workers)
            worker.join();
        std::cerr << "Cannot create worker threads: " << error.what() << '\n';
        return 1;
    }

    // 主线程通知所有工作线程开始执行，在锁竞争模式下等待所有线程到达加锁位置，然后继续持锁一段时间，最后释放锁。
    start.store(true);
    bool passed = true;
    if (contention) {
        // 主线程最多等待 5 秒，让所有工作线程到达准备调用加锁的位置。
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (attempts.load() != options.threads && std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield(); //主线程等待工作线程更新 attempts，所以通过 yield() 减少自己持续占用 CPU 的机会。
        if (attempts.load() != options.threads) {
            std::cerr << "Workers did not reach pthread_mutex_lock in time.\n";
            passed = false;
        }
        // 主线程继续持锁指定时长，为工作线程产生可测量的等待留出时间，然后释放。
        std::this_thread::sleep_for(std::chrono::milliseconds(options.hold_ms));
        if (pthread_mutex_unlock(&mutexes.values[0]) != 0)
            passed = false;
    }
    // 主线程等待全部工作线程退出，再读取结果；join 本身也可能产生其他地址上的 futex 等待。
    for (auto& worker : workers)
        worker.join();

    // 汇总每个线程的返回码和应用层加锁耗时。
    int acquisitions = 0;
    for (int index = 0; index < options.threads; ++index) {
        const WorkerResult& result = results[index];
        // 这里是整个加锁调用的经过时间，不直接等于某一条 futex 事件的耗时。
        const uint64_t elapsed = result.acquired_ns >= result.wait_start_ns
            ? result.acquired_ns - result.wait_start_ns : 0;
        if (result.lock_ret == 0)
            ++acquisitions;
        // 竞争场景要求等待至少达到设定持锁时长的一半；对照场景不设耗时上限。
        if (result.lock_ret || result.unlock_ret || !result.wait_start_ns ||
            result.acquired_ns < result.wait_start_ns ||
            (contention && elapsed < static_cast<uint64_t>(options.hold_ms) * 500'000ULL))
            passed = false;
        // 打印当前工作线程使用的锁对象和加锁区间，供验收脚本匹配实际采集事件。
        std::cout << "[MUTEX WORKER] pid=" << getpid()
                  << " tid=" << result.tid
                  << " mutex_addr=0x" << std::hex
                  << reinterpret_cast<uintptr_t>(&mutexes.values[contention ? 0 : index]) << std::dec
                  << " mutex_size=" << sizeof(pthread_mutex_t)
                  << " wait_start_ns=" << result.wait_start_ns
                  << " acquired_ns=" << result.acquired_ns
                  << " application_wait_ns=" << elapsed
                  << " lock_ret=" << result.lock_ret
                  << " unlock_ret=" << result.unlock_ret << '\n';
    }
    // 每个工作线程应成功加锁并增加计数一次，因此两项总数都应等于线程数。
    const uint64_t total = std::accumulate(counters.begin(), counters.end(), uint64_t{0});
    passed = passed &&
             acquisitions == options.threads &&
             total == static_cast<uint64_t>(options.threads); //显式类型转换，options.threads是int
    //为什么既检查 acquisitions，又检查 total？
    // acquisitions：有多少工作线程成功获取了互斥锁。而 total ：所有受互斥锁保护的计数器实际增加了多少次。

    // 输出场景汇总；全部通过返回 0，否则返回 1。
    std::cout << "[MUTEX RESULT] scenario=" << options.scenario
              << " threads=" << options.threads
              << " acquisitions=" << acquisitions
              << " counter=" << total
              << " passed=" << passed << std::endl;
    return passed ? 0 : 1;
}

}

/*解析启动参数后执行场景，参数无效时打印运行方式并退出。*/
int main(int argc, char** argv)
{
    // 使用默认配置接收命令行参数，随后由 run() 执行并返回状态。
    Options options;
    if (!parse_options(argc, argv, options)) {
        std::cerr << "Usage: " << argv[0]
                  << " [--scenario contention|uncontended] [--threads 2..64]"
                     " [--hold-ms 20..1000] [--auto]\n";
        return 1;
    }
    return run(options);
}
