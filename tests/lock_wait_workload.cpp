/*制造可核对的 futex 等待。
    覆盖普通等待、PRIVATE、BITSET、立即失败和超时，打印预期记录供验收脚本比较。
    默认等待回车后开始；--auto 用于不需要人工操作的 CTest。*/
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <time.h>

namespace {

/*执行一次等待，根据需要启动唤醒线程，并核对实际返回值是否符合预期。*/
bool run_wait(uint32_t& word, int operation, uint32_t expected,
              bool wake, int expected_ret)
{
    // 去掉附加标志，取得 WAIT 或 WAIT_BITSET 操作编号。
    const int command = operation & FUTEX_CMD_MASK;
    // 唤醒用例最多等待 1 秒，超时用例设置为 20 毫秒。
    const long timeout_ns = wake ? 1'000'000'000L : 20'000'000L;
    timespec timeout {};
    // WAIT 使用相对时长；WAIT_BITSET 先取得当前时间，再计算绝对截止时间。
    if (command == FUTEX_WAIT_BITSET && clock_gettime(CLOCK_MONOTONIC, &timeout) != 0)
        return false;
    timeout.tv_sec += timeout_ns / 1'000'000'000L;
    timeout.tv_nsec += timeout_ns % 1'000'000'000L;
    // 纳秒部分满一秒时，向秒字段进位。
    if (timeout.tv_nsec >= 1'000'000'000L) {
        ++timeout.tv_sec;
        timeout.tv_nsec -= 1'000'000'000L;
    }

    // 原子停止标志供两个线程安全读写；woken 在唤醒线程结束后读取。
    std::atomic<bool> stop {false};
    bool woken = false;
    std::thread waker;
    // 正常唤醒用例创建辅助线程，立即失败和超时用例不创建。
    if (wake) {
        waker = std::thread([&] {
            // 唤醒操作保留与等待操作相同的 PRIVATE 标志。
            const int wake_operation = FUTEX_WAKE | (operation & FUTEX_PRIVATE_FLAG);
            while (!stop.load()) {
                // 首次尝试可能早于主线程进入等待，因此每隔 1 毫秒重试。
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                const long result = syscall(SYS_futex, &word, wake_operation, 1, nullptr, nullptr, 0);
                // 返回 1 表示确实唤醒了一个等待者；负值表示调用失败。
                if (result == 1) {
                    woken = true;
                    break;
                }
                if (result < 0)
                    break;
            }
        });
    }

    // 主线程执行真正的 futex 等待；BITSET 使用允许任意标记匹配的参数。
    const long result = syscall(SYS_futex, &word, operation, expected,
                                &timeout, nullptr, FUTEX_BITSET_MATCH_ANY);
    // 用户态 syscall 失败时返回 -1 并设置 errno，转换为负错误码以便与 BPF 记录比较。
    const int actual_ret = result < 0 ? -errno : static_cast<int>(result);
    // 等待结束后停止辅助线程，并通过 join 等它彻底退出。
    stop.store(true);
    if (waker.joinable())
        waker.join();

    // 输出预期的身份、地址、操作、返回值及最低耗时要求，供验收脚本核对。
    std::cout << "[EXPECT] pid=" << getpid()
              << " tid=" << syscall(SYS_gettid)
              << " lock_addr=0x" << std::hex << reinterpret_cast<uintptr_t>(&word) << std::dec
              << " futex_op=" << operation
              << " ret=" << expected_ret
              << " min_duration_ns=" << (expected_ret == -ETIMEDOUT ? 15'000'000 : 0)
              << std::endl;
    // 返回值不符，或需要唤醒却没有成功唤醒时，本次测试失败。
    if (actual_ret != expected_ret || (wake && !woken)) {
        std::cerr << "Unexpected wait result: expected=" << expected_ret
                  << " actual=" << actual_ret << " woken=" << woken << '\n';
        return false;
    }
    return true;
}

}

/*解析参数，准备等待对象，再按指定轮数执行六种等待用例。*/
int main(int argc, char** argv)
{
    // 默认执行 3 轮并等待回车；--auto 跳过等待，--iterations 指定轮数。
    bool automatic = false;
    int iterations = 3;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--auto") {
            automatic = true;
        } else if (argument == "--iterations" && ++i < argc) {
            const char* end = argv[i] + std::strlen(argv[i]);
            // 轮数必须是完整、有效的正整数字符串。
            const auto parsed = std::from_chars(argv[i], end, iterations);
            if (parsed.ec != std::errc{} || parsed.ptr != end || iterations <= 0)
                return 1;
        } else {
            std::cerr << "Usage: " << argv[0] << " [--auto] [--iterations count]\n";
            return 1;
        }
    }

    // futex 等待对象为 4 字节对齐的 32 位整数，本程序始终保持其值为 0。
    alignas(4) uint32_t word = 0;
    // 先打印身份和对象地址，便于探针设置目标和验收脚本匹配事件。
    std::cout << "[WORKLOAD] ready pid=" << getpid()
              << " tid=" << syscall(SYS_gettid)
              << " lock_addr=0x" << std::hex << reinterpret_cast<uintptr_t>(&word) << std::dec
              << std::endl;
    // 人工测试时按回车开始；验收脚本则通过标准输入发送一行文字放行。
    if (!automatic) {
        std::cout << "Press Enter after the lock probe is ready." << std::endl;
        std::string command;
        if (!std::getline(std::cin, command))
            return 1;
    }

    // 每轮覆盖四种正常唤醒、期望值不匹配的 EAGAIN，以及无人唤醒时的超时。
    for (int i = 0; i < iterations; ++i) {
        if (!run_wait(word, FUTEX_WAIT, 0, true, 0) ||
            !run_wait(word, FUTEX_WAIT_PRIVATE, 0, true, 0) ||
            !run_wait(word, FUTEX_WAIT_BITSET, 0, true, 0) ||
            !run_wait(word, FUTEX_WAIT_BITSET_PRIVATE, 0, true, 0) ||
            !run_wait(word, FUTEX_WAIT_PRIVATE, 1, false, -EAGAIN) ||
            !run_wait(word, FUTEX_WAIT_BITSET_PRIVATE, 0, false, -ETIMEDOUT))
            return 1;
    }
    // 所有用例通过时返回 0。
    return 0;
}
