#include "io_config.h"
#include <iostream>
#include <sstream>
#include <stdexcept>

// 判断配置规则是否满足预期，失败抛异常以使 CTest 返回非零。
void require(bool value) { if (!value) throw std::runtime_error("I/O config assertion failed"); }
// 确认指定文本被模块解析器拒绝；不会让非法值静默使用产品默认值。
void rejects(const std::string& text) {
    std::istringstream input(text);
    try { IoConfig::parse(input); }
    catch (const std::runtime_error&) { return; }
    throw std::runtime_error("invalid I/O config accepted: " + text);
}
// 验证模块默认值、显式覆盖、设备格式、边界、重复和读取错误，与公共配置测试分开。
int main() {
    try {
        std::istringstream empty("");
        const auto defaults = IoConfig::parse(empty);
        require(defaults.device.empty() && defaults.analyzer.latency_threshold_ns == 10000000 &&
                defaults.analyzer.min_samples == 10 && defaults.analyzer.window_ns == 1000000000);
        std::istringstream text(" # 模块配置\r\n latency_threshold_us = 100\r\nmin_samples=20\ndevice=7:12");
        const auto config = IoConfig::parse(text);
        require(config.device == "7:12" && config.analyzer.latency_threshold_ns == 100000 &&
                config.analyzer.min_samples == 20);
        std::istringstream maximum("latency_threshold_us=4294967295\ndevice=0:4294967295");
        require(IoConfig::parse(maximum).analyzer.latency_threshold_ns == 4294967295000ULL);
        for (auto key : {"latency_threshold_us", "min_samples"})
            for (auto value : {"0", "-1", "+1", "1.5", "100us", "4294967296"})
                rejects(std::string(key) + "=" + value);
        for (auto value : {"7", ":0", "7:", "-1:0", "7:0:1", "4294967296:0"})
            rejects(std::string("device=") + value);
        rejects("min_samples=10\nmin_samples=20");
        rejects("window_ms=1000");
        rejects("enable_io=true");
        rejects("device=7:0 # comment");
        rejects("min_samples=");
        rejects(std::string("device=7:\0", 10));
        std::istringstream broken("");
        broken.setstate(std::ios::badbit);
        bool failed = false;
        try { IoConfig::parse(broken); } catch (const std::runtime_error&) { failed = true; }
        require(failed);
        failed = false;
        try { IoConfig::load("/nonexistent/kylinrca-io.conf"); }
        catch (const std::runtime_error&) { failed = true; }
        require(failed);
        std::cout << "I/O module config passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
