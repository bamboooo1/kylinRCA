# kylinRCA
Cross-architecture eBPF anomaly observability and root cause analysis agent for Linux

## Development Environment

KylinRCA is currently developed and tested on:

- Ubuntu 26.04 LTS
- WSL2 Linux Kernel 6.18+
- x86_64
- GCC 15+
- Clang/LLVM 21+
- CMake 3.16+
- bpftool 7+
- libbpf 1.6+

### 目录介绍
- src/：用户态核心代码，负责加载探针、处理事件、分析数据和输出结果。
- include/：头文件，定义接口和数据结构，部分由用户态与内核态共用。
- bpf/：运行在内核中的 eBPF 探针，负责采集系统调用、调度和锁等待等事件。
- scenarios/：制造实际场景，例如多个线程竞争同一把锁。
- tests/：检查模块或验证结果。
- scripts/：构建、环境准备和自动验收脚本，负责启动程序、收集并核对结果。

### Required packages

```bash
sudo apt install -y \
    git make cmake gcc g++ clang llvm \
    bpftool libbpf-dev libelf-dev zlib1g-dev pkg-config
```

### Generate vmlinux.h

The eBPF programs use BTF/CO-RE.
Generate the kernel type header with:

```bash
./scripts/gen_vmlinux.sh
```
The generated file is: bpf/include/vmlinux.h

vmlinux.h is generated from the target kernel BTF and is therefore not committed to the repository.

### Build

Configure:
```bash
cmake -S . -B build
```

BUild:
```bash
cmake --build build
```

## CPU 链路修复与验证

中文排查过程、原理、逐轮日志和学习日志模板见
[CPU 调试学习记录](docs/cpu-debug/README.md) 与
[实测结果](docs/cpu-debug/validation-results.md)。

```bash
ctest --test-dir build --output-on-failure
sudo python3 scripts/check_cpu_pipeline.py --label full
sudo python3 scripts/check_cpu_pipeline.py --label contention --oversubscribe
```

CPU 诊断新增 `runtime_valid`、`runtime_window_ns`、`runtime_uncertainty_ns`。
运行时间来自独立 BPF 累计快照差分；缺失快照不等于线程没有运行。

## W3 I/O Analyzer

设备窗口聚合、IO_LATENCY 和 JSON 输出的运行与验收见 [IoAnalyzer 报告](docs/io_analyzer_w3_report.md)。

## Lock 探针与真实互斥锁验证

基础 futex 用例与真实 `pthread_mutex` 竞争、无竞争对照可分别运行：

```bash
sudo python3 scripts/check_lock_probe.py
sudo python3 scripts/check_mutex_probe.py
```

真实互斥锁场景默认使用 8 个工作线程。完整运行步骤、采集口径和 JSON 日志位置见
[Lock 采集验证说明](docs/lock_probe_validation.md)。当前验证采集链路，不包含锁竞争诊断规则。

## LockAnalyzer 与竞争诊断

Issue #22 的窗口聚合、`LOCK_CONTENTION` 规则和 JSON 报告已接入现有 Lock 采集入口：

```bash
sudo ./build/kylinrca_lock_probe_smoke --pid 12345 --duration 10 --analyze
```

将 `12345` 替换为真实目标 PID。默认按 1 秒窗口统计同一进程、同一 futex 地址上的
成功明显等待，输出不同等待线程数、平均/最大耗时和主要竞争对象；连续正常窗口后恢复。
实现规划、阈值、统计口径、测试和双终端验证步骤见
[LockAnalyzer 与 Lock RCA](docs/lock_analyzer.md)。

## Lock 场景与诊断自动验收

Issue #23 的自动复现会取得负载 PID，挂好探针后放行线程，默认重复运行 3 轮
8 线程竞争和无竞争对照，并检查 JSON 指标、主要竞争对象及告警恢复：

```bash
sudo python3 scripts/check_lock_rca.py
```

每次执行会在 `/tmp/kylinrca-lock-rca-validation/run-*` 中保存独立的日志和结果。
实现规划、通过标准、历史结果回放与新一轮实采的区别见
[锁竞争场景自动验收](docs/lock_scenario_validation.md)。
