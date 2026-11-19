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
