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
    bpftool libbpf-dev libelf-dev zlib1g-dev pkg-config \
    python3 stress-ng fio util-linux
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

Build:
```bash
cmake --build build
```

## W4 统一采集进程

构建后启动 `kylinrcad`，默认同时挂载 Syscall、CPU、Lock 探针：

```bash
sudo ./build/kylinrcad > /tmp/kylinrcad.json
```

可用 `--config config/kylinrca.conf.example` 设置模块开关、CPU 采样与
Lock 的窗口时长、日志等级。至少启用一个采集模块。采集结果写到标准输出，
运行日志走标准错误。
CPU 和 Lock 按窗口输出 `cpu_summary` 和 `lock_summary`，Syscall 在退出时输出
`syscall_summary`。各报告都是独立 JSON 文档，可用 `jq` 逐份读取。

看到 `[daemon] Ready` 后，可以在另一个终端用真实负载验证三条链路：

```bash
sh -c 'echo "Syscall PID=$$"; exec cat /proc/self/status >/dev/null'
stress-ng --cpu "$(nproc)" --timeout 12s &
./build/kylinrca_lock_test --scenario contention --threads 8 --auto
wait
```

等待几个窗口让告警恢复后，在 daemon 终端按 Ctrl+C。检查 Syscall 的目标
PID 统计、CPU 的热点与 runtime 有效性、Lock 的竞争 PID/地址及恢复。
SIGINT 和 SIGTERM 都会解除挂载、排空队列并等待分析线程退出。

### 查询运行中的 daemon（Issue #38）

daemon 在 `socket_path`（默认 `/run/kylinrca/kylinrca.sock`）接收
`status`、`top`、`report` 查询。分析线程每个窗口保存新快照，查询线程读取快照。
默认 Socket 权限为 `0600`；使用 `sudo` 启动 daemon 后，查询也使用 `sudo`。

保持上面的 daemon 运行，在另一个终端执行以下命令；把 `status` 改成 `top`
或 `report` 可以查询热点或已有分析结果。这段 Python 仅发送请求，不启动采集：

```bash
sudo python3 - status <<'PY'
import json, socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(3)
    connection.connect('/run/kylinrca/kylinrca.sock')
    connection.sendall((sys.argv[1] + '\n').encode())
    with connection.makefile('rb') as response:
        print(json.dumps(json.loads(response.readline()), indent=2, ensure_ascii=False))
PY
```

`top` 每模块最多返回 10 个热点，包含各自的窗口起止时间；首次窗口尚未完成时
相应结果为 `null`。`status` 的事件计数和窗口数应随运行继续增长。
协议、字段、排序、路径清理和本地验收步骤见 [Socket 查询说明](docs/daemon_socket.md)。

## W3 四模块整合验收

Syscall、CPU、Lock、I/O 的构建、运行顺序、通过标准和数据流见
[W3 四模块整合验收](docs/w3_integration_validation.md)。

2026-11-21 在最新 `main` 基线 `e694090` 完成 Debug 构建、CTest 18/18，
以及 Syscall、两种 CPU 压力、三轮 Lock 竞争与对照、三轮 fio/BPF 实采。
[本轮结果](docs/w3-integration/records/2026-11-21/summary.json)和原始记录已归档。
这轮按模块依次运行；双方已有互审记录，数据流讲解仍需双方确认。

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

I/O 默认按设备连续三个异常窗口触发 IO_LATENCY，连续三个正常或空窗口恢复。设备窗口聚合、JSON 输出的运行与验收见 [IoAnalyzer 报告](docs/io_analyzer_w3_report.md)。

## W3 fio 场景与重复验收

```bash
sudo python3 scripts/check_io_analyzer.py
```

默认在三轮独立临时 loop 设备上验证真实 I/O、IO_LATENCY 和空闲恢复；负载参数、环境与命令记录、结果位置及清理方式见 [fio 验收报告](docs/io_fio_w3_report.md)。

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
