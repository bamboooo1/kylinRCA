# W3 四模块整合验收

任务：[#28](https://github.com/bamboooo1/kylinRCA/issues/28)。日期：2026-11-21，Asia/Shanghai。

在已合入 Lock、I/O 及各自场景的同一份代码上，重新构建并依次验证 Syscall、CPU、Lock、I/O。
本轮由用户在真实内核执行；本文根据本轮原始日志和结果文件核对，未把历史回放当作新的实采。

## 基线、环境与结论

| 项目 | 本轮记录 |
| --- | --- |
| Git 提交 | `e694090a30b2d51e357651ff255708259cec837e`，核对时与 GitHub 最新 `main` 一致 |
| 验收分支 | `feat/w3-integration`，开始验收时工作区干净 |
| 环境 | Ubuntu 26.04.1 LTS / WSL2，x86_64 |
| 内核 | `6.18.58.1-microsoft-standard-WSL2` |
| 构建类型 | Debug；从当前内核 BTF 重新生成 `vmlinux.h` |
| 负载工具 | fio 3.41；util-linux 2.41.3；CPU 使用 stress-ng |
| 原始目录 | `/tmp/kylinrca-w3-nYsGQb` |
| 仓库归档 | [2026-11-21 实采记录](w3-integration/records/2026-11-21/README.md) |

| 检查 | 结果 |
| --- | --- |
| CMake 配置及全工程构建 | 通过，四类 BPF 对象和用户态入口均构建完成 |
| CTest | 18/18，通过，含 `io_fio_validation` |
| Syscall | PID/TID、自过滤及 loader 最终读写统计均通过 |
| CPU | 全核压力、两倍 worker 竞争均通过；空闲基线与尾部恢复正常 |
| Lock | 三轮竞争、三轮无竞争对照，共六例全部通过 |
| I/O | 三轮 fio/BPF 全部通过，告警恢复及临时资源清理通过 |

完整汇总见 [summary.json](w3-integration/records/2026-11-21/summary.json)。
技术回归通过；Issue 中“双方能解释对方模块的数据流”仍需双方实际确认。

## 运行准备与构建

在仓库根目录执行。首次准备环境时安装以下依赖，已有的无需重复安装：

```bash
sudo apt install -y git make cmake gcc g++ clang llvm \
    bpftool libbpf-dev libelf-dev zlib1g-dev pkg-config \
    python3 stress-ng fio util-linux
```

后续命令在同一个 Bash 终端运行。按模块依次验收，前一步失败先查看日志。
`pipefail` 使日志管道保留失败状态；BPF 实采需要相应权限。

```bash
set -o pipefail
W3_RUN=$(mktemp -d /tmp/kylinrca-w3-XXXXXX)
echo "本轮结果目录：$W3_RUN"
git status --short --branch | tee "$W3_RUN/git-status.txt"
git rev-parse HEAD | tee "$W3_RUN/commit.txt"
uname -a | tee "$W3_RUN/kernel.txt"

bash scripts/gen_vmlinux.sh 2>&1 | tee "$W3_RUN/vmlinux.log"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
    2>&1 | tee "$W3_RUN/configure.log"
cmake --build build -j2 2>&1 | tee "$W3_RUN/build.log"
ctest --test-dir build --output-on-failure 2>&1 | tee "$W3_RUN/ctest.log"
```

当前基线预期 18 项 CTest 全部通过。更新源码后先重新配置 CMake，避免旧构建目录漏登记新测试。
CTest 包含分析器、报告、验收判断逻辑、场景及帮助入口测试，不加载 BPF；
`io_fio_validation` 核对脚本判断逻辑，真实 fio 采集由下文独立执行。

## Syscall：身份、自过滤和最终 JSON

先检查 PID/TID 与采集进程自过滤：

```bash
sudo ./build/kylinrca_syscall_pid_test \
    2>&1 | tee "$W3_RUN/syscall-pid.log"
```

应出现 `identity=PASS matched_calls=6` 和
`self_filter=PASS excluded_calls=6 child_calls=2`。

终端一启动 loader，等出现 `Collecting syscall events...`：

```bash
sudo ./build/bpf_loader 2>&1 | tee -i "$W3_RUN/syscall.log"
```

终端二执行真实读写，打印并记住本轮 PID：

```bash
python3 -c '
import os
read_fd, write_fd = os.pipe()
print("测试进程 PID：", os.getpid(), flush=True)
for _ in range(100):
    os.write(write_fd, b"x" * 64)
    assert os.read(read_fd, 64) == b"x" * 64
os.close(read_fd)
os.close(write_fd)
input("先停止采集并检查最终 JSON，再按回车退出。")
'
```

保持终端二进程存活，在终端一按 Ctrl+C，等待最终 JSON 输出和 detach。
`tee -i` 保留退出时的报告。按测试 PID 检查 `read`、`write` 各不少于 100 次、
各自 `error_count=0`，并确认 tracer PID 不在 `processes` 中。完整提取步骤见
[Syscall PID 验证](syscall_pid_validation.md)。检查后才在终端二按回车。

本轮测试 PID `600135`；tracer PID `599997` 未出现在报告中，退出完成 detach：

| 调用 | count | error_count | 平均耗时 ns | 最大耗时 ns |
| --- | ---: | ---: | ---: | ---: |
| read | 133 | 0 | 1910 | 83927 |
| write | 102 | 0 | 805 | 26955 |

Python 初始化和标准输入输出会增加调用数，因此不要求恰好 100。
以上是目标进程读写的结果，未将全系统其他调用的错误数混入此用例。
提取结果见 [syscall-check.json](w3-integration/records/2026-11-21/syscall-check.json)，
完整 loader 日志已压缩归档。

## CPU：全核压力和超额竞争

两条命令依次运行，每条约 32 秒：

```bash
sudo python3 scripts/check_cpu_pipeline.py --label full \
    --output-dir "$W3_RUN/cpu" 2>&1 | tee "$W3_RUN/cpu-full.console.log"
sudo python3 scripts/check_cpu_pipeline.py --label contention --oversubscribe \
    --output-dir "$W3_RUN/cpu" 2>&1 | tee "$W3_RUN/cpu-contention.console.log"
```

两份 JSON 均须 `passed=true`、`errors=[]`。脚本核对热点属于本轮真实 worker、
BPF 运行时间有效且不超过窗口加读取不确定度、与 `/proc` 使用率差不超过 15 个百分点，
负载开始后 10 秒内告警，前后三个采样点均正常。

| 场景 | worker 数 | 报告数 | 热点样本 | 告警延迟 s | 热点 BPF 使用率范围 | 与 proc 最大差值（百分点） |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| full | 8 | 30 | 13 | 3.818 | 97.90%～99.97% | 1.15 |
| contention | 16 | 30 | 11 | 3.435 | 49.52%～79.92% | 1.34 |

本轮探针报告的计数均为 0，包含时间倒序、Map 更新失败和 RingBuffer 丢失。
原始报告与结果见 [cpu/](w3-integration/records/2026-11-21/cpu/)。

## Lock：三轮竞争与无竞争对照

```bash
sudo python3 scripts/check_lock_rca.py --output-dir "$W3_RUN/lock" \
    2>&1 | tee "$W3_RUN/lock.console.log"
```

默认 3 轮、8 个工作线程，主线程额外持锁 100 ms，诊断阈值沿用产品默认值。
每轮竞争需覆盖全部工作线程、定位共享 mutex，逐窗口指标与原始事件相符，
连续两个完整正常窗口后恢复。每轮无竞争对照应保持 NORMAL。
六例均须通过，总体 `passed=true`、`interrupted=false`。

| 竞争轮次 | PID | 匹配线程数 | 平均等待 ms | 最大等待 ms | 恢复 |
| --- | ---: | ---: | ---: | ---: | --- |
| 1 | 603164 | 8 | 104.542 | 108.850 | 是 |
| 2 | 603267 | 8 | 104.787 | 109.223 | 是 |
| 3 | 603369 | 8 | 104.405 | 108.352 | 是 |

三轮对照 PID 为 `603216`、`603318`、`603420`，目标 mutex 匹配等待均为 0，
全部窗口正常。其 `recovery_observed=false` 表示从未告警，没有恢复过程。
六例 workload/probe 退出码均为 0，Map 错误、丢事件、拒绝和迟到计数均为 0。
完整结果见 [Lock results.json](w3-integration/records/2026-11-21/lock/run-zuyudpoe/results.json)。

## I/O：三轮 fio、持续告警与清理

```bash
sudo python3 scripts/check_io_analyzer.py --repeat 3 --output "$W3_RUN/io" \
    2>&1 | tee "$W3_RUN/io.console.log"
```

`io` 输出目录须尚不存在。脚本每轮新建 128 MiB 临时镜像和 loop 设备，挂好探针后，
使用 libaio、direct I/O、128 KiB 随机写、iodepth=64，持续负载 4 秒。
设备编号可在清理后复用，本轮三轮均为 `7:0`。

loop 验收显式使用 P95 >= 100 μs、窗口样本数 >= 10；产品默认阈值保持 10 ms。
三个连续完整异常窗口才触发，三个连续正常或空窗口才恢复。
判断持续告警看顶层 `diagnoses`，不能仅凭 `devices=[]` 判断已恢复。

| 轮次 | 接收事件 | 已聚合样本 | 显式迟到 | 聚合 bytes | 有样本告警窗口 | 含恢复期告警窗口 | 清理 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 106228 | 106228 | 0 | 13913841664 | 3 | 5 | 完成 |
| 2 | 87349 | 87348 | 1 | 11439202304 | 3 | 5 | 完成 |
| 3 | 77193 | 77193 | 0 | 10108166144 | 3 | 5 | 完成 |

每轮末尾三个报告均无设备样本和持续告警。fio job 均成功，临时镜像已删除。
RingBuffer/Map、时间和读取错误为 0；Consumer invalid/pending 和 Analyzer
invalid/capacity_drops 为 0；Probe emitted 与 Consumer received 一致。

第二轮有 1 条显式迟到，`87348 + 1 = 87349`，符合现有规则。
该事件未计入窗口聚合，Consumer bytes 为 `11439333376`，比聚合 bytes 多 `131072`。
迟到已单独计数，未将其描述成零迟到，也未通过修改阈值消除这一记录。
三轮 unmatched 为 10、27、61，按现有语义包含挂载前完成或过滤范围外事件，
不直接按传输丢失判定。规则和限制见 [fio 报告](io_fio_w3_report.md)。
原始 JSON、Probe 计数、fio 输出和清理记录见 [io/](w3-integration/records/2026-11-21/io/)。

## 双方互审与数据流

GitHub 已存在双向 Approved：

| 模块 | 审阅人 | 记录 |
| --- | --- | --- |
| I/O 场景与持续状态 | bamboooo1 | [PR #34 Approved](https://github.com/bamboooo1/kylinRCA/pull/34#pullrequestreview-5993071198) |
| Lock 场景自动验收 | cyyc03 | [PR #35 Approved](https://github.com/bamboooo1/kylinRCA/pull/35#pullrequestreview-5992733330) |

可沿下面的文件顺序讲解数据流。Python 脚本负责启动负载、管理采集程序和核对结果；
实际的事件消费与分析在 C++ 中执行。

| 模块 | 实际数据流 | 讲解要点 |
| --- | --- | --- |
| Syscall | `bpf/syscall.bpf.c` → `src/ring_buffer_consumer.cpp` → `src/event_queue.cpp` → `src/syscall_analyzer.cpp` → `src/json_reporter.cpp`；由 `src/bpf_loader.cpp` 组织 | enter/exit 如何配对；PID/TID 如何转换；按 PID、调用编号统计并输出 |
| CPU | `bpf/cpu.bpf.c` 的事件和 runtime_map → `tests/cpu_rca_smoke.cpp`；结合 `src/proc_cpu_sampler.cpp` → `src/cpu_analyzer.cpp` → 文本诊断 | 调度事件与运行快照的用途；独立 proc 使用率；有效窗口、不确定度、告警和恢复 |
| Lock | `scenarios/lock_test.cpp` → futex → `bpf/lock.bpf.c` → `tests/lock_probe_test.cpp` → `src/lock_analyzer.cpp` → `src/lock_json_reporter.cpp` | PID/地址/TID 如何匹配；等待如何归窗；主要竞争对象及恢复依据 |
| I/O | `scenarios/io_latency.fio` → 块请求 → `bpf/io.bpf.c` → `tests/io_rca_smoke.cpp` → `src/io_analyzer.cpp` → `src/io_json_reporter.cpp` | issue/complete 如何关联；requeue 保留什么；设备聚合、P95/P99、连续触发和恢复 |

互审记录能够在 GitHub 核对；双方能否独立复述、定位和修改对方数据路径，需双方实际确认。
自动回归与本文的数据流表不替代这一确认。

## Issue #28 验收状态与范围

- [x] Lock 和 I/O 及场景已合入基线 main（PR #33、#34、#35）。
- [x] 补齐统一构建、运行文档和可追溯的实采记录。
- [x] 基线代码可构建，18 项 CTest 通过，四类模块真实回归通过。
- [x] 双方互审有 Approved 记录。
- [ ] 双方确认能够解释对方模块的数据流，合并前补充确认结果。

本轮按模块顺序验收，未进行四类采集程序同时运行的共存测试。
统一 daemon、EventQueue/worker 重构与 Unix Socket 属于 PDF 的 W4 计划。
本轮未验证 ARM64、物理 SSD、长期稳定性；I/O 的 partial/requeue/release_cleanup
等特殊分支本轮实采未触发，仍依赖已有状态转换测试覆盖。
