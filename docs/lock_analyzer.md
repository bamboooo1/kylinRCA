# Issue #22：LockAnalyzer 与 Lock RCA

## 本周上下文与实现范围

本次实现依据仓库根目录 `KylinRCA.pdf` 第 6 页的 W3 计划，以及
[Issue #22](https://github.com/bamboooo1/kylinRCA/issues/22) 的聚合、诊断和 JSON 验收要求。
截至 2026-11-19，本周相关进展如下：

- [PR #31](https://github.com/bamboooo1/kylinRCA/pull/31) 已于 2026-11-19 合入 main；
  当前本地代码已包含其中的 futex 探针、真实 mutex 场景和 Syscall PID 命名空间修复。
- [PR #29](https://github.com/bamboooo1/kylinRCA/pull/29) 和
  [PR #30](https://github.com/bamboooo1/kylinRCA/pull/30) 的 I/O 协议与采集代码已在本地。
- #22 在 #21 的已完成等待事件之上实现分析，不修改 BPF 事件协议。
  [#23](https://github.com/bamboooo1/kylinRCA/issues/23) 的自动复现与实采诊断验收、
  [#27](https://github.com/bamboooo1/kylinRCA/issues/27) 的交叉功能修改、
  [#28](https://github.com/bamboooo1/kylinRCA/issues/28) 的四模块集成仍应分别保留验证记录。

PDF 将统一 daemon 安排在 W4、统一 RCA Engine 安排在 W5，因此这里提供独立的
`LockAnalyzer` 和 `JsonReporter::report_locks()`，复用现有采集入口运行分析。
`kylinrca_lock_analysis` 静态库可供后续 daemon 直接链接。

## 数据链与解决思路

```text
lock.bpf.c：futex WAIT / WAIT_BITSET 结束
    -> RingBuffer：kylinrca_lock_event
    -> lock_probe_test.cpp：事件格式检查和原始输出
    -> LockAnalyzer::process()：校验、归窗、按 PID + lock_addr 聚合
    -> advance_window()：选择主要对象、触发或恢复诊断
    -> JsonReporter::report_locks()：逐行 JSON
```

实现分为四步：

1. 按 `(pid, lock_addr)` 分组。同一虚拟地址在不同进程中不合并；同一 TID 多次等待
   增加等待次数，但只计一个等待线程。
2. 使用事件的单调时钟结束时间归入固定窗口，计算合格等待的次数、去重线程数、
   累计、平均和最大耗时。报告只保留最近结算窗口，不累计保存所有历史地址。
3. 对每个对象应用线程数、平均耗时和最大耗时门槛，从满足规则的对象中选择累计
   等待耗时最大的一个作为主要竞争对象。相同时按 PID、地址排序，保证输出稳定。
4. 每个窗口重新判断。连续正常或空窗口达到恢复要求后输出 `NORMAL`，防止一次
   竞争永久留在告警中。退出时排空 RingBuffer，并结算不足一个完整窗口的尾部事件。

## 统计口径与默认规则

`LockAnalyzerConfig` 可由调用方构造时传入；默认值如下。

| 配置 | 默认值 | 用途 |
| --- | --- | --- |
| `window_ns` | 1 s | 窗口长度 |
| `minimum_wait_ns` | 1 ms | 成功调用达到此值才计入等待指标 |
| `minimum_waiting_threads` | 2 | 同一窗口、同一对象的不同等待 TID 数 |
| `average_wait_threshold_ns` | 10 ms | 平均等待门槛 |
| `max_wait_threshold_ns` | 50 ms | 最大等待门槛 |
| `recovery_windows` | 2 | 解除告警所需连续正常窗口数 |

触发 `LOCK_CONTENTION` 必须同时满足线程数、平均耗时和最大耗时门槛。
默认 `lock_test` 的 8 线程、主线程持锁 100 ms 场景适合验证这些默认阈值。
这些值是第一版经验阈值，后续应结合 Ubuntu 与 ARM64 的真实结果调整。

逐锁统计中：

- `event_count` 包括收到的所有有效事件。
- `wait_count`、`waiting_threads`、`waiting_tids`、`total_wait_ns`、`avg_wait_ns`、
  `max_wait_ns` 只包含 `ret == 0` 且耗时至少为 `minimum_wait_ns` 的调用。
- 短成功调用计入 `short_wait_count`；值不匹配、超时、中断和其他错误分别计入
  `eagain_count`、`timeout_count`、`interrupted_count`、`other_error_count`。
  超时可能确实发生过等待，但当前规则不将其视为成功等待的竞争证据。
- 顶层 `received_events`、`rejected_events`、`late_events` 是本次采集的累计计数；
  `processes` 是最近结算窗口的明细。

这里的 `lock_addr` 是 futex 等待地址，`wait_metric` 明确为
`completed_futex_wait_ns`。它不保证等于 `pthread_mutex_t` 的起始地址，耗时不是锁持有
时间，也不是完整 `pthread_mutex_lock()` 耗时。成功返回只说明 futex 等待返回，
不能据此确认已获得互斥锁。futex 还用于条件变量等同步结构，因此本规则给出等待
竞争信号；若要确认具体 mutex，应结合场景的 TID、对象范围及调用时间区间核对。

`waiting_threads` 表示窗口内发生过合格等待的不同线程数，不表示同时阻塞线程数。
当前协议只在等待结束时发事件，不能判断尚未结束的阻塞，也不能给出锁持有者。
`NORMAL` 表示窗口证据未满足本规则。

## 窗口与恢复

- 调用方应以 `CLOCK_MONOTONIC` 定期调用 `advance_window()`，即使本轮没有事件。
  采集入口每次 poll 后都会推进窗口。
- 窗口为左闭右开区间；正好位于边界的事件归入新窗口。跨窗口等待的完整耗时
  归入结束窗口，不按占用比例拆分，因此 `total_wait_ns` 也不是窗口内的阻塞占比。
- 同一未结算窗口内允许事件乱序。已经结算窗口的迟到事件不回写，计入
  `late_events`；无效格式或不可能的时间区间计入 `rejected_events`。
- 恢复观察期间仍可能输出 `LOCK_CONTENTION`，此时 `diagnosis.recovery_windows`
  大于 0。`diagnosis.evidence_window_start_ns/end_ns` 保留触发时的区间，
  不把旧证据标为当前窗口的数据。
- 连续两个正常完整窗口后，旧诊断及其对象清空；新异常会取消恢复计数。
- `flush()` 用于退出阶段的最终结算；再次开始采集前应 `reset()` 或重新构造分析器。

## 构建与无特权测试

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

新增 `lock_analyzer`、`lock_json_reporter`、`lock_probe_help` 三项 CTest。
合成事件测试覆盖去重、PID/地址隔离、主要竞争对象、八线程证据、短等待和各类返回码、
低竞争与空闲、恢复与重新触发、时间边界、迟到事件、跨窗口等待以及退出结算。
JSON 测试实际调用 C++ Reporter，再用 Python 标准解析器检查字段和 64 位地址精度。
测试使用显式检查，Release 构建不会因为关闭 `assert` 而省略验证。

2026-11-19 提交前复核：全工程 Debug 编译成功，CTest **12/12 通过**。
以下真实 BPF 采集由开发者在终端执行，结果通过保存的日志交叉核对。

## 2026-11-19 真实采集结果

| 检查项 | 竞争场景 | 无竞争对照 |
| --- | --- | --- |
| 场景 PID / 探针目标 PID | 75948 / 75948 | 77274 / 77274 |
| 工作线程 / mutex 数量 | 8 / 1 | 8 / 8 |
| 加锁次数 / 受保护计数 / passed | 8 / 8 / 1 | 8 / 8 / 1 |
| 原始等待事件数 | 11 | 2 |
| 目标 mutex 上匹配到的等待事件数 | 8 | 0 |
| 诊断 | LOCK_CONTENTION | 30 份窗口报告均为 NORMAL |
| 等待线程数 | 8 | 目标 mutex 上无等待事件 |
| 平均 / 最大合格等待耗时 | 105172964 / 109333505 ns | 目标 mutex 上无等待事件 |
| 恢复 | 连续两个正常窗口后恢复 NORMAL | 保持 NORMAL |

竞争对象地址为 `0x6312a9531020`，累计合格等待耗时为 `841383717 ns`。
8 个工作线程的 BPF 事件均匹配到目标 mutex，且每条等待区间均位于对应工作线程的
`pthread_mutex_lock()` 调用区间内。JSON 的线程集合、次数、累计、平均及最大值与
原始事件核算一致。

竞争诊断窗口为 `[347677000000000, 347678000000000)` ns；下一空窗口保留告警，
`recovery_windows=1`，证据时间仍指向原竞争窗口；再下一空窗口恢复 NORMAL 并清空
旧对象。另有 3 条原始事件来自主线程在其他地址上的等待，没有混入目标 mutex 的统计。

无竞争对照的 8 个工作线程使用不同 mutex，应用层加锁耗时为 218～1178 ns。
采到的 2 条 futex 等待均来自主线程，地址在目标 mutex 数组之外，分别约为
1.718 ms 和 0.729 ms，没有触发竞争规则。

两轮的 Map 更新失败、起点缺失、删除失败、RingBuffer 丢失、时间异常、用户态拒绝和
分析器迟到事件计数均为 0；完成等待数、接收数和原始事件记录数一致。

本轮源日志位置如下；竞争探针日志与带 retry 的场景日志属于同一轮，按 PID 75948 配对：

```text
/tmp/issue22-contention-retry-workload.log
/tmp/issue22-contention-probe.log
/tmp/issue22-uncontended-workload.log
/tmp/issue22-uncontended-probe.log
```

以上结果验证 #22 的竞争对象定位、指标输出、恢复及本轮无竞争对照；重复运行自动验收
脚本和多轮稳定性记录可在 #23 中继续完善。

## 真实事件诊断步骤

终端一启动场景，记下实际 PID，先保持等待输入：

```bash
./build/kylinrca_lock_test --scenario contention --threads 8 --hold-ms 100
```

终端二将 `12345` 替换为实际 PID：

```bash
sudo ./build/kylinrca_lock_probe_smoke --pid 12345 --duration 10 --analyze \
  | tee /tmp/kylinrca-lock-rca.log
```

看到 `[LOCK PROBE] ready` 后，在终端一按回车。程序保留原始 `[LOCK]` 记录，
同时每个结算窗口输出一行 `lock_summary` JSON，关键字段示意如下：

```json
{
  "type": "lock_summary",
  "diagnosis": {
    "type": "LOCK_CONTENTION",
    "pid": 12345,
    "lock_addr": "0x7f1234567000",
    "waiting_threads": 8,
    "avg_wait_ns": 103000000,
    "max_wait_ns": 108000000
  }
}
```

示例数值仅说明格式，不是本次实采结果。负载结束后，保持采集约 3 秒，观察恢复为
`NORMAL`。诊断是窗口报告，不能只读取日志最后一行判断是否曾经触发。

可提取报告查看状态与对象变化：

```bash
python3 - <<'PY'
import json
from pathlib import Path
for line in Path('/tmp/kylinrca-lock-rca.log').read_text().splitlines():
    if line.startswith('{'):
        report = json.loads(line)
        diagnosis = report['diagnosis']
        print(report['window_end_ns'], diagnosis['type'], diagnosis['pid'],
              diagnosis['lock_addr'], diagnosis['waiting_threads'])
PY
```

重新启动 `--scenario uncontended`，对新 PID 重复采集，检查没有持续竞争诊断。
同时核对原始事件、工作线程 TID、锁对象范围及 probe 丢失/错误计数。
保留 #21 的 `scripts/check_mutex_probe.py` 采集验收；其默认运行方式不启用分析，
不能替代 #22 的诊断验收。

#23 的 `scripts/check_lock_rca.py` 已提供多轮自动复现，核对目标竞争地址、JSON 指标、
正常对照和停止负载后的恢复。运行步骤与结果位置见
[锁竞争场景自动验收](lock_scenario_validation.md)。新一轮真实自动验收结果应单独记录，
不能用合成事件或历史日志回放代替。
