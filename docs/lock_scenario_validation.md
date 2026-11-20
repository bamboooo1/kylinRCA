# Issue #23：真实锁竞争复现与自动验收

## 本周工作与本次范围

本次依据 `KylinRCA.pdf` 第 6 页 W3 计划和
[Issue #23](https://github.com/bamboooo1/kylinRCA/issues/23)：8 个线程竞争真实
`pthread_mutex`，稳定触发 `LOCK_CONTENTION`，并保留正常对照和验证结果。

截至 2026-11-20：

- #21 / [PR #31](https://github.com/bamboooo1/kylinRCA/pull/31) 的采集链路及
  `scenarios/lock_test.cpp` 已在本地，PR #31 已合入 main。
- #22 / [PR #33](https://github.com/bamboooo1/kylinRCA/pull/33) 已提供窗口分析和 JSON；
  PR #33 已于 2026-11-20 合入 main，当前功能分支已同步该提交。
- 本周 I/O 协议、采集及分析的 PR #29、#30、#32 已同步到本地；本次不修改 I/O 代码。

原有 `check_mutex_probe.py` 验证真实采集；#23 新增 `check_lock_rca.py`，把场景、
采集、JSON 告警、恢复和多轮结果串起来。沿用已有 C++ 场景，避免维护两份负载程序。

## 实现规划与验收对应

| 要求 | 实现 |
| --- | --- |
| 真实多线程 mutex 竞争 | `lock_test.cpp --scenario contention`，8 个工作线程共用一把锁 |
| 正常对照 | `--scenario uncontended`，每个工作线程使用独立的锁 |
| 稳定触发诊断 | 默认运行 3 轮，每轮分别验证竞争与对照，任何一例失败则总体失败 |
| 避免手填错误 PID | 从新启动的子进程取得 PID，核对负载与探针 ready 输出后才放行线程 |
| 主要竞争对象与指标正确 | 按原始事件、TID、mutex 对象范围、应用层时间区间核对 JSON |
| 告警恢复 | 负载结束后继续采集 4 秒，核对两个完整正常窗口及证据时间 |
| 保留结果 | 每次运行创建新目录，保存每轮两个场景的日志、JSON 和总体结果 |

运行顺序：

```text
启动 lock_test 并等待输入
    -> 取得当前负载 PID
    -> 用 --pid 和 --analyze 启动探针
    -> 确认探针 ready 且目标 PID 一致
    -> 放行负载，等待全部线程结束
    -> 继续采集 4 秒
    -> 正常停止探针，排空尾部事件
    -> 校验原始事件、窗口报告及采集计数
    -> 保存本例结果，继续下一例
```

## 默认参数与统计口径

- 8 个工作线程；竞争模式下主线程额外持锁 100 ms，工作线程取得锁后持锁 1 ms。
- 默认规则保持 #22 的配置：1 秒窗口；成功等待至少 1 ms；不同等待线程至少 2 个；
  平均等待至少 10 ms、最大等待至少 50 ms；连续两个正常窗口恢复。
- 脚本不降低诊断阈值。`--hold-ms` 支持 100～1000，保证默认复现负载具有明显等待。
- `--threads` 支持 8～64；验收 Issue #23 时使用默认的 8。
- 默认 3 轮，每轮包含竞争与对照，共 6 个独立场景。可用 `--rounds 10` 扩大样本。
- 按事件结束时间归窗。8 个线程可能分到两个窗口，验收不要求每份报告都有 8 个线程；
  要求原始记录覆盖全部 8 个工作线程，并且至少一个窗口正确触发诊断。
- futex 地址只要求位于 mutex 对象范围内，不假定它等于对象起始地址。
- 主线程在其他地址上的等待单独统计，不能混入目标 mutex 的竞争证据。
- 耗时表示已完成 futex 等待调用的耗时，不表示锁持有时间；线程数不表示同时阻塞数。

## 构建和无特权检查

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

新增 CTest：

- `lock_rca_validation`：校验验收逻辑及进程编排。覆盖错误 PID、坏 JSON、缺失线程、
  错误地址/指标、窗口遗漏、阈值变化、持续旧告警、非零退出码、提前退出和日志保留。
- `lock_rca_script_help`：确认验收入口可正常查看帮助。

也可单独运行：

```bash
python3 -B tests/lock_rca_validation_test.py
python3 scripts/check_lock_rca.py --help
```

这些测试不加载 BPF；模拟的进程编排结果不能作为新一轮实采证据。

## 一条命令进行真实验收

在具备 BPF 权限、内核 BTF 和所需 tracepoint 的 Ubuntu / WSL 终端执行：

```bash
sudo python3 scripts/check_lock_rca.py
```

脚本会自动配对 PID，不需要再开两个终端。默认运行通常约半分钟，具体取决于启动
和调度耗时。每例结束后打印轮次、场景、是否通过和日志目录；最后输出总体 JSON。
退出码为 0 表示所选场景全部通过，1 表示有失败，Ctrl+C 中断返回 130。

可以增加轮次或指定目录：

```bash
sudo python3 scripts/check_lock_rca.py --rounds 10 --threads 8 --hold-ms 100 \
  --build-dir build --output-dir /tmp/kylinrca-lock-rca-validation
```

只排查一种场景时可加 `--scenario contention` 或 `--scenario uncontended`。
完整验收应保留默认 `both`。

## 结果文件与通过标准

每次运行创建独立的 `run-*` 目录，不覆盖过去的结果：

```text
/tmp/kylinrca-lock-rca-validation/run-xxxx/
    results.json
    round-01/
        contention/
            workload.log
            probe.log
            reports.jsonl
            result.json
        uncontended/
            ...
    round-02/...
    round-03/...
```

`results.json` 中应为 `passed: true`，默认有 6 个 `cases`，每例也应通过。

竞争场景必须满足：

1. 全部工作线程成功加锁，受保护计数正确；每个线程有目标 mutex 上至少半个主线程
   持锁时长的成功 BPF 等待，等待起止位于对应应用层加锁调用区间内。
2. JSON 的逐锁计数、线程集合及耗时与原始事件重算结果一致，且使用默认阈值。
3. 新告警正确指出共享 mutex 和工作线程；恢复观察期间保留原证据时间。
4. 负载结束后经过两个完整正常窗口恢复 NORMAL，尾部有正常空窗口。

无竞争对照必须满足：独立 mutex、正确计数、目标 mutex 上没有匹配等待事件，
全部窗口保持 NORMAL。进程内可以出现主线程在其他地址上的 futex 等待。

两种场景均要求：PID 一致；报告连续；接收数与原始记录数及完成数一致；Map 错误、
RingBuffer 丢失、拒绝与迟到计数为 0。加载失败、没有 JSON、非零退出或观察时间不足
均判失败，并保留日志，不会用空数据宣称竞争验证成功。

## 本次已完成的验证

- 全工程 Debug 编译和 CTest 17/17 通过。
- 验收脚本自身的 21 项检查通过。
- 新校验逻辑完整回放了此前为 #22 保存的两轮真实手工采集，各有 30 份窗口报告：
  竞争 PID 75948，8 个目标等待线程，平均 105172964 ns、最大 109333505 ns，随后恢复；
  无竞争 PID 77274，目标 mutex 上无等待，全部报告 NORMAL。两轮采集健康计数为 0。
- 已将全部原始事件、工作线程记录及各自三个连续关键窗口保存到
  [结果样本](lock_rca_validation_results.json)，同时保存源日志 SHA-256。
  CTest 会再次核对这份样本，避免结果只存在于 `/tmp`。

上述历史样本标记为 `historical_capture_replay`，`fresh_bpf_capture=false`，保留作回归输入。

## 2026-11-20 三轮自动实采

开发者执行 `sudo python3 scripts/check_lock_rca.py` 后，生成了
`/tmp/kylinrca-lock-rca-validation/run-7qq8hydu`。提交前已重新读取六例原始日志，
核对 PID、目标 mutex、线程集合、调用时间区间、逐窗 JSON、恢复和采集计数。

环境：Ubuntu / WSL2，x86_64，内核 `6.18.58.1-microsoft-standard-WSL2`。
默认参数：3 轮、每轮竞争和对照、8 个工作线程、主线程额外持锁 100 ms，诊断阈值未降低。

| 轮次 | 竞争 PID | 目标等待线程数 | 平均等待 ns | 最大等待 ns | 恢复 | 对照 PID | 对照告警数 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 275568 | 8 | 105046537 | 109686716 | NORMAL | 275617 | 0 |
| 2 | 275667 | 8 | 106193249 | 108713474 | NORMAL | 275716 | 0 |
| 3 | 275764 | 8 | 104613085 | 108853590 | NORMAL | 275812 | 0 |

三例竞争均正确指出共享 mutex；每个工作线程都有匹配的成功长等待，JSON 指标与
原始事件重算结果一致。随后经过两个完整正常窗口恢复 NORMAL。
三例对照的目标 mutex 上均无匹配等待，全部窗口保持 NORMAL。
六例的加锁次数、受保护计数均为 8，负载和探针退出码均为 0；错误、丢事件、拒绝及
迟到计数均为 0。总体 `passed=true`、`interrupted=false`，六例全部通过。

本轮[总体结果及每例指标](lock-rca/records/2026-11-20/results.json) 已归档到仓库，
标记为 `automatic_bpf_capture`、`fresh_bpf_capture=true`。
同一目录保留了每例的 `workload.txt`、`probe.txt`，包含原始记录和全部窗口 JSON。
结果中的日志路径相对于该 `results.json`，同时保留原 `/tmp` 路径和 SHA-256，
便于 PR Review 时重新核对。
