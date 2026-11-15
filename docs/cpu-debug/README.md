# CPU 调度、线程身份与窗口统计修复学习记录

日期：2026-11-12。平台：Ubuntu / WSL2，6.18.33.2-microsoft-standard-WSL2，x86_64。
本轮基于 feat/cpu-rca 的 83167d3，在 fix/cpu-timing 上修改。没有自动提交或推送。

## 1. 最初现象与证据

用户第一次0中：`victim_max_runqueue_ns=18446744073709551606`。
该值等于 `2^64-10`，说明原本负 10ns 的差值进入 uint64_t 后下溢。
同时出现线程 CPU 接近 100%，但 `culprit_oncpu_ns=0`，以及约一秒窗口中显示
`culprit_oncpu_ns=4386727575`（约 4.39 秒）。

第一阶段只增加非法时间戳保护与内核计数。保护避免坏值进入诊断，但不能证明根因消失。
实际 45 秒测试（18 秒全核压力）收到 69580 条事件，运行时间倒序 0，
排队时间倒序 **187**，RingBuffer 丢失 0。原始日志在 records/baseline-protected.txt。

一个现场为：

```text
tid=162 ktid=162
start=28789418923898
end=28789418923888
check=28789418924550
```

这条记录说明 start 比旧 end 晚 10ns，但早于第二次取时 check。
它不能单独证明 namespace 是这一次负值的原因，也不能证明宿主机时钟一定有故障。

## 2. 排查顺序：先获得证据，再逐步收窄

1. 先加 `start > end` 检查，异常样本计数并限量打印，不允许巨值进入分析器。
2. 从 PERCPU_ARRAY 汇总所有 possible CPU 的计数。单纯 grep 没输出不能证明没有错误：
   tracing 可能未启用、被其他消费者读走，或者日志未捕获。
3. 检查身份口径：旧 wakeup 以 tracepoint 的内核 TID 写 Map，而 switch 取任务最深层
   namespace 的 TID 查 Map。同一编号不能在多个 namespace 之间直接比较。
4. 先统一内部 key、观测者 namespace 和 raw wakeup；保留 switch 原来的提前取时。
   30 秒验证中，15 秒全核负载的两个倒序计数都是 0，wakeup_miss 为 0。
   这是改进证据，尚不足以宣布完全修复。
5. 加严到两倍 CPU worker 的竞争场景，仍复现 **3 次**负的排队差值，分别为约 30、30、70ns。
   因此修复身份后仍存在取时顺序问题，不能把所有现象归结为 namespace。
6. 将排队的计算终点移动到复制 Map 起点之后；保留检查，不取绝对值、不截成零、不丢弃超大
   正数来伪装成功。运行片段仍采用同一次 switch 的共同边界。
7. 对最终版本运行重复压力、竞争、嵌套 PID namespace 和无特权回归，结果见 validation-results.md。

取时修复的含义是明确测量顺序：先得到本次使用的起点快照，再取得终点。
远端唤醒写入可能发生在 switch 入口取时之后，提前取时不适合与稍后读到的 Map 快照相减。
这个排队终点包含少量探针处理开销；它不是零开销的调度器内部时间。
本轮未对每一次旧错误都记录完整写入来源，因此不声称 187 次全都由一个原因造成。

## 3. 身份修复：内核关联与用户可见编号分开

旧实现的问题：

```text
wakeup：Map[初始 namespace 的 TID]
switch：Map[任务自己最深层 namespace 的 TID]
```

新实现：

```text
内部时间戳 Map key：task_struct.pid（初始 PID namespace）
生命周期：task_struct.start_boottime
输出 PID/TID：查找 numbers[] 中与观测者 namespace inode 相同的一层
```

用户态读取 `/proc/self/ns/pid` 的 inode，写入 namespace_config。
BPF 沿 task 的 pid->numbers[] 查找该 namespace，而不是默认选择最深的一层。
不属于观测者可见范围的任务跳过，避免宿主机或兄弟容器的编号污染当前 /proc。

wakeup 与 wakeup_new 改用 raw tracepoint 取得目标 task_struct，便于统一转换。
tracer 自过滤也使用同一套可见 TGID，/proc 热点排名同步排除 tracer。
临时 Map 和运行快照都检查 birth，防止数字编号复用。
任务释放时利用保存的内核 ID→可见 ID 回收状态，不依赖释放阶段仍有完整 thread_pid。

## 4. 为什么“100% 但运行时间为 0”

旧实现只在 switch-out 时提交一个完整运行片段。如果线程这一轮一直在 CPU 上，
它还没切下，用户态就没有收到新的完整片段；/proc 已经统计了它的运行。
此外，RingBuffer 延迟消费也会使两个窗口不同步。零事件不等于零运行。

新 runtime_map 保存：

```text
completed_ns：已切出的片段累计运行时间
running_since_ns：仍在运行的当前起点，未运行时为 0
birth_ns：任务生命周期
```

采样时：

```text
累计运行快照 R(t) = completed_ns + 当前运行尾部(t - running_since_ns)
窗口运行时间     = R(t1) - R(t0)
窗口时长         = t1 - t0
```

没有使用 `/proc 使用率 × 窗口` 来伪造 BPF 证据。两条数据流独立。
Hash value 在局部构造后通过 bpf_map_update_elem 整项发布，不原地逐字段修改。
内核官方文档说明 Hash 元素的更新是原子替换：
https://docs.kernel.org/bpf/map_hash.html

最初尝试用 bpf_spin_lock 保护值，但本机 verifier 明确拒绝：
`tracing progs cannot use bpf_spin_lock yet`。因此改成单任务调度路径串行更新、Hash 整项替换。
这次失败属于实际排查过程，不是当前代码仍有的加载错误。

## 5. 为什么一秒窗口曾显示 4.39 秒

原逻辑把“本轮收到的完整片段”全部计入本轮。一段跨越多个采样窗口的片段，
直到切出或延迟消费时才一起出现，就可能表现为先零、后数秒。

修复后，热点 on-CPU 证据只使用累计快照做差。原始完整事件仍用于生命周期 Summary，
但不能覆盖实时快照值。单元测试特意构造 4.39 秒的旧片段，验证它不会覆盖 1 秒快照结果。

读取 BPF Map 前后均记录 CLOCK_MONOTONIC，保留 lookup 耗时作为不确定度。
累计差值若超出窗口加读取不确定度，返回 invalid，而不是截断为窗口长度。
输出包含 runtime_valid、runtime_window_ns、runtime_uncertainty_ns。
读不到两个完整快照时明确无效，不能解释为“线程没有运行”。

## 6. /proc 与事件窗口的配套修改

- 每个线程记录自己的 CLOCK_MONOTONIC 读取时间，使用自己的前后间隔计算使用率。
- 读取 stat 第 22 字段 starttime，拒绝把复用后的 TID 与旧计数做差。
- BPF 挂载后重新建立初始基线，避免将加载前的 /proc 区间与加载后的 BPF 比较。
- runqueue 事件按 header.timestamp_ns 归属 `(window_start, window_end]`。
  迟到的旧事件不进入新窗口，未来事件暂存。
- 排队延迟是一次完整等待的延迟指标；on-CPU 是时间总量，两者不能用同一种聚合口径。
- 空间扫描仍不是原子操作，系统、线程、BPF 的读取时刻存在微小偏差，不要求完全相等。

## 7. 告警计数修正

高占用与排队压力分别累计并恢复。
`高占用 → 高占用且排队 → 高占用` 不再因为标签变化而重新累计高占用。
压力解除但使用率仍高时，可以回到 HighUsage；连续低负载后恢复 Normal。
缺失或坏的调度证据不能被当作一个正常压力样本。

## 8. 你可以照着做的复习练习

1. 在 cpu.bpf.c 画出 wakeup→runnable Map→switch-in→事件的路径，分别写出内部和输出 ID。
2. 用十进制算出 uint64 的 0-10，再与原始巨值比较。
3. 用 `[0.8s,1.3s]` 的运行片段解释旧窗口为什么错，再用累计快照做差演算。
4. 查一个线程的 stat，找 utime/stime/starttime；解释 tick、ns、实际秒数的区别。
5. 看 runtime_valid=0 与 runtime_ns=0 的区别：前者缺少证据，后者需要有效快照才能解释。
6. 人为把 test 中的 birth 改掉，理解为什么编号相同也不能直接相减。
7. 使用脚本在普通与嵌套 PID namespace 中验证同样代码，观察 worker 的编号变化。

## 9. 复现命令

```bash
./scripts/gen_vmlinux.sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build --output-on-failure
sudo python3 scripts/check_cpu_pipeline.py --label full
sudo python3 scripts/check_cpu_pipeline.py --label contention --oversubscribe
sudo unshare --pid --fork --mount-proc python3 scripts/check_cpu_pipeline.py --label nested
```

真实负载脚本约 32 秒：6 秒基线、15 秒压力、余下时间验证恢复。
输出 JSON 与完整日志默认写入 /tmp/kylinrca-cpu-validation，不保存密码。
脚本检查热点 PID 是否属于本轮真正的 stress-ng 子进程，而不只检查名称。

## 10. 已知边界与后续学习任务

- 本轮验证的是当前 WSL x86_64 内核，尚未证明 ARM64 或其他内核可用；raw sched_switch
  参数需按目标内核能力验证，不能将 CO-RE 理解为所有 hook 语义自动兼容。
- /proc tick 量化、读取顺序、探针开销、中断和虚拟化调度会造成两条使用率的微小差异。
- 开始时缺少双快照、新建/短命任务、Map 失败时允许显式 unavailable；不承诺所有时刻都有证据。
- 当前仍是基于规则的热点与压力诊断，不能证明某个热点线程直接造成某个受害线程等待。
- daemon、CPU JSON、长期性能与 ARM64 部署仍属于后续任务。
- 本轮连续负载验证不能代替数小时稳定性测试；出现新失败应保留计数并继续调查。

## 11. 学习日志模板

今日目标：修复 CPU 排队负值、身份关联和窗口运行时间。
现象：写出原始值与预期，不只写“运行异常”。
假设：身份不一致、提前取时、事件窗口错位，各自需要什么证据？
实验：记录测试条件、修改点、通过/失败与日志位置。
结果：引用 validation-results.md 的实测数字，保留曾失败的竞争场景。
收获：无符号下溢、namespace 身份、累计差分、生命周期、事件时间与接收时间。
不足：写出平台覆盖、非原子扫描、证据 unavailable 和长期测试尚未覆盖的范围。

## 12. 源码阅读索引

| 文件 | 本轮修改与阅读重点 |
|---|---|
| bpf/cpu.bpf.c | raw wakeup/switch、统一内部 key、取时顺序、运行累计、任务释放清理 |
| include/cpu_bpf_config.h | 将观测者 PID namespace inode 写入 Map |
| include/cpu_runtime.h | 内核/用户态共享快照布局、生命周期 |
| include/cpu_runtime_sampler.h | 当前运行尾部补偿、单调时钟、累计差分与有效性 |
| include/cpu_probe_stats.h | 共享探针计数编号 |
| src/proc_cpu_sampler.cpp | stat 第22字段、每线程读取时间、采样 hook |
| src/cpu_analyzer.cpp | 实时快照证据、排队事件按时间归窗、独立告警计数 |
| tests/cpu_rca_smoke.cpp | 配置→挂载→基线→采样→质量门控→退出与统计 |
| tests/cpu_runtime_smoke.cpp | 负例、跨窗、生命周期及状态机回归 |
| scripts/check_cpu_pipeline.py | 可复现的真实负载验收与 JSON 汇总 |

建议先看 validation-results.md 知道结果，再对照 records 的失败样本，最后按此表追踪代码。
