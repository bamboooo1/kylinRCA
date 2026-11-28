# W4 #40：I/O 接入统一 daemon

当前分支基于 main 的 d63ee5e（PR #47），对应
[Issue #40](https://github.com/bamboooo1/kylinRCA/issues/40)。
2026-11-26 按 Lock 的组织方式调整：daemon 直接调用 IoAnalyzer，
窗口推进和退出尾窗归分析器管理，移除了 IoPipeline。
公共配置保留 daemon 运行参数与模块开关，I/O 专用参数由 IoConfig 管理。
CPU、Lock 现也支持同样的独立模块配置，见[模块配置与验证](module_configuration.md)；
下文测试数量和实采记录对应 2026-11-26 的 I/O/配置阶段；当前 daemon 回归已整合到统一测试入口。

I/O 采集、公共分发、统计、JSON 和线程安全快照已实现。
Socket 的 status/top/report 已接入统一快照；正式 CLI 属于 #39，人工联调和 Review 仍按本轮实际结果验收。

## 职责与数据路径

~~~mermaid
flowchart LR
    B[I/O BPF 请求生命周期] --> R[公共 RingBufferConsumer]
    R --> Q[EventQueue]
    Q --> D[daemon 分析线程]
    D --> A[IoAnalyzer]
    A --> W[已结算的 IoReport]
    W --> D
    D --> J[JsonReporter 输出]
    D --> S[SnapshotStore 发布四模块快照]
    S --> U[UnixSocketServer 查询]
    H[主线程读取健康计数] --> Q
~~~

| 部分 | 职责 |
| --- | --- |
| IoAnalyzerConfig | 分析规则、容量、连续窗口条件和窗口长度 |
| IoConfig | 读取模块配置，分别保存分析规则与探针设备条件 |
| IoAnalyzer | 事件校验、窗口归属、设备聚合、持续告警、恢复、尾窗、运行累计计数 |
| daemon 的 analyze_events | 分发事件和时间通知，取走报告，调用 Reporter，发布快照 |
| IoSnapshot | I/O 状态数据，包含累计、健康信息和最近报告，不负责加锁 |
| SnapshotStore | 一次发布四模块查询结果，短暂加锁交换只读快照指针 |
| I/O 健康读取函数 | 从内核 map 汇总采集链路的累计计数 |

IoAnalyzer 不读取配置文件，不访问 BPF，不输出 JSON，不持有共享快照或输出回调。
daemon 对 I/O 和 Lock 都采用“处理事件、推进窗口、读取结果”的组织方式。
I/O 通过 take_reports 交出每个已结算窗口，保留跨过多个空窗口时的逐窗恢复证据；
report 提供最近一次报告供快照使用。调用方应在每次处理事件或时间通知后及时取走报告。

手动 finish_window 保留给原有指标回归，返回结果但不加入待输出列表；
daemon 和独立采集入口均使用 advance_window 与 flush。
结束边界的事件计入前窗，旧时间通知不使窗口倒退，迟到事件不改写已发布窗口。
退出尾窗标记 window_complete=false，不增加连续异常或恢复次数。

## 公共配置与模块配置

~~~bash
cmake -S . -B build/w4-io-refactor -DCMAKE_BUILD_TYPE=Debug
cmake --build build/w4-io-refactor -j 4
ctest --test-dir build/w4-io-refactor --output-on-failure
sudo ./build/w4-io-refactor/kylinrcad --config config/kylinrca.conf.example --io-config config/io.conf.example
~~~

| 入口 | 内容 |
| --- | --- |
| --config / AppConfig | 日志等级、Socket 路径、公共 window_ms、四模块开关 |
| --io-config / IoConfig | latency_threshold_us、min_samples、device |
| IoAnalyzerConfig | 保存分析规则；默认阈值 10ms，最低样本数 10 |
| I/O 探针配置 | 使用 IoConfig.device 设置设备过滤；省略表示所有设备 |

不传文件时使用默认值，显式文件缺失或字段非法时明确失败。
window_ms 仍由公共配置提供，daemon 与 Lock 一样转换后传给分析器；
模块文件不接收公共窗口、日志等级或模块开关。

模块文件示例：

~~~text
latency_threshold_us=10000
min_samples=10
# device=7:0
~~~

旧公共配置中的 io_threshold_us、io_min_samples、io_device 已不接受。
迁移为独立文件中的 latency_threshold_us、min_samples、device，
再通过 --io-config 传入；不会静默忽略旧字段。

## 运行和退出顺序

1. main 分别读取公共配置和模块配置，调用 run。
2. run 检查开关和 I/O BTF 参数兼容性，加载、配置、登记接收并挂载探针。
3. 建立 CPU 基线和初始快照，启动 Socket 接待线程与分析线程；主线程持续接收并复制四类事件入公共队列。
4. 分析线程直接调用 IoAnalyzer.process；分析器先结算必要前窗，再接受当前事件。
5. daemon 通过 take_reports 取走报告，输出 JSON，再将最近结果复制进共享快照。
6. 主线程定期发送包含 CPU 观测和 I/O 健康计数的 AnalysisTick，分析线程推进窗口。
7. 退出时先停止 Socket 接待，再 detach、消费尾部事件，再发送最终 Tick 调用 IoAnalyzer.flush，
   随后关闭队列并等待分析线程排空，最后输出 io_status。

原有 BPF 请求关联、partial complete、requeue/reissue 和释放清理代码未改动。
耗时仍从首次 issue 到最终 complete；I/O PID/TID 为 0，责任对象仍是设备。
四种事件使用独立类型，保留原有指标口径。

## JSON 与快照

标准输出是连续 JSON 文档流，包含原有三类 summary、io_summary、
周期及退出时的 io_probe_stats，以及退出时的 io_status。
Syscall 文档可能跨行，请用 jq 或 read_documents 逐份解析；运行日志写标准错误。

io_summary 保留样本数、bytes、读写/错误次数、平均/P95/P99、阈值、
窗口异常情况、持续诊断和迟到/无效/容量计数。
设备连续三个异常窗口触发 IO_LATENCY，连续三个正常或空窗口恢复。

include/io_snapshot.h 保留 IoSnapshot 数据和 io_snapshot_json 序列化。
分析线程在处理 AnalysisTick 后，把 I/O 的 enabled、counters、probe、report 与其他模块
一起交给 make_daemon_snapshot，再由唯一的 SnapshotStore 发布。
Socket 查询使用同一批只读快照；各模块保留自己的窗口边界，不直接读取 Analyzer。
退出 final tick 结算尾窗后，主线程从统一快照输出原有 io_status，保持历史报告字段。

status 返回四模块开关和事件计数；report.io 返回 io_status；top.io 按设备 P95 降序、
设备号升序排列，最多 10 项。协议及完整验收见 [Socket 查询说明](daemon_socket.md)。

健康计数包含丢失、map 操作失败、坏时间戳、读取失败、emitted、
partial、requeue/reissue、最大重排、释放清理和 pending。
unmatched 包含启动前在途和非目标设备通知，不直接等于丢失。
运行中 map 逐项采样，pending 为有上限的近似遍历；detach 后的最终值用于核对。

## 重构后验收

~~~bash
sudo python3 scripts/check_daemon.py --suite io --build build/w4-io-refactor --repeat 2 --output build/io-refactor-term
sudo python3 scripts/check_daemon.py --suite io --build build/w4-io-refactor --repeat 1 --sigint --output build/io-refactor-int
sudo python3 scripts/check_daemon.py --suite modes --build build/w4-io-refactor --output build/io-refactor-modes
~~~

复跑需使用不存在的新输出目录。每轮只对新建的 128MiB 镜像建立 loop 设备：
空闲 2.2 秒，叠加 6 秒 fio、CPU、8 线程锁竞争和指定 PID 的 Syscall 负载，
再空闲 7 秒观察恢复。退出时停止进程、解除关联并清理；解除失败保留镜像。

最终检查发现短时锁负载可能在 fio 初始化期间就结束。验收脚本现先等待目标设备出现真实 I/O 样本，
确认后再启动 CPU、Lock 和 Syscall 负载，并记录确认窗口和负载 PID；
报告窗口重叠检查仍保留，不以同时创建进程代替实际共存证据。
最终重跑记录见[最终核查](w4-io/records/2026-11-26/final-check/summary.json)。

验收通过独立 io.conf 显式使用 100μs、最低 10 样本，不改变产品默认 10ms。
复用 W3 独立状态机核对设备、指标、字节、三窗触发/恢复、emitted=received、
accepted+late=received，以及精确 Syscall/Lock PID 和 CPU/Lock/I/O 时间重叠。

2026-11-26，Ubuntu 26.04 / x86_64 / WSL2 Linux 6.18.33.2-microsoft-standard-WSL2：
干净 Debug 构建通过，CTest 23/23，三轮四模块实采和配置模式通过。

| 轮次 | 信号 | 接收/聚合样本数 | 迟到 | 已确认异常设备窗口 | 结果 |
| --- | --- | ---: | ---: | ---: | --- |
| 1 | SIGTERM | 57647 | 0 | 3 | 告警、恢复和清理通过 |
| 2 | SIGTERM | 57092 | 0 | 3 | 告警、恢复和清理通过 |
| 3 | SIGINT | 56420 | 0 | 3 | 告警、恢复和清理通过 |

三轮关键丢失与错误计数为 0，emitted 等于 received，最终 pending 为 0。
配置模式覆盖仅 I/O 默认 10ms、禁用 I/O 的三模块运行、全禁用非零退出。
回归覆盖配置边界与错误、公共配置拒绝模块字段、窗口边界、旧 Tick、迟到、
恢复、尾窗、重复 flush、累计计数和快照并发。

[2026-11-26 重构汇总](w4-io/records/2026-11-26/summary.json)记录本轮证据；
[2026-11-25 历史汇总](w4-io/records/2026-11-25/summary.json)保留旧实现证据，不代表当前源码。
记录均标识未提交工作树，基线 SHA 不等于实现提交。日志归档后缀改为 .txt，
配置中的绝对路径保留现场值，复跑时不要复用旧 loop 设备。

## 限制

- Socket/CLI 实际接入、A 独立联调和人工 Review 仍待完成。
- loop 未自然产生 requeue/partial complete，不能声称已实采重排；原有生命周期回归通过，计数保留。
- 本轮迟到为 0，拒收行为由确定性回归验证。
- 本任务不等于 #45 的 CPU/Lock 告警全套验收、Pi ARM64 和跨角色里程碑；本轮未验证 Pi。
