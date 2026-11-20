# W3 B 第二个任务：IoAnalyzer 与 I/O RCA

日期：2026-11-17（Asia/Shanghai）  
分支：feat/io-analyzer  
任务：https://github.com/bamboooo1/kylinRCA/issues/25

## 2026-11-20：连续窗口触发与恢复

当前实现按设备维护持续诊断，替代下文历史版本的单窗口即时告警。默认完整窗口约 1 秒：

- 同一设备连续 3 个完整窗口满足“样本数 >= min_samples 且 P95 >= 阈值”，第三次结算才触发 IO_LATENCY。
- 触发后连续 3 个完整窗口不满足条件（含空窗口、样本不足窗口）才恢复。第一次、第二次仍保留告警。
- 正常窗口打断尚未触发的异常序列；恢复观察期再次异常会清零恢复计数。
- 设备之间独立计数。C++ 配置 alert_consecutive_windows / recovery_consecutive_windows 默认为 3，必须为正。
- finish_window 每次完整结算推进一次状态，不按跨度猜测多个窗口。调用方须定期结算；退出时不足整窗传 complete=false，仅输出数据，不改变连续次数。

JSON 的 devices 只保存当前窗口样本，新增 window_abnormal、abnormal_windows、recovery_windows；原 diagnosis 字段改为持续状态，前两次异常仍是 NORMAL，恢复前两次仍是 IO_LATENCY。

新增顶层 diagnoses，列出仍在告警的设备及其连续计数；即使 devices=[]，恢复期 diagnoses 也可能非空。因此不能再仅用 devices=[] 判断已恢复，应检查 diagnoses=[]。阈值与 window_complete 也输出到报告。

持续状态不复制旧窗口的延迟指标，避免历史证据被误标为当前数据。统计和状态共享 max_devices 上限；恢复或未触发序列中断后释放状态。底层 Probe、事件协议、延迟口径及默认 10 ms 阈值保持原有定义。

“连续三次”过滤短时波动，同时增加约数个窗口的确认延迟；空窗口只代表没有收到完成样本，不能证明所有在途请求都正常。采集健康仍需结合 Probe 计数判断。

以下“实现及口径”和“实际验收”保留 #25 初始单窗口版本的历史记录；当前验收见 fio 报告的状态机更新段。

## 实现及口径

新增 include/io_analyzer.h、src/io_analyzer.cpp、src/io_json_reporter.cpp、tests/io_rca_smoke.cpp。
JsonReporter 增加 report_io，原有 syscall 报告保持原接口。
诊断入口复用第一任务的 BTF 签名检查、设备过滤、BPF 挂载和清理流程；不修改公共事件协议及 BPF Probe。

按设备 major:minor 聚合每个窗口内的完成事件。输出样本数、请求 bytes、读写次数、错误数、平均/P95/P99 延迟（纳秒）。设备键按数值排序。平均数向下取整；分位数使用 nearest-rank：排序后 ceil(p*N) 对应的样本，不插值。错误完成也保留为延迟样本，单独累计 error_count。

默认每约 1 秒生成窗口报告；设备至少 10 个样本且 P95 >= 10ms 时诊断为 IO_LATENCY。阈值和最低样本数可配置，报告记录实际配置。每次报告后清空聚合；空窗口 devices=[]，不会携带旧告警。单个慢请求不满足默认样本门槛。尾部短窗口也输出，以实际 window_start_ns/window_end_ns 为准。

窗口使用单调时钟，与 BPF ktime 同一时间域。process 的事件必须先于调用方 finish_window 的截止时间；生产入口先 poll，再读取截止时间。迟到的已关闭窗口事件计入 late_events 并拒绝，避免污染新窗口。不是追溯重算历史窗口的实现。

每窗口最多 128 个设备、每设备 100000 个样本、全窗口 100000 个样本；超容量明确累计 capacity_drops，所有指标基于接收的样本。窗口清空后释放样本存储。invalid_events 和 late_events 分别记录协议错误及迟到事件。Probe 的 ringbuf_drop、Map 失败等独立输出到 stderr；分析报告不是无损采集保证，判断完整性时应同时检查该健康日志。

2026-11-18 Review 修复后，延迟为首次观测到的 block issue 到最终 complete，包含其间 requeue 等待；bytes/sector 保留首次观测值。不含首次 issue 前等待。详见 [Review 修复报告](io_requeue_review_fix.md)。PID 未知，不归因应用进程；设备延迟告警不等价于硬件故障。

## 构建与运行

```bash
cmake -S . -B build
cmake --build build -j8
ctest --test-dir build --output-on-failure
sudo ./build/kylinrca_io_rca_smoke --seconds 10
# 可选 --device MAJOR:MINOR --window-ms 1000 --threshold-us 10000 --min-samples 10
# stdout 为 JSON Lines，stderr 为 READY、Probe 健康统计和错误信息。
sudo python3 scripts/check_io_analyzer.py
```

最后一条需要 fio、losetup、内核 BTF 和 BPF 权限。脚本只读写本次新建 128MiB 临时镜像关联的 loop；无外部磁盘参数，finally 终止监控进程、detach loop 并删除镜像。不可捕获中止仍可能需要手动清理。

## 实际验收

Ubuntu WSL2；构建及 CTest 6/6 通过。单测覆盖设备隔离、bytes、错误、均值、已知 P95/P99、阈值及最小样本、空窗恢复、迟到/非法事件、设备和样本容量限制、非递增窗口拒绝。

真实 fio 使用 libaio、direct=1、randwrite、128KiB、iodepth=64、4 秒。虚拟 loop 验收显式配置 100us 阈值、最低 10 个样本；这验证配置下的触发链路，不声称默认 10ms 在所有虚拟设备都必然触发。

本轮设备 7:0：12 个报告窗口中 5 个设备窗口触发 IO_LATENCY；末尾连续 3 个窗口 devices=[]。收到 78275 条有效事件，10249986048 bytes；Probe emitted 与 received 相等。ringbuf_drop、map_update_fail、map_delete_fail、bad_timestamp、read_fail、invalid 均为 0，pending=0。unmatched=403，按 Probe 原有语义含过滤范围外和挂载前完成事件，不能直接当作丢失。

一个触发窗口：sample_count=11645，avg_duration_ns=3496350，p95_duration_ns=7309782，p99_duration_ns=10371176，bytes=1521496064。

原始验收产物：build/io-analyzer-validation/{reports.jsonl,probe.log,fio.json,results.json}。该目录在忽略的 build 内。脚本断言真实触发、报告指标、末尾空闲、零容量丢弃及零 RingBuffer/Map 更新失败。

尚未在物理 SSD、ARM64 或长时间生产负载上验证。此任务没有实现跨模块集成、统一 daemon 或其他 W3 issue；没有自动提交、推送或修改 GitHub issue。

## 事件校验职责更新

RCA 回调只检查原始记录长度并复制数据；版本、类型、声明长度、当前 Probe 的 PID/TID=0 约定、操作范围和时间合理性统一由 IoAnalyzer 校验。process_detailed 返回 Accepted/Invalid/Late/CapacityDropped，process 保留原 bool 接口并调用同一处理逻辑。Consumer 的 received/reads/writes/bytes 统计格式有效的接收事件（含迟到或超容量事件），窗口设备统计只包含 Accepted；invalid 是整次运行的原始长度错误和内容非法总数，窗口 invalid_events 只统计到达 Analyzer 的内容非法事件。--max-print 只限制原始调试行数，默认0，不限制采集、分析或窗口 JSON。

## #26 场景入口更新

`check_io_analyzer.py` 现默认执行三轮并创建独立输出目录，采用 `scenarios/io_latency.fio`。复现步骤和清理记录见 [fio 验收报告](io_fio_w3_report.md)。上文原始数据及 build/io-analyzer-validation 路径属于 #25 历史验收。
