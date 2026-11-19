# I/O requeue Review 修复

日期：2026-11-18（Asia/Shanghai），分支 feat/io-analyzer。  
依据：https://github.com/bamboooo1/kylinRCA/pull/30#pullrequestreview-5958236586

## 两点修复

1. requeue 不删除 io_starts。再次 issue 保留首次观测时间，延迟变为首次观测 issue 到最终完成，含中间重排队等待，不含首次 issue 前的排队时间。
2. 再次 issue 不覆盖首次 bytes/sector、设备、操作及此前的第一个非零 status。部分完成判定仍使用 tracepoint 时当前 rq->__data_len，而不是首次 bytes。一次请求最终只产生一条事件。

公共 include/event.h 和 include/io_probe_stats.h 均未修改，事件仍为 64 字节。重排队次数不进入公共事件或每设备 JSON。

## 内部次数及生命周期

bpf/include/io_request_state.h 是新增私有状态/诊断定义，不是公共协议。每请求保存 requeue_count（饱和累计）和 awaiting_reissue，重下发清标记但不清历史。所有已存在记录的重复 issue 都不覆盖证据；未观察到先行 requeue 的重复 issue 单独累计 unexpected_reissue，不直接诊断故障。

新增私有 per-CPU Map io_lifecycle_stats，两个用户态入口在退出时汇总输出：

| STAT | 含义 |
|---|---|
| requeued_completed | 经历重排队并最终完成的请求数 |
| completed_requeues | 上述最终完成请求累计经历的 requeue 次数 |
| max_requeues | 最终完成请求的最大单请求 requeue 次数，跨 CPU 取最大值 |
| unexpected_reissue | 没有已观测 requeue 标记的重复 issue 次数 |
| release_cleanup | 请求释放时仍留有开始记录而被清理的次数 |

既有 requeue 是观测到的已跟踪请求 requeue 通知数；completed_requeues 按请求最终完成统计，两者在请求仍在途或释放未输出时不一定相等。完成统计在尝试写 RingBuffer 前更新，因此故意溢出时不等于用户态收到的事件统计。次数只提供诊断证据，不以某个次数自动判故障。

新增 kprobe/__blk_mq_free_request，在最后引用释放、tag 可复用前删除遗留记录，防止地址复用关联旧请求。该探针在 issue 之前挂载，逆序清理时最后卸载。内核批量完成路径先发最终 complete，状态已在该处删除。普通完成、字段读取失败和 RingBuffer 满仍保留既有清理行为。

依赖运行内核提供可探测的 __blk_mq_free_request；当前 WSL 内核可挂载。其他内核若符号缺失、kprobe 被禁用等会明确 attach 失败，不能无清理保护继续采集。不设置任意请求超时，避免误删合法长请求；真正一直未释放的请求可能占据固定容量 Map，满时累计 map_update_fail。对象销毁释放全部 Map。

内核依据：Linux v6.18 block/blk-mq.c 中 blk_update_request、__blk_mq_free_request、blk_mq_end_request_batch。block_rq_complete 在扣减长度前触发；最后引用释放后归还 tag，批量完成在归还 tag 前已通知完成。

## 验证及边界

```bash
cmake -S . -B build
cmake --build build -j8
ctest --test-dir build --output-on-failure
sudo python3 scripts/check_io_probe.py
sudo python3 scripts/check_io_analyzer.py
```

当前内核 6.18.33.2-microsoft-standard-WSL2：

- 构建通过（新增 BPF 编译仍为 -Wall -Werror）；CTest 7/7 通过。
- 新增原生生命周期测试直接调用 BPF 使用的私有状态转换函数：部分完成不 requeue、部分完成后重复三次 requeue/reissue、保留首次时间/8192 bytes/sector/错误、4096 对当前剩余4096的最终判定、未预期重复 issue、无 bio 和计数饱和。
- 原有十项真实内核 Probe 集成全部通过，包括 direct I/O、并发、过滤、故意溢出、信号和程序回收；新释放探针 load/attach 通过。
- fio 链路通过：79533 条有效事件，emitted=received，bytes=10414874624，pending=0；12 个窗口中 5 个触发 IO_LATENCY，末尾3个空闲窗口没有设备/残留告警。loop 敏感度阈值100us，默认仍为10ms。ringbuf_drop、Map 操作失败、read_fail、invalid 均为0。

真实 loop/fio 本次仍未产生 partial、requeue、unexpected_reissue 或 release_cleanup。因此上述特殊序列通过共享状态函数测试；不声称已在真实驱动路径完成重排队、错误注入或释放遗留记录的端到端验证。释放钩子的实际删除分支仍需后续受控内核注入验证，内核兼容性与长时间压力也未覆盖。

原始集成日志在 build/io-validation/ 和 build/io-analyzer-validation/，build 被忽略。没有提交、推送或回复 GitHub review。
