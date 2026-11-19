# W3 B 的第一个任务：Block I/O Probe 实现与验证报告

> 本文保留首次验收时的历史口径。2026-11-18 已修复 requeue 后重置时间与长度的问题；当前实现、计数器及验证限制见 [Review 修复报告](io_requeue_review_fix.md)。下文“最近一次 issue”和“requeue 删除记录”不再描述当前代码。

日期：2026-11-16（Asia/Shanghai）  
工作分支：`feat/io-probe`  
范围：内核采集、请求关联、原始事件传输及最小用户态验证；不包含 IoAnalyzer、P95/P99、IO_LATENCY RCA 或 fio 场景。

## 1. 结论

已完成当前 Ubuntu WSL2 x86_64 环境下的 I/O Probe。真实内核 BPF load/attach、隔离 loop 设备 direct I/O、并发、设备过滤、RingBuffer 溢出统计、信号退出与资源回收通过。Syscall、CPU、I/O 同时运行验证通过。

本报告不将编译通过等同于所有内核路径均已验证：部分完成、重排队、硬件错误等路径尚未在当前环境实际触发，详见第 7 节。

没有自动提交、push、创建或合并 PR。已合并的 `include/event.h` 保持不变。

## 2. 文件与阅读顺序

| 文件 | 作用 |
|---|---|
| `bpf/io.bpf.c` | raw tracepoint 采集、Hash 请求关联、延迟计算、RingBuffer 输出 |
| `include/io_probe_stats.h` | 设备过滤配置和错误/状态统计编号 |
| `tests/io_probe_smoke.cpp` | 检查运行内核 BTF 签名，加载和挂载 BPF，校验并打印事件，管理资源 |
| `scripts/check_io_probe.py` | 创建临时 loop 设备，执行有断言的特权集成验证并清理 |
| `CMakeLists.txt` | 新增 io_bpf 与 kylinrca_io_probe_smoke 构建目标 |
| 本报告 | 实现原理、复现命令、验证结果和限制 |

建议先读 `io_request_start`，再按 issue → complete → requeue 阅读 BPF 函数，最后看用户态的 receive、main 和清理过程。

## 3. 原理与明确的协议口径

### 3.1 数据路径

```text
block_rq_issue(rq)
  → 读取设备/操作/请求长度/起始扇区
  → io_starts[rq 地址] = 最近一次 issue 的信息与时间
block_rq_complete(rq, status, nr_bytes)
  → 查找开始记录
  → 部分完成：保留记录和首次非零错误
  → 最终完成：计算耗时、删除记录、输出 kylinrca_io_event
events RingBuffer
  → C++ 回调校验协议并打印
```

- `io_starts` 是跨 CPU 共享的普通 Hash Map，最多 16384 条在途记录。开始和完成可以发生在不同 CPU。
- `events` RingBuffer 为 256 KiB，采用默认自适应通知；用户态默认最多打印 20 条，避免逐条终端输出成为主要开销。
- 请求地址只作为内核内部关联键，不输出到用户态。
- 原始事件为 64 字节，C++ 用 static_assert 检查布局。
- PID/TID 都填 0：块层执行上下文不能可靠代表原始应用进程。
- operation 转换为项目已有的 IO_OP_READ/WRITE/OTHER，不直接发送内核操作编号。
- status 保留原始 blk_status_t 状态，0 表示成功，不冒充 errno。

### 3.2 延迟、部分完成与重排队

延迟定义为“最近一次 issue 到最终完成”。issue 之前的队列等待、此前失败尝试和重排队等待不在这个指标中。

当前 Linux 的 blk_update_request 在更新 bio 和剩余字节数之前触发 block_rq_complete。因此：

- 有 bio，且本次完成字节数小于当前剩余字节数：部分完成，保留开始记录。
- 没有 bio，或本次完成覆盖剩余字节数：按最终完成处理。
- 部分完成期间的首次非零 status 被保留，最终随事件发送。
- requeue 删除本次尝试，下一次 issue 重新计时；重复 issue 也会覆盖计时并增加 reissue 计数。
- 即使 RingBuffer 满了，最终完成的开始记录仍然删除，避免旧地址与新请求错误关联。

这里的口径是第一版工程取舍，不是“应用一次 read/write 的完整耗时”，也不是跨重试的完整请求寿命。

依据：
- [Linux v6.18 block tracepoint 定义](https://github.com/torvalds/linux/blob/v6.18/include/trace/events/block.h)
- [Linux v6.18 blk_update_request](https://github.com/torvalds/linux/blob/v6.18/block/blk-mq.c)

运行内核 BTF 已确认 issue/requeue 原始参数为 request 指针，complete 为 request 指针、1 字节状态、4 字节完成量。Loader 每次启动都会核对这些签名；缺少 BTF 或签名不兼容时明确拒绝挂载。CO-RE 负责字段偏移，不负责修复不同的 raw tracepoint 参数签名。

### 3.3 设备过滤与计数器

可用 `--device MAJOR:MINOR` 限定设备。使用 request → q → disk 的 major/first_minor，即整个磁盘/loop 设备编号；不是分区编号。

| 计数器 | 含义 |
|---|---|
| issue | 通过设备过滤的 issue 数 |
| complete | 找到开始记录的完成通知数，含部分完成 |
| partial | 部分完成次数 |
| requeue / reissue | 重排队清理 / 重复 issue 次数 |
| unmatched | 所有未找到开始记录的完成通知数 |
| map_update_fail / map_delete_fail | Map 操作失败 |
| ringbuf_drop | RingBuffer 满等原因导致 reserve 失败 |
| bad_timestamp | 结束时间早于开始时间 |
| read_fail | 读取内核字段失败 |
| emitted | 成功提交的最终事件数 |

重要：`unmatched` 还包含被设备过滤掉的请求及挂载前已在途的请求，不能直接解读为采集丢失。过滤负例中它不为零是预期行为。

## 4. 环境与构建

实际验证环境：

- Kernel：6.18.33.2-microsoft-standard-WSL2
- 架构：x86_64
- Kernel BTF：/sys/kernel/btf/vmlinux 可用
- 项目文件系统：ext4
- BPF 通过 clang 的 -Wall -Werror 构建
- 新增 C++ Probe 通过 -Wall -Wextra -Werror 构建

在项目根目录执行：

```bash
cmake -S . -B build
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

手动观察原始事件：

```bash
sudo ./build/kylinrca_io_probe_smoke --seconds 10 --max-print 20
# 指定设备时，先用 lsblk -o NAME,MAJ:MIN 确认整个设备编号。
sudo ./build/kylinrca_io_probe_smoke --seconds 10 --device 8:48
```

上面的 8:48 只是命令格式示例，以实际 lsblk 输出为准。设备没有真实 I/O 时可能没有事件，不能仅凭空输出判定失败。

支持 Ctrl+C / SIGTERM，退出时先销毁 links 停止生产，再消费尾部事件、读取统计并关闭对象。BPF 对象路径由 CMake 写入，程序不依赖调用时的工作目录；也可用 --object 指定路径。

## 5. 可复现的隔离验证

```bash
sudo python3 scripts/check_io_probe.py
```

依赖：Python 3、bpftool、losetup、BPF 权限和 loop 设备支持；无需 fio。

脚本只创建一个新的 64 MiB 临时镜像并关联空闲 loop，读写目标必须是本次 losetup 返回的 loop，完成后 detach 并移除临时镜像。无外部磁盘目标参数。常规失败通过 finally 清理；SIGKILL/机器断电等不可捕获退出仍可能需要手动清理。

初次建 loop 会触发系统分区/设备探测，所以测试先等待 udev settle；之后打开设备仍可能产生额外探测读。因此断言检查最低有效读写量，不把事件总数硬等同于应用 I/O 次数。

本机 dd 的 direct-read 报 EINVAL，但使用页对齐 mmap 缓冲区的 O_DIRECT + readv 成功。最终脚本使用 Python 对齐缓冲区执行 direct 读写，保留直接 I/O 语义。

原始日志位于 `build/io-validation/`（build 已被 gitignore）：

- `results.json`：集成验证断言结果及计数
- `verification-console.txt`：最终一次集成验证控制台记录
- `direct_read_write.txt`、`concurrent.txt`、`ringbuf_overflow.txt` 等：原始事件样本
- `coexistence-results.json`：三模块共存验证结果
- `regression-results.json`：已有模块加载回归和三次启停结果

## 6. 实际验证结果

最终一次集成验证在 Syscall 和 CPU 两个已有 Probe 同时运行的情况下通过。

| 用例 | 实测结果 |
|---|---|
| idle | 收到 0 条事件 |
| direct_read_write | 收到 298 条：170 读、128 写；总计 1716224 字节 |
| concurrent（四路） | 收到 1066 条：554 读、512 写；总计 4861952 字节 |
| filter_miss | 工作负载运行，但不匹配设备过滤，收到 0 条 |
| ringbuf_overflow | 暂停用户态消费，8234 次完成；成功提交并收到 3682 条，明确记录 4552 次丢事件 |
| invalid_seconds | --seconds 0 以状态 2 拒绝 |
| invalid_device | 非法设备参数以状态 2 拒绝 |
| missing_object | 缺失对象以状态 1 失败 |
| sigterm | 提前停止且状态 0 |
| resource_cleanup | 内核 RCU 回收后，本 Probe 程序 ID 集合恢复到启动前 |

以上正常读写和并发中：invalid、Map 更新/删除失败、时间戳异常、字段读取失败、RingBuffer 丢事件均为 0；完成后 pending 均为 0。故意溢出时 pending 仍为 0，说明丢事件不会遗留该批已完成请求的开始记录。

本环境中的并发用例 unmatched=8；过滤负例 unmatched=298，含非目标设备完成通知，不是错误计数。

其他回归：

- CTest：4/4 通过。其中前三项是已有 CPU Analyzer、CPU runtime window、JSON Reporter，第四项是新增 CLI help 启动检查；实际内核验证是上面的 10 项集成用例。
- C++17 toolchain、Syscall Analyzer smoke、proc CPU sampler smoke 通过。
- 已有 kylinrca_loader 和 kylinrca_cpu_probe_smoke：真实 load/attach/消费/信号退出通过。
- Syscall + CPU + I/O 共存运行通过，两个已有进程最终退出状态均为 0。
- I/O Probe 连续三次加载退出，内核 RCU 回收后无残留 I/O BPF 程序。
- 非 root 运行明确失败（退出 1），不会把加载失败报告为成功。

溢出用例验证的是“能明确统计丢事件并清理记录”，并不声称高负载永远不丢事件。上述次数是本轮数据，不是所有机器的固定预期值。

## 7. 未覆盖与后续工作

1. 本轮 loop 工作负载没有产生 partial、requeue 或 reissue，这些实现分支经过源码核对和 verifier 加载，但没有实际触发验证。硬件错误、Map 耗尽也未注入。
2. 未在 ARM64 / Raspberry Pi 验证；不宣称当前 Pi 缺少 BTF 的部署阻塞已解决。
3. 当前主流程只提供原始事件和采集健康统计；没有实现 IoAnalyzer、P95/P99、IO_LATENCY 或五类统一 daemon。
4. 不保证 PID 归属，不采集调用栈，不把设备延迟直接解释为硬件故障。
5. 没有收到最终完成或重排队的异常请求可能占用固定容量 Map，暂未实现超时扫描；容量耗尽会累计 map_update_fail。正常退出会随 BPF 对象销毁回收 Map。
6. WSL loop 结果证明关联与传输链路工作，不代表物理 SSD 延迟基准。未做长期稳定性或完整性能评测。
7. 协议不增加字段；后续若要报告重试次数、端到端请求寿命、进程归属等，需要重新约定协议。

## 8. 建议 Review 重点

- 计时口径“最近一次 issue → 最终完成”是否符合当前阶段需求。
- partial 完成判断是否与运行内核 blk_update_request 调用时机一致。
- 请求完成、重排队、reserve 失败的清理路径是否完整。
- PID/TID 未知语义、status 原始块层状态语义是否保持协议一致。
- 设备过滤按整盘编号、unmatched 计数范围是否清楚。
- 后续 Analyzer 应根据 ringbuf_drop/map_update_fail 判断证据完整性，不应默认为所有请求均已采集。
