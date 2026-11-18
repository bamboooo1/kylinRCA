# pthread_mutex 竞争采集验证

该验证对应 Issue #21 的真实竞争采集要求。程序直接调用 `pthread_mutex_lock()` /
`pthread_mutex_unlock()`，不直接调用 futex，也不修改互斥锁的内部字段。

本阶段验证事件采集，不输出 `LOCK_CONTENTION` 诊断，不代表完成 Issue #22 或 #23。

## 场景

- `contention`：默认 8 个工作线程共用一把 `PTHREAD_MUTEX_NORMAL` 锁。主线程先持锁，
  等所有工作线程准备调用加锁后，再持有 100 ms，随后释放。每个工作线程获得锁后，
  增加受保护计数并持锁 1 ms，最后解锁。
- `uncontended`：每个工作线程使用自己的锁，执行相同的加锁、计数和解锁操作，
  不制造锁竞争。线程启动和回收可能仍产生其他地址上的 futex 事件。

程序先输出 `[MUTEX WORKLOAD] ready` 并等待输入，便于在负载开始前挂载探针。
所有线程完成后，输出 `[MUTEX WORKER]` 和 `[MUTEX RESULT]`。

## 构建及无需 root 的检查

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

CTest 中的 `mutex_contention_workload`、`mutex_uncontended_workload` 验证锁操作和受保护计数，并检查竞争线程的应用层等待确实存在。`mutex_probe_validation` 在 Python3 可用时
注册，用于检查验收逻辑能排除 join 等待，并拒绝缺失线程、越界时间和丢事件等数据。
这些检查不加载 BPF，不能替代下面的真实采集验收。

## 真实 BPF 自动验收

在具备 BPF 加载权限、内核 BTF 和相关 tracepoint 的 Ubuntu / WSL 终端运行：

```bash
sudo python3 scripts/check_mutex_probe.py
```

脚本先等待工作程序就绪，再挂载探针，然后放行负载。探针输出由后台线程持续读取，
避免输出管道阻塞影响采集。两个场景分别执行，结束后保存完整日志和 JSON：

```text
/tmp/kylinrca-mutex-validation/contention-probe.log
/tmp/kylinrca-mutex-validation/contention-workload.log
/tmp/kylinrca-mutex-validation/contention.json
/tmp/kylinrca-mutex-validation/uncontended-probe.log
/tmp/kylinrca-mutex-validation/uncontended-workload.log
/tmp/kylinrca-mutex-validation/uncontended.json
```

成功标准：

- 总体及两个场景的 `passed` 都为 `true`。
- 竞争场景 `threads=8`、`long_waiters=8`，每个工作线程均有成功返回、至少 50 ms 的
  BPF 等待记录，`futex_addresses` 只有一个地址，且位于同一互斥锁对象范围内。
- 事件起止时间处于对应线程的 `pthread_mutex_lock()` 调用区间内。
- 无竞争场景 `matched_events=0`；不要求整个进程完全没有 futex 等待。
- Map 错误、起点缺失、时间异常、丢事件和格式拒绝计数为 0；等待完成数、接收数和
  实际输出记录数一致。
- 两个场景均完成 8 次加锁，受保护计数为 8。

验收不假定 futex 地址等于 `pthread_mutex_t` 起始地址，而是检查它是否位于所声明的
锁对象内。工作线程之外的 join 等待，以及锁对象范围之外的等待，不计为该锁的竞争。
目前仅验证进程内普通互斥锁，不承诺覆盖递归锁、PI 锁或跨进程共享锁。

可调整线程数、持锁时长、构建和输出目录：

```bash
sudo python3 scripts/check_mutex_probe.py --threads 8 --hold-ms 200 \
  --build-dir build --output-dir /tmp/kylinrca-mutex-validation-200ms
```

线程数范围为 2～64，持锁时长范围为 20～1000 ms；最低 BPF 等待要求为持锁时长的一半。

## 双终端观察

终端一执行，记下输出中的实际 PID，先不按回车：

```bash
./build/kylinrca_lock_test --scenario contention --threads 8 --hold-ms 100
```

终端二将 `12345` 替换为实际 PID：

```bash
sudo ./build/kylinrca_lock_probe_smoke --pid 12345 --duration 60
```

看到探针 `ready` 后，回到终端一按回车。观察工作线程记录和 `[LOCK]` 事件，完成后在
终端二按 Ctrl+C 查看统计。也可以将终端一的场景改为 `uncontended` 观察对照结果。

提交 PR 时应附上真实执行生成的 JSON 和环境信息。加载失败的日志不能作为通过证据。
