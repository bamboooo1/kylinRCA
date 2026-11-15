# Raspberry Pi 3 BPF 能力预检报告

## 1. 测试环境

- 设备型号：Raspberry Pi 3 Model B Plus Rev 1.3
- 操作系统：Debian GNU/Linux 13（trixie）
- 架构：aarch64
- 用户空间位数：64-bit
- Kernel：6.18.39+rpt-rpi-v8
- Hostname：kylinrca-pi3

## 2. BPF 内核能力

通过内核配置和运行时能力检查，确认当前树莓派内核具备基础 eBPF 支持。

已确认的能力包括：

- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_JIT=y`
- eBPF tracepoint 程序类型可用
- BPF Hash Map 可用
- BPF Ring Buffer Map 可用

运行时检查结果：

```text
eBPF program_type tracepoint is available
eBPF map_type hash is available
eBPF map_type ringbuf is available
```

### 结论

当前 Raspberry Pi 内核具备 KylinRCA 的 Syscall 和 CPU 数据采集路径所需的基础 eBPF 能力。

## 3. BTF 能力

当前系统不存在标准内核 BTF 文件：

```text
/sys/kernel/btf/vmlinux
```

运行时检查结果：

```text
[FAIL] Kernel BTF unavailable
```

同时，测试内核上也不存在：

```text
/sys/kernel/btf
```

因此，当前项目中的：

```text
scripts/gen_vmlinux.sh
```

无法直接通过目标 Raspberry Pi 内核生成：

```text
bpf/include/vmlinux.h
```

### 结论

当前 Raspberry Pi 内核不提供标准 Kernel BTF。

## 4. CO-RE 能力

当前 KylinRCA 的标准 CO-RE 工作流依赖目标内核提供：

```text
/sys/kernel/btf/vmlinux
```

由于当前测试的 Raspberry Pi 内核不提供 Kernel BTF，因此当前项目的标准 CO-RE 构建流程无法直接在该系统上使用。

需要注意：

**Kernel BTF 不可用，并不代表 eBPF 本身不可用。**

当前状态如下：

- eBPF 程序执行：支持
- tracepoint 挂载：支持
- 当前项目所需 BPF Map：支持
- 目标内核 BTF：不支持
- 当前 KylinRCA 标准 CO-RE 路径：无法直接使用

因此，后续 Raspberry Pi 部署需要提供明确的能力降级或 fallback 路径，而不能在 BTF 不存在时静默失败。

可考虑的 fallback 方向包括：

1. 如果能够获取与目标内核严格匹配的外部 BTF，则使用外部 BTF。
2. 使用启用了 BTF 的 Raspberry Pi 内核。
3. 为当前使用的 tracepoint 提供非 CO-RE / tracepoint ABI fallback。

Week 2 阶段的主要目标是确认能力边界，因此当前只记录这一限制，不在本阶段重新编译 Raspberry Pi 内核。

## 5. tracefs 与 Tracepoint 能力

当前系统已经挂载 tracefs：

```text
/sys/kernel/tracing
```

KylinRCA CPU 模块当前所需的 tracepoint 均存在：

```text
sched/sched_switch
sched/sched_wakeup
sched/sched_wakeup_new
```

KylinRCA Syscall 模块当前所需的 tracepoint 也存在：

```text
raw_syscalls/sys_enter
raw_syscalls/sys_exit
```

### 5.1 `sched_switch` 字段

当前内核中观测到：

```text
prev_pid    offset:24 size:4
prev_state  offset:32 size:8
next_pid    offset:56 size:4
```

这些字段与当前 `cpu.bpf.c` 中使用的数据字段一致。

### 5.2 `sched_wakeup` / `sched_wakeup_new` 字段

两个 tracepoint 中均存在：

```text
pid offset:24 size:4
```

这与当前 CPU BPF 程序中的：

```c
ctx->pid
```

访问方式相对应。

### 5.3 `raw_syscalls` 字段

`sys_enter` 中存在：

```text
id offset:8 size:8
```

`sys_exit` 中存在：

```text
id  offset:8  size:8
ret offset:16 size:8
```

这些字段与当前 `syscall.bpf.c` 中使用的数据字段一致。

需要注意：

以上 offset 仅代表当前测试内核：

```text
6.18.39+rpt-rpi-v8
```

的实际观测结果，不能认为这些偏移在所有 Linux Kernel 上都固定不变。

## 6. 开发工具链

当前 Raspberry Pi 已安装并确认可用：

```text
bpftool v7.7.0
clang 19.1.7
libbpf-dev 1.5.0
cmake 3.31.6
```

Clang 已包含 BPF backend：

```text
bpf - BPF (host endian)
```

因此，当前 Raspberry Pi 已具备本地编译 eBPF 字节码所需的基础工具链。

## 7. 当前 KylinRCA 兼容性

### 当前已具备

- ARM64 用户空间构建环境
- Clang BPF backend
- libbpf 用户空间开发库
- BPF tracepoint 程序类型
- BPF Hash Map
- BPF Ring Buffer
- `sched_switch`
- `sched_wakeup`
- `sched_wakeup_new`
- `raw_syscalls/sys_enter`
- `raw_syscalls/sys_exit`

### 当前缺失

- `/sys/kernel/btf/vmlinux`
- 基于目标内核 BTF 生成的 `vmlinux.h`
- 当前标准 CO-RE 构建流程的直接可用性

因此，当前 Raspberry Pi 已经具备 KylinRCA 所需的大部分基础 eBPF 能力，但在完整 ARM64 部署之前，仍需要解决 BTF / CO-RE fallback 问题。

## 8. Week 2 结论

Raspberry Pi 3 ARM64 可以作为 KylinRCA 的嵌入式部署平台继续推进。

当前已经确认：

- eBPF 基础能力可用
- tracepoint 程序类型可用
- Hash Map 可用
- Ring Buffer 可用
- CPU 模块所需 tracepoint 可用
- Syscall 模块所需 tracepoint 可用
- ARM64 本地编译工具链可用

Week 2 能力预检发现的主要兼容性问题是：

```text
/sys/kernel/btf/vmlinux
```

不存在。

这会阻塞当前基于目标内核 BTF 生成 `vmlinux.h` 的标准 CO-RE 流程，但不会阻塞底层 eBPF 与 tracepoint 能力。

后续 ARM64 部署阶段需要显式加入 BTF / CO-RE 能力检测与 fallback 方案，确保当目标系统缺少 BTF 时，程序能够给出明确提示或采用兼容路径，而不是静默失败。
