#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>//**CO-RE 核心头文件**，提供 `BPF_CORE_READ` 系列宏，实现跨内核自动修正结构体字段偏移。

SEC("tracepoint/syscalls/sys_enter_getpid") //只要任意进程执行 `getpid()`，这个 BPF 函数就会被内核执行一次。
int core_smoke(void *ctx)
{
    struct task_struct *task; //Linux Kernel 中描述进程/线程的重要结构体。

    task = (struct task_struct *)bpf_get_current_task();//获取当前正在执行 syscall 的 task

    __u32 tgid = BPF_CORE_READ(task, tgid);//CO-RE安全读取tgid，没有写死字段偏移

    bpf_printk("KylinRCA CO-RE smoke: tgid=%u\n", tgid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL"; //使用了 `bpf_get_current_task()`、`BPF_CORE_READ` 这类内核受限辅助函数时，**必须声明 GPL 协议**；
