#ifndef KYLINRCA_CPU_RUNTIME_H
#define KYLINRCA_CPU_RUNTIME_H
#ifndef __VMLINUX_H__
#include <linux/bpf.h>
#include <linux/types.h>
#endif

/* 用户态写入自身 PID namespace 的 inode，所有输出 ID 都在这个空间解释。 */
struct cpu_namespace_config {
    __u64 inode;
};

/*
 * 已完成片段累计值 + 尚未结束的运行起点。
 * Hash Map 整项原子替换；禁止原地逐字段写入，用户态读取完整快照。
 * birth_ns 区分同一数字 TID 的不同生命周期，防止复用后错误做差。
 */
struct cpu_runtime_value {
    __u32 reserved;
    __u32 pid;
    __u64 birth_ns;
    __u64 completed_ns;
    __u64 running_since_ns;
};
#endif
