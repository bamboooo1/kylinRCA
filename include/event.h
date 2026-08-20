#ifndef KYLINRCA_EVENT_H
#define KYLINRCA_EVENT_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define KYLINRCA_EVENT_VERSION 1

enum event_type {
    EVENT_TYPE_UNKNOWN = 0,
    EVENT_TYPE_SYSCALL = 1,
    EVENT_TYPE_CPU     = 2,
    EVENT_TYPE_LOCK    = 3,
    EVENT_TYPE_IO      = 4,
    EVENT_TYPE_MEMORY  = 5,
};

struct kylinrca_event_header {
    __u16 version;
    __u16 type;
    __u32 size;

    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
};

struct syscall_event {
    struct kylinrca_event_header header;

    __s64 syscall_id;
    __s64 ret;

    __u64 duration_ns;
};

/*
 * CPU 模块内部的事件类型。
 */
enum cpu_event_kind {
    CPU_EVENT_RUNQUEUE_DELAY = 1,
    CPU_EVENT_ONCPU_TIME     = 2,
};


/*
 * CPU 调度事件。
 *
 * kind == CPU_EVENT_RUNQUEUE_DELAY:
 *     runqueue_delay_ns 有效
 *
 * kind == CPU_EVENT_ONCPU_TIME:
 *     on_cpu_time_ns 有效
 */
struct cpu_event {
    struct kylinrca_event_header header;
    __u32 kind;
    __u32 reserved;

    __u64 runqueue_delay_ns;
    __u64 on_cpu_time_ns;
};


#endif
