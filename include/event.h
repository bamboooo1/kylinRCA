// 规定“内核 eBPF 写出去的字节”和“用户态 C++ 读进来的字节”到底按什么格式排列。
#ifndef KYLINRCA_EVENT_H
#define KYLINRCA_EVENT_H

#include <linux/types.h>

#define KYLINRCA_EVENT_VERSION 1

enum event_type {
    EVENT_TYPE_UNKNOWN = 0,
    EVENT_TYPE_SYSCALL = 1,
    EVENT_TYPE_CPU     = 2,
    EVENT_TYPE_LOCK    = 3,
    EVENT_TYPE_IO      = 4,
    EVENT_TYPE_MEMORY  = 5,
};

struct event_header {
    __u16 version;
    __u16 type;
    __u32 size;

    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
};

struct syscall_event {
    struct event_header header;

    __s64 syscall_id;
    __s64 ret;

    __u64 duration_ns;
};

#endif