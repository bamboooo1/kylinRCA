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

/*一次 futex 等待调用结束后的记录。*/
struct kylinrca_lock_event {
    struct kylinrca_event_header header; //	事件类型、时间戳、PID/TID 等公共信息
    __u64 lock_addr; //    锁地址，用户态传入的 futex 地址
    __u64 duration_ns; //    从调用开始到返回的耗时，单位纳秒
    __s64 ret;      //    futex 调用返回值，内核层返回的原始值
    __u32 futex_op; //	等待操作及其标志
    __u32 reserved;  // 	预留字段，发送时置零
};

/*
 * I/O 操作类型。
 */
enum io_operation {
    IO_OP_UNKNOWN = 0,
    IO_OP_READ    = 1,
    IO_OP_WRITE   = 2,
    IO_OP_OTHER   = 3,
};

/*
 * 一次块请求完成后的事件。
 * header.timestamp_ns：最终完成时的单调时钟时间，单位纳秒。
 * header.pid/tid：无法确认请求归属时填 0。
 */
struct kylinrca_io_event {
    struct kylinrca_event_header header;

    __u64 duration_ns; //从选定 issue 起点到请求最终完成的耗时，单位纳秒
    __u64 bytes;  //本次观测请求的数据量，单位字节
    __u64 sector; //请求起始扇区号

    __u32 dev_major; //设备主、次编号
    __u32 dev_minor;

    __u32 operation; //我们定义的读、写或其他操作
    __u32 status; //	内核块层完成状态，约定 0 为成功
};


#endif
