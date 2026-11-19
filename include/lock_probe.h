#ifndef KYLINRCA_LOCK_PROBE_H
#define KYLINRCA_LOCK_PROBE_H //防止同一个头文件在一次编译过程中被重复展开

#include "event.h"

/*kylinrca_lock_config 是用户态传给内核探针的配置，告诉探针观察谁、识别哪些操作。*/
struct kylinrca_lock_config {
    __u64 namespace_inode; //	当前 PID 命名空间的标识，用来把内核中的进程、线程编号转换成当前终端能看到的编号。
    __s64 futex_syscall_id; //	当前平台上 futex 系统调用的编号，用来筛选 futex 调用。
    __u32 target_pid; //要观察的进程 PID；`0` 表示不限制目标进程。
    __u32 futex_wait; //FUTEX_WAIT 的操作编号，用来识别普通等待。
    __u32 futex_wait_bitset; //	FUTEX_WAIT_BITSET 的操作编号，用来识别支持选择性唤醒的等待
    __u32 futex_cmd_mask; //提取操作编号时使用的掩码，去掉 PRIVATE 等附加标志，判断它究竟是哪种操作。
};

/*定义统计项的编号，统计项记录的是事件发生次数，不是耗时。*/
enum kylinrca_lock_stat_key {
    LOCK_STAT_FUTEX_ENTER = 0, //被选中观察的线程进入一次 futex 调用时。
    LOCK_STAT_WAIT_ENTER,  //确认这次调用是 WAIT 或 WAIT_BITSET 时。
    LOCK_STAT_WAIT_EXIT, //	等待调用退出，并成功找到之前保存的起点时。
    LOCK_STAT_START_UPDATE_FAIL, //向 Map 保存调用起点失败时。
    LOCK_STAT_START_MISS, //futex 调用退出，却找不到对应起点时。
    LOCK_STAT_DELETE_FAIL, //删除 Map 中的调用记录失败时。
    LOCK_STAT_RINGBUF_DROP, //RingBuffer 无法分配空间，导致事件未能发送时。
    LOCK_STAT_BAD_TIMESTAMP, //发现结束时间早于开始时间时。
    LOCK_STAT_THREAD_EXIT_CLEANUP, //线程退出时，发现并清理了残留调用记录。
    LOCK_STAT_MAX, //表示统计项的总数，用于设置容量，不是实际计数项。
};

#endif
