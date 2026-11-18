#ifndef KYLINRCA_IO_PROBE_STATS_H
#define KYLINRCA_IO_PROBE_STATS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

struct kylinrca_io_config {
    __u32 filter_device;
    __u32 major;
    __u32 minor;
};

/* 用户态与 BPF 共用计数器编号；PERCPU_ARRAY 在用户态汇总。 */
enum kylinrca_io_stat {
    IO_STAT_ISSUE,
    IO_STAT_COMPLETE,
    IO_STAT_PARTIAL,
    IO_STAT_REQUEUE,
    IO_STAT_UNMATCHED,
    IO_STAT_MAP_UPDATE_FAIL,
    IO_STAT_MAP_DELETE_FAIL,
    IO_STAT_RINGBUF_DROP,
    IO_STAT_BAD_TIMESTAMP,
    IO_STAT_READ_FAIL,
    IO_STAT_EMITTED,
    IO_STAT_REISSUE,
    IO_STAT_MAX
};
#endif
