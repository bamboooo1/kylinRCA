#ifndef KYLINRCA_LOCK_BPF_CONFIG_H
#define KYLINRCA_LOCK_BPF_CONFIG_H

#include "lock_probe.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/futex.h>
#include <sys/stat.h>
#include <sys/syscall.h>

inline bool configure_lock_probe(bpf_object* object, __u32 target_pid)
{
    struct stat info {};
    if (stat("/proc/self/ns/pid", &info) != 0)
        return false;

    const int fd = bpf_object__find_map_fd_by_name(object, "lock_config");
    const __u32 key = 0;
    const kylinrca_lock_config config {
        static_cast<__u64>(info.st_ino), SYS_futex, target_pid,
        FUTEX_WAIT, FUTEX_WAIT_BITSET, static_cast<__u32>(FUTEX_CMD_MASK)
    };
    return fd >= 0 && bpf_map_update_elem(fd, &key, &config, BPF_ANY) == 0;
}

#endif
