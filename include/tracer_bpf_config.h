#ifndef KYLINRCA_TRACER_BPF_CONFIG_H
#define KYLINRCA_TRACER_BPF_CONFIG_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

inline bool configure_tracer_pid(bpf_object* object)
{
    const int fd = bpf_object__find_map_fd_by_name(object, "config_map");
    const __u32 key = 0;
    const __u32 pid = getpid();
    return fd >= 0 && bpf_map_update_elem(fd, &key, &pid, BPF_ANY) == 0;
}

#endif
