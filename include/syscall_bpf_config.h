#ifndef KYLINRCA_SYSCALL_BPF_CONFIG_H
#define KYLINRCA_SYSCALL_BPF_CONFIG_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>

// 把采集程序所在的 PID 命名空间告诉 BPF，让事件编号与用户态一致。
inline bool configure_syscall_namespace(bpf_object* object)
{
    struct stat info {};
    if (stat("/proc/self/ns/pid", &info) != 0)
        return false;
    bpf_map* map = bpf_object__find_map_by_name(object, "namespace_config");
    if (!map)
        return false;
    const __u32 key = 0;
    const __u64 inode = info.st_ino;
    return bpf_map_update_elem(bpf_map__fd(map), &key, &inode, BPF_ANY) == 0;
}

#endif
