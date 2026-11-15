#ifndef KYLINRCA_CPU_BPF_CONFIG_H
#define KYLINRCA_CPU_BPF_CONFIG_H
#include "cpu_runtime.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>

/* 使用 /proc 所属的 PID namespace；部署时 /proc 必须与当前进程匹配。 */
inline bool configure_cpu_namespace(bpf_object* object)
{
    struct stat info {};
    if (stat("/proc/self/ns/pid", &info) != 0)
        return false;
    bpf_map* map = bpf_object__find_map_by_name(object, "namespace_config");
    if (!map)
        return false;
    const uint32_t key = 0;
    const cpu_namespace_config config {static_cast<__u64>(info.st_ino)};
    return bpf_map_update_elem(bpf_map__fd(map), &key, &config, BPF_ANY) == 0;
}
#endif
