#ifndef KYLINRCA_BPF_COMMON_H
#define KYLINRCA_BPF_COMMON_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

/*
 * KylinRCA BPF common layer - v1
 *
 * 目标：
 * 1. 统一常用 BPF Map 声明方式
 * 2. 统一 pid_tgid 中 PID/TID 的拆分
 * 3. 统一 tracer 自过滤
 * 4. 提供目标 PID/TID filter helper
 * 5. 为后续 Stack ID 能力预留公共接口
 *
 * 注意：
 * - 不定义具体模块事件结构；
 * - 不修改 include/event.h；
 * - CPU / Syscall / IO 等模块仍拥有自己的业务 Map 和事件字段。
 */


/* -------------------- common constants -------------------- */

/*
 * 当前 W1 用户态约定：
 *
 * config_map[0] = tracer PID
 *
 * 第一版 common 必须保持这个 ABI 不变。
 */
#define KYLINRCA_CONFIG_KEY 0

/*
 * 后续使用 BPF_MAP_TYPE_STACK_TRACE 时的默认容量。
 * 这里只提供公共声明能力，W2 第一版暂不强制任何模块使用 stack map。
 */
#define KYLINRCA_DEFAULT_STACK_MAP_ENTRIES 1024

/*
 * Linux BPF stack trace 常用最大深度。
 * 当前只用于声明 stack-trace map 的 value 大小。
 */
#define KYLINRCA_MAX_STACK_DEPTH 127


/* -------------------- common map declarations -------------------- */

/*
 * 通用 HASH Map。
 *
 * Example:
 *
 * KYLINRCA_DECLARE_HASH_MAP(
 *     start_map,
 *     __u64,
 *     struct syscall_start,
 *     16384
 * );
 */
#define KYLINRCA_DECLARE_HASH_MAP(name, key_type, value_type, entries) \
struct {                                                               \
    __uint(type, BPF_MAP_TYPE_HASH);                                   \
    __uint(max_entries, entries);                                      \
    __type(key, key_type);                                             \
    __type(value, value_type);                                         \
} name SEC(".maps") // C 预处理器宏，用于简化 Hash 类型 BPF Map 的声明，即一个代码模板


/*
 * 通用 RingBuffer。
 *
 * Example:
 *
 * KYLINRCA_DECLARE_RINGBUF(events, 256 * 1024);
 */
#define KYLINRCA_DECLARE_RINGBUF(name, bytes) \
struct {                                      \
    __uint(type, BPF_MAP_TYPE_RINGBUF);       \
    __uint(max_entries, bytes);               \
} name SEC(".maps")


/*
 * tracer PID 配置 Map。
 *
 * 保持 W1 ABI：
 *
 * key   = __u32
 * value = __u32 tracer_pid
 * key 0 保存当前用户态 tracer PID。
 *
 * Syscall 当前继续声明为：
 *
 * KYLINRCA_DECLARE_TRACER_PID_MAP(config_map);
 */
#define KYLINRCA_DECLARE_TRACER_PID_MAP(name) \
struct {                                      \
    __uint(type, BPF_MAP_TYPE_ARRAY);         \
    __uint(max_entries, 1);                   \
    __type(key, __u32);                       \
    __type(value, __u32);                     \
} name SEC(".maps")


/*
 * Stack ID 公共接口预留。
 *
 * 第一版暂不在 Syscall 中真正创建该 Map；
 * 后续 CPU / Lock 等模块需要内核栈时可以使用：
 *
 * KYLINRCA_DECLARE_STACK_MAP(stack_map, 1024);
 */
#define KYLINRCA_DECLARE_STACK_MAP(name, entries)                 \
struct {                                                          \
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);                       \
    __uint(max_entries, entries);                                 \
    __uint(key_size, sizeof(__u32));                              \
    __uint(value_size, KYLINRCA_MAX_STACK_DEPTH * sizeof(__u64)); \
} name SEC(".maps")


/* -------------------- PID / TID helpers -------------------- */

// __always_inline 是一个宏定义，用于强制编译器将函数标记为内联函数，确保在每个调用点都进行内联展开。这可以提高性能，尤其是在小型函数频繁调用的情况下。
// 这里的 static 表示：这个函数只在包含 bpf_common.h 的当前 .c 文件内部使用，不会成为一个对外可见的全局函数。

static __always_inline __u32 kylinrca_pid_from_pid_tgid(__u64 pid_tgid)
{
    return (__u32)(pid_tgid >> 32);
}
 

static __always_inline __u32 kylinrca_tid_from_pid_tgid(__u64 pid_tgid)
{
    return (__u32)pid_tgid;
}


/* -------------------- common filtering -------------------- */

/*
 * target_pid == 0：
 *     不限制 PID。
 *
 * target_pid != 0：
 *     只允许指定 PID。
 *
 * 当前 Syscall 尚未使用 target PID 配置，
 * 先把公共判断接口准备好供 CPU / 后续模块复用。
 */
static __always_inline int kylinrca_pid_matches(__u32 current_pid, __u32 target_pid)
{
    return target_pid == 0 || current_pid == target_pid;
}


/*
 * target_tid == 0：
 *     不限制 TID。
 *
 * target_tid != 0：
 *     只允许指定线程。
 */
static __always_inline int kylinrca_tid_matches(__u32 current_tid, __u32 target_tid)
{
    return target_tid == 0 || current_tid == target_tid;
}


/*
 * 判断当前事件是否来自 tracer 自己。return 1 表示当前事件来自 tracer 自己。
 *
 * config_map 必须保持：
 *
 * key   __u32
 * value __u32 tracer_pid
 *
 * 调用示例：
 *
 * if (kylinrca_should_skip_tracer(&config_map, pid_tgid))
 *     return 0;
 */
static __always_inline int kylinrca_should_skip_tracer(void *config_map, __u64 pid_tgid)
{
    __u32 key = KYLINRCA_CONFIG_KEY;
    __u32 *tracer_pid;

    tracer_pid = bpf_map_lookup_elem(config_map, &key); // 得到的是地址

    if (!tracer_pid)
        return 0; // 没有查到 tracer PID，因此不能确定事件来自 tracer，不跳过，继续采集。

    return kylinrca_pid_from_pid_tgid(pid_tgid) == *tracer_pid;
}

#endif /* KYLINRCA_BPF_COMMON_H */
