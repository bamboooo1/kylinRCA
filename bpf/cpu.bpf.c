#include "bpf_common.h"
#include "event.h"
#include "cpu_probe_stats.h"
#include "cpu_runtime.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* 临时状态始终使用初始 namespace 的内核 TID，禁止混入可见 TID。 */
struct timestamp_value {
    __u64 time_ns;
    __u64 birth_ns;
};
KYLINRCA_DECLARE_HASH_MAP(runnable_ts_map, __u32, struct timestamp_value, 16384);
KYLINRCA_DECLARE_HASH_MAP(oncpu_start_map, __u32, struct timestamp_value, 16384);
KYLINRCA_DECLARE_HASH_MAP(runtime_map, __u32, struct cpu_runtime_value, 16384);
/* 任务释放时 thread_pid 可能已解除关联，保存带生命周期的可见 ID 用于回收。 */
struct task_identity {
    __u32 tid;
    __u32 pid;
    __u64 birth_ns;
};
KYLINRCA_DECLARE_HASH_MAP(task_ids, __u32, struct task_identity, 16384);
KYLINRCA_DECLARE_RINGBUF(events, 256 * 1024);
KYLINRCA_DECLARE_TRACER_PID_MAP(config_map);
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cpu_namespace_config);
} namespace_config SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CPU_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} cpu_stats SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_submit_seq SEC(".maps");

static __always_inline void inc_cpu_stat(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&cpu_stats, &key);
    if (value)
        (*value)++;
}

/*
 * 选择观测者的 namespace，而不是任务自己的最深层 namespace。
 * 同一宿主机可能有多个容器，各自都能有 TID=162；内部 key 绝不能混用。
 * 不在观测者 namespace 中可见的任务返回 0，不冒充可见任务。
 */
static __always_inline __u32 visible_id(struct task_struct *task, int leader)
{
    __u32 zero = 0;
    struct cpu_namespace_config *cfg = bpf_map_lookup_elem(&namespace_config, &zero);
    if (!cfg || !cfg->inode)
        return 0;
    __u64 wanted = cfg->inode;
    if (leader)
        task = BPF_CORE_READ(task, group_leader);
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    if (!pid)
        return 0;
    unsigned int level = BPF_CORE_READ(pid, level);
    if (level > 32)
        return 0;
    for (int i = 0; i <= 32; ++i) {
        if (i > level)
            break;
        struct upid up = {};
        if (bpf_core_read(&up, sizeof(up), &pid->numbers[i]) < 0)
            return 0;
        if (up.ns && BPF_CORE_READ(up.ns, ns.inum) == wanted)
            return up.nr;
    }
    return 0;
}

static __always_inline int ignored(__u32 pid, __u32 tid)
{
    __u32 zero = 0;
    __u32 *tracer = bpf_map_lookup_elem(&config_map, &zero);
    return !pid || !tid || (tracer && pid == *tracer);
}

static __always_inline void bad_timestamp(__u32 key, __u32 tid,
                                          __u64 start, __u64 end)
{
    __u64 *count = bpf_map_lookup_elem(&cpu_stats, &key);
    if (count && ++(*count) <= 5)
        bpf_printk("CPU_BAD tid=%u start=%llu end=%llu", tid, start, end);
}

static __always_inline void emit_cpu_event(__u32 pid, __u32 tid, __u32 kind,
                                           __u64 duration, __u64 now)
{
    struct cpu_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        inc_cpu_stat(CPU_STAT_RINGBUF_DROP);
        return;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->header.version = KYLINRCA_EVENT_VERSION;
    event->header.type = EVENT_TYPE_CPU;
    event->header.size = sizeof(*event);
    event->header.timestamp_ns = now;
    event->header.pid = pid;
    event->header.tid = tid;
    event->kind = kind;
    if (kind == CPU_EVENT_RUNQUEUE_DELAY)
        event->runqueue_delay_ns = duration;
    else
        event->on_cpu_time_ns = duration;
    __u32 zero = 0;
    __u64 *seq = bpf_map_lookup_elem(&ringbuf_submit_seq, &zero);
    __u64 flags = BPF_RB_NO_WAKEUP;
    if (seq && ((++(*seq) & 63) == 0))
        flags = BPF_RB_FORCE_WAKEUP;
    bpf_ringbuf_submit(event, flags);
}

/* 每个线程的运行累计值独立于 RingBuffer，事件丢失不再丢失运行总量。 */
static __always_inline void runtime_switch(__u32 kernel_tid, __u32 pid, __u32 tid, __u64 birth,
                                           __u64 now, int entering)
{
    struct task_identity identity = {.tid = tid, .pid = pid, .birth_ns = birth};
    if (bpf_map_update_elem(&task_ids, &kernel_tid, &identity, BPF_ANY) < 0)
        inc_cpu_stat(CPU_STAT_ONCPU_UPDATE_FAIL);
    struct cpu_runtime_value local = {};
    struct cpu_runtime_value *old = bpf_map_lookup_elem(&runtime_map, &tid);
    if (old)
        local = *old;
    if (local.birth_ns != birth || local.pid != pid) {
        local.pid = pid;
        local.birth_ns = birth;
        local.completed_ns = 0;
        local.running_since_ns = 0;
    }
    if (entering) {
        local.running_since_ns = now;
    } else if (local.running_since_ns) {
        if (now >= local.running_since_ns)
            local.completed_ns += now - local.running_since_ns;
        else
            bad_timestamp(CPU_STAT_BAD_ONCPU_TIMESTAMP, tid,
                          local.running_since_ns, now);
        local.running_since_ns = 0;
    }
    /*
     * 同一任务的切入/切出由调度路径串行化；用 Hash 整项替换发布快照。
     * tracing 程序不能使用 bpf_spin_lock，因此不采用原地写入加锁。
     */
    if (bpf_map_update_elem(&runtime_map, &tid, &local, BPF_ANY) < 0)
        inc_cpu_stat(CPU_STAT_ONCPU_UPDATE_FAIL);
}

static __always_inline int wakeup(struct task_struct *task)
{
    __u32 tid = visible_id(task, 0);
    __u32 pid = visible_id(task, 1);
    if (ignored(pid, tid))
        return 0;
    __u32 key = BPF_CORE_READ(task, pid);
    struct timestamp_value stamp = {
        .birth_ns = BPF_CORE_READ(task, start_boottime),
        .time_ns = bpf_ktime_get_ns(),
    };
    if (bpf_map_update_elem(&runnable_ts_map, &key, &stamp, BPF_ANY) < 0)
        inc_cpu_stat(CPU_STAT_WAKEUP_UPDATE_FAIL);
    return 0;
}

/* 两条 wakeup 路径都拿 task_struct，彻底统一内部 key 与可见 ID 的转换。 */
SEC("raw_tracepoint/sched_wakeup")
int handle_sched_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    return wakeup((struct task_struct *)ctx->args[0]);
}
SEC("raw_tracepoint/sched_wakeup_new")
int handle_sched_wakeup_new(struct bpf_raw_tracepoint_args *ctx)
{
    return wakeup((struct task_struct *)ctx->args[0]);
}

SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev = (struct task_struct *)ctx->args[1];
    struct task_struct *next = (struct task_struct *)ctx->args[2];
    __u32 pk = BPF_CORE_READ(prev, pid), nk = BPF_CORE_READ(next, pid);
    __u32 pt = visible_id(prev, 0), pp = visible_id(prev, 1);
    __u32 nt = visible_id(next, 0), np = visible_id(next, 1);
    __u64 pb = BPF_CORE_READ(prev, start_boottime);
    __u64 nb = BPF_CORE_READ(next, start_boottime);
    /* 同一次切换的起止边界一致；不将不同线程的处理耗时算成运行时间。 */
    __u64 now = bpf_ktime_get_ns();
    if (!ignored(pp, pt)) {
        struct timestamp_value *found = bpf_map_lookup_elem(&oncpu_start_map, &pk);
        if (found) {
            struct timestamp_value start = *found;
            if (start.birth_ns == pb) {
                if (now >= start.time_ns)
                    emit_cpu_event(pp, pt, CPU_EVENT_ONCPU_TIME, now - start.time_ns, now);
                else
                    bad_timestamp(CPU_STAT_BAD_ONCPU_TIMESTAMP, pt, start.time_ns, now);
            }
            bpf_map_delete_elem(&oncpu_start_map, &pk);
        } else {
            inc_cpu_stat(CPU_STAT_ONCPU_MISS);
        }
        runtime_switch(pk, pp, pt, pb, now, 0);
        /* raw tracepoint 的 preempt 参数单独处理，不依赖格式化 prev_state 的位掩码。 */
        if (ctx->args[0] || ctx->args[3] == 0) {
            struct timestamp_value stamp = {.time_ns = now, .birth_ns = pb};
            if (bpf_map_update_elem(&runnable_ts_map, &pk, &stamp, BPF_ANY) < 0)
                inc_cpu_stat(CPU_STAT_REQUEUE_UPDATE_FAIL);
        }
    }
    if (!ignored(np, nt)) {
        struct timestamp_value *found = bpf_map_lookup_elem(&runnable_ts_map, &nk);
        if (found) {
            struct timestamp_value start = *found;
            if (start.birth_ns == nb) {
                /*
                 * 先固定 Map 快照，再读取计算终点。
                 * 远端 CPU 的唤醒写入可能晚于本函数入口的 now；提前取时
                 * 会产生几十 ns 的负值。只调整排队测量终点，不改变调度
                 * 运行片段的共同边界 now，也不把负值截断为零。
                 */
                __u64 measured_end = bpf_ktime_get_ns();
                if (measured_end >= start.time_ns)
                    emit_cpu_event(np, nt, CPU_EVENT_RUNQUEUE_DELAY,
                                   measured_end - start.time_ns, measured_end);
                else
                    bad_timestamp(CPU_STAT_BAD_RUNQUEUE_TIMESTAMP, nt,
                                  start.time_ns, measured_end);
            }
            bpf_map_delete_elem(&runnable_ts_map, &nk);
        } else {
            inc_cpu_stat(CPU_STAT_WAKEUP_MISS);
        }
        struct timestamp_value stamp = {.time_ns = now, .birth_ns = nb};
        if (bpf_map_update_elem(&oncpu_start_map, &nk, &stamp, BPF_ANY) < 0)
            inc_cpu_stat(CPU_STAT_ONCPU_UPDATE_FAIL);
        runtime_switch(nk, np, nt, nb, now, 1);
    }
    return 0;
}

/* 任务释放时清理；exit 事件早于最后一次 switch-out，不能在 exit 时提前删除。 */
SEC("raw_tracepoint/sched_process_free")
int handle_sched_free(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *)ctx->args[0];
    __u32 key = BPF_CORE_READ(task, pid);
    __u64 birth = BPF_CORE_READ(task, start_boottime);
    struct timestamp_value *stamp = bpf_map_lookup_elem(&runnable_ts_map, &key);
    if (stamp && stamp->birth_ns == birth)
        bpf_map_delete_elem(&runnable_ts_map, &key);
    stamp = bpf_map_lookup_elem(&oncpu_start_map, &key);
    if (stamp && stamp->birth_ns == birth)
        bpf_map_delete_elem(&oncpu_start_map, &key);
    struct task_identity *found = bpf_map_lookup_elem(&task_ids, &key);
    if (found) {
        struct task_identity id = *found;
        if (id.birth_ns == birth) {
            struct cpu_runtime_value *runtime = bpf_map_lookup_elem(&runtime_map, &id.tid);
            if (runtime && runtime->birth_ns == birth)
                bpf_map_delete_elem(&runtime_map, &id.tid);
            bpf_map_delete_elem(&task_ids, &key);
        }
    }
    return 0;
}
char LICENSE[] SEC("license") = "GPL";
