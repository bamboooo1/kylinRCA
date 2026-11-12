#include "bpf_common.h"
#include "event.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/*
 * 当前 Ubuntu 内核 sched_switch 的 prev_state：
 *
 * 低 8 位表示任务状态。
 * 低 8 位为 0 表示任务仍然 runnable。
 *
 * 当前先按 Ubuntu 实际 tracepoint format 实现。
 * ARM64 / 不同内核版本兼容后续统一处理。
 */
#define KYLINRCA_SCHED_STATE_MASK 0xffUL


/*
 * runnable_ts_map: 记录“开始等 CPU”的时间
 */
KYLINRCA_DECLARE_HASH_MAP(
    runnable_ts_map,
    __u32,
    __u64,
    16384
);


/*
 * oncpu_start_map: 记录“开始占用 CPU”的时间
 */
KYLINRCA_DECLARE_HASH_MAP(
    oncpu_start_map,
    __u32,
    __u64,
    16384
);


/*
 * CPU 调度事件通过该 RingBuffer
 * 发送到用户态 CpuAnalyzer。
 */
KYLINRCA_DECLARE_RINGBUF(
    events,
    256 * 1024
);


/*
 * 记录 tracer 的进程 PID
 */
KYLINRCA_DECLARE_TRACER_PID_MAP(config_map);


/*
 * 记录“需要从 CPU 调度观测中排除的 tracer 线程 TID”
 *
 * 它主要是为了解决用户态 PID 与调度 tracepoint 中 TID 可能不一致的问题。
 * 
 * config_map[0] 中的用户态 tracer PID
                ↓
 * sched_switch 时识别 current 属于 tracer
                ↓
 * 取得 ctx->prev_pid
                ↓
 * 写入 cpu_ignored_tids
                ↓
 * 后续忽略这个 scheduler-visible TID
 *
 */
KYLINRCA_DECLARE_HASH_MAP(
    cpu_ignored_tids,
    __u32,
    __u8,
    64
);


/*
 * Probe 自身运行状态统计。
 */
enum cpu_stat_key {
    CPU_STAT_WAKEUP_UPDATE_FAIL = 0,
    CPU_STAT_WAKEUP_MISS,
    CPU_STAT_ONCPU_UPDATE_FAIL,
    CPU_STAT_ONCPU_MISS,
    CPU_STAT_REQUEUE_UPDATE_FAIL,
    CPU_STAT_RINGBUF_DROP,
    CPU_STAT_DELETE_FAIL,
    CPU_STAT_MAX,
};


/*
 * 使用 PERCPU_ARRAY：
 *
 * 高频 tracepoint 下不同 CPU 修改自己的 counter，
 * 避免所有 CPU 竞争同一个计数值。
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CPU_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} cpu_stats SEC(".maps");

/* Per-CPU sequence used to batch RingBuffer wakeups. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_submit_seq SEC(".maps");


/*
 * 增加 Probe 内部统计计数。
 *
 * __always_inline：
 * 强制编译器内联展开，适合 BPF helper 风格的小函数。
 */
static __always_inline void inc_cpu_stat(__u32 key)
{
    __u64 *value;

    value = bpf_map_lookup_elem(
        &cpu_stats,
        &key);

    if (value)
        (*value)++;
}


/*
 * 判断 sched_switch 中：
 *
 * 被切下 CPU 的 prev task
 * 是否仍然处于 runnable 状态。
 *
 * 如果仍 runnable，说明它不是主动睡眠，
 * 而是被抢占，需要重新开始计算 runqueue delay。
 */
static __always_inline int prev_is_runnable(long prev_state)
{
    return (
        prev_state &
        KYLINRCA_SCHED_STATE_MASK
    ) == 0;
}


/*
 * 新增：学习 scheduler 视角下的 tracer TID。
 *
 * pid_tgid:
 *     bpf_get_current_pid_tgid() 的结果。
 *
 * sched_tid:
 *     sched_switch 中的 ctx->prev_pid。
 *
 *
 * 为什么只在 sched_switch 中调用？
 *
 * sched_switch 发生时，current 对应正在被切下 CPU 的 prev task。
 *
 * 因此：
 *
 * 如果 bpf_get_current_pid_tgid()
 * 能确认 current 属于 tracer，
 *
 * 那么：
 *
 *     ctx->prev_pid
 *
 * 就是 scheduler 视角下这个 tracer 线程真正使用的 TID。
 *
 *
 * 注意：
 *
 * 这里不能再使用
 *
 *     kylinrca_tid_from_pid_tgid(pid_tgid)
 *
 * 作为 cpu_ignored_tids 的 key。
 *
 * 因为我们建立这个 Map 的目的，
 * 正是为了处理用户态/BPF current ID
 * 与 sched tracepoint TID 可能不一致的问题。
 */
static __always_inline void remember_tracer_sched_tid(
    __u32 sched_tgid,
    __u32 sched_tid)
{
    __u32 key = KYLINRCA_CONFIG_KEY;
    __u32 *tracer_pid;
    __u8 value = 1;

    /*
     * 先利用和 syscall.bpf.c 相同的公共机制，
     * 判断 current 是否属于 tracer 进程。
     */
    tracer_pid = bpf_map_lookup_elem(&config_map, &key);

    if (!tracer_pid || sched_tgid != *tracer_pid)
        return;

    if (sched_tid == 0)
        return;

    /*
     * 保存 scheduler 视角下的 tracer TID。
     *
     * 后续 sched_wakeup / sched_switch
     * 都可以直接通过这个 TID 判断是否忽略。
     */
    bpf_map_update_elem(
        &cpu_ignored_tids,
        &sched_tid,
        &value,
        BPF_ANY);

    /*
     * 在第一次识别出 tracer TID 之前，
     * 它有可能已经留下过：
     *
     * runnable_ts_map[tid]
     * 或
     * oncpu_start_map[tid]
     *
     * 这些状态已经属于 observer 自己，
     * 必须立即清除，否则后续可能生成一条错误事件。
     */
    bpf_map_delete_elem(
        &runnable_ts_map,
        &sched_tid);

    bpf_map_delete_elem(
        &oncpu_start_map,
        &sched_tid);
}


/*
 * 新增：判断某个 sched tracepoint TID
 * 是否应该被 CPU Probe 忽略。
 */
static __always_inline int cpu_should_ignore_tid(__u32 tid)
{
    __u32 key = KYLINRCA_CONFIG_KEY;
    __u32 *tracer_pid;

    /*
     * idle task 不需要分析。
     */
    if (tid == 0)
        return 1;

    /*
     * 第一层：
     *
     * 普通 Linux 环境下，
     * sched TID 与用户态 tracer PID
     * 可能本身就是相同的。
     *
     * 这种情况下无需等待动态学习，
     * 可以直接过滤。
     */
    tracer_pid = bpf_map_lookup_elem(
        &config_map,
        &key);

    if (tracer_pid &&
        tid == *tracer_pid)
        return 1;

    /*
     * 第二层：
     *
     * 对于 WSL / namespace 等环境，
     * 查询我们在 sched_switch 中动态学习到的
     * scheduler-visible tracer TID。
     */
    return bpf_map_lookup_elem(
        &cpu_ignored_tids,
        &tid) != 0;
}

/*
 * raw sched_switch 可以同时读取 prev/next task_struct，因此可以按
 * TGID 立即过滤 tracer 的所有线程，而不必等到动态学习 TID。
 */
static __always_inline int cpu_should_ignore_task(
    __u32 tid,
    __u32 tgid)
{
    __u32 key = KYLINRCA_CONFIG_KEY;
    __u32 *tracer_pid;

    if (cpu_should_ignore_tid(tid))
        return 1;

    tracer_pid = bpf_map_lookup_elem(
        &config_map, &key);

    return tracer_pid && tgid == *tracer_pid;
}

/*
 * 返回任务在其所属最深 PID namespace 中可见的 PID。
 *
 * 直接读取 task_struct.pid/tgid 得到的是初始 PID namespace 的编号，
 * 在容器或 WSL 中无法与 /proc/<pid> 对齐。thread_pid->numbers[level]
 * 保存了任务在各层 namespace 中的编号，最深一层就是进程自身看到的
 * PID。普通宿主机任务的 level 为 0，因此行为与直接读取 pid/tgid 一致。
 */

static __always_inline __u32 task_namespace_pid(
    struct task_struct *task, // 每一个线程都有自己的task_struct
    int process_id)
{
    struct task_struct *identity_task = task;
    struct pid *kernel_pid; //pid结构体，因为同一个线程在不同的PID namespace 里可能有不同的PID
    struct upid namespace_pid = {};
    unsigned int level;

    if (process_id) //如果要求进程ID
        identity_task =
            BPF_CORE_READ(task, group_leader); //找到主线程的task

    kernel_pid =
        BPF_CORE_READ(identity_task, thread_pid); // 找到这个 task 对应的 struct pid

    if (!kernel_pid)
        return 0;

    level = BPF_CORE_READ(kernel_pid, level); // 获取 PID namespace 层级

    /*
     * 给 verifier 一个明确上界；Linux 的 PID namespace 嵌套上限
     * 远小于 32。
     */
    if (level > 32)
        return 0;

    if (bpf_core_read(
            &namespace_pid,
            sizeof(namespace_pid),
            &kernel_pid->numbers[level]) < 0) //读取numbers[level]
        return 0;

    return (__u32)namespace_pid.nr; //最后返回 namespace PID
}


/*
 * 向用户态发送一个 CPU 调度事件。
 */
static __always_inline void emit_cpu_event(
    __u32 pid,
    __u32 tid,
    __u32 kind,
    __u64 runqueue_delay_ns,
    __u64 on_cpu_time_ns,
    __u64 timestamp_ns)
{
    struct cpu_event *event;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0);

    if (!event) {
        inc_cpu_stat(
            CPU_STAT_RINGBUF_DROP);
        return;
    }

    event->header.version =
        KYLINRCA_EVENT_VERSION;

    event->header.type =
        EVENT_TYPE_CPU;

    event->header.size =
        sizeof(*event);

    event->header.timestamp_ns =
        timestamp_ns;

    event->header.pid = pid;
    event->header.tid = tid;

    event->kind = kind;
    event->reserved = 0;

    event->runqueue_delay_ns =
        runqueue_delay_ns;

    event->on_cpu_time_ns =
        on_cpu_time_ns;

    /*
     * sched_switch is a high-frequency tracepoint. Default adaptive wakeups
     * can wake the userspace poller for each submission; scheduling that
     * poller then creates more scheduler events and an observer feedback loop.
     *
     * The userspace poll has a 100 ms timeout, so suppress per-event wakeups
     * and let it consume events in batches. No sampling is introduced and the
     * event/statistics semantics stay unchanged.
     */
    __u32 seq_key = 0;
    __u64 *seq = bpf_map_lookup_elem(
        &ringbuf_submit_seq, &seq_key);
    __u64 submit_flags = BPF_RB_NO_WAKEUP;

    if (seq) {
        (*seq)++;
        if (((*seq) & 63) == 0)
            submit_flags = BPF_RB_FORCE_WAKEUP; //存满 64 条 events 就 WAKEUP
    } else {
        submit_flags = 0;
    }

    bpf_ringbuf_submit(event, submit_flags);
}


/*
 * 已存在的线程从 sleeping 等状态
 * 被唤醒进入 runnable 状态。
 */
SEC("tracepoint/sched/sched_wakeup")
int handle_sched_wakeup(
    struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 tid;
    __u64 now;

    int ret;

    /*
     * ctx->pid 是“被唤醒线程”的 TID。
     */
    tid = (__u32)ctx->pid;

    /*
     * 新增：
     *
     * 如果被唤醒的是 tracer 自己，
     * 不为它记录 runnable timestamp。
     */
    if (cpu_should_ignore_tid(tid))
        return 0;

    now = bpf_ktime_get_ns();

    ret = bpf_map_update_elem(
        &runnable_ts_map,
        &tid,
        &now,
        BPF_ANY);

    if (ret < 0)
        inc_cpu_stat(
            CPU_STAT_WAKEUP_UPDATE_FAIL);

    return 0;
}


/*
 * 新创建线程第一次进入 runnable 状态。
 */
SEC("tracepoint/sched/sched_wakeup_new")
int handle_sched_wakeup_new(
    struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 tid;
    __u64 now;

    int ret;

    tid = (__u32)ctx->pid;

    /*
     * 与 sched_wakeup 相同：
     *
     * 已经确认属于 tracer 的线程
     * 不记录 runnable timestamp。
     */
    if (cpu_should_ignore_tid(tid))
        return 0;

    now = bpf_ktime_get_ns();

    ret = bpf_map_update_elem(
        &runnable_ts_map,
        &tid,
        &now,
        BPF_ANY);

    if (ret < 0)
        inc_cpu_stat(
            CPU_STAT_WAKEUP_UPDATE_FAIL);

    return 0;
}


/*
 * CPU 调度切换：
 *
 * prev task
 *      ↓ switch out
 *
 * next task
 *      ↓ switch in
 *
 *
 * 一次 sched_switch 同时描述两个线程，
 * 所以不能像 syscall 一样：
 *
 *     tracer -> return 0
 *
 * 否则如果：
 *
 *     prev = tracer
 *     next = 普通线程
 *
 * 会连普通线程的 switch-in 信息也一起丢掉。
 *
 * 因此这里必须分别判断：
 *
 *     ignore_prev
 *     ignore_next
 */
SEC("raw_tracepoint/sched_switch")
int handle_sched_switch(
    struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *prev;
    struct task_struct *next;

    __u32 prev_tid;
    __u32 next_tid;
    __u32 prev_pid;
    __u32 next_pid;

    long prev_state;
    __u64 now;

    int ignore_prev;
    int ignore_next;

    __u64 *oncpu_start;
    __u64 *wakeup_ts;
    __u64 on_cpu_time_ns;
    __u64 runqueue_delay_ns;

    int ret;

    /*
     * raw sched_switch 参数与内核 TRACE_EVENT(sched_switch) 的
     * TP_PROTO 顺序一致：
     *
     * args[0] = preempt
     * args[1] = prev task_struct
     * args[2] = next task_struct
     * args[3] = prev_state
     */
    prev = (struct task_struct *)ctx->args[1];
    next = (struct task_struct *)ctx->args[2];
    prev_state = (long)ctx->args[3];

    /*
     * task_struct.pid 是线程 ID（TID），task_struct.tgid 是用户态
     * getpid() 返回的进程 ID。CO-RE 会按目标内核 BTF 重定位字段。
     */
    prev_tid = task_namespace_pid(prev, 0);
    prev_pid = task_namespace_pid(prev, 1);
    next_tid = task_namespace_pid(next, 0);
    next_pid = task_namespace_pid(next, 1);

    now = bpf_ktime_get_ns();

    /*
     * 保留 scheduler-visible tracer TID 的动态学习，供只提供 TID 的
     * sched_wakeup/sched_wakeup_new 路径使用。
     */
    remember_tracer_sched_tid(
        prev_pid,
        prev_tid);

    ignore_prev =
        cpu_should_ignore_task(
            prev_tid,
            prev_pid);

    ignore_next =
        cpu_should_ignore_task(
            next_tid,
            next_pid);

    /*
     * 处理被切下 CPU 的线程，生成它本轮的 on-CPU 时间。
     */
    if (prev_tid != 0 &&
        !ignore_prev) {

        oncpu_start =
            bpf_map_lookup_elem(
                &oncpu_start_map,
                &prev_tid);

        if (oncpu_start) {

            on_cpu_time_ns =
                now - *oncpu_start;

            emit_cpu_event(
                prev_pid,
                prev_tid,
                CPU_EVENT_ONCPU_TIME,
                0,
                on_cpu_time_ns,
                now);

            ret = bpf_map_delete_elem(
                &oncpu_start_map,
                &prev_tid);

            if (ret < 0)
                inc_cpu_stat(
                    CPU_STAT_DELETE_FAIL);

        } else {

            inc_cpu_stat(
                CPU_STAT_ONCPU_MISS);
        }
    }

    /*
     * 被抢占的 prev 仍然 runnable，从当前时刻重新计算排队时间。
     */
    if (prev_tid != 0 &&
        !ignore_prev &&
        prev_is_runnable(
            prev_state)) {

        ret = bpf_map_update_elem(
            &runnable_ts_map,
            &prev_tid,
            &now,
            BPF_ANY);

        if (ret < 0)
            inc_cpu_stat(
                CPU_STAT_REQUEUE_UPDATE_FAIL);
    }

    /*
     * 处理即将上 CPU 的 next，生成 runqueue delay，并记录新的
     * on-CPU 起点。
     */
    if (next_tid != 0 &&
        !ignore_next) {

        wakeup_ts =
            bpf_map_lookup_elem(
                &runnable_ts_map,
                &next_tid);

        if (wakeup_ts) {

            runqueue_delay_ns =
                now - *wakeup_ts;

            emit_cpu_event(
                next_pid,
                next_tid,
                CPU_EVENT_RUNQUEUE_DELAY,
                runqueue_delay_ns,
                0,
                now);

            ret = bpf_map_delete_elem(
                &runnable_ts_map,
                &next_tid);

            if (ret < 0)
                inc_cpu_stat(
                    CPU_STAT_DELETE_FAIL);

        } else {

            inc_cpu_stat(
                CPU_STAT_WAKEUP_MISS);
        }

        ret = bpf_map_update_elem(
            &oncpu_start_map,
            &next_tid,
            &now,
            BPF_ANY);

        if (ret < 0)
            inc_cpu_stat(
                CPU_STAT_ONCPU_UPDATE_FAIL);
    }

    /*
     * 已确认属于 tracer 的线程不能在状态 Map 中留下历史时间戳。
     */
    if (ignore_prev) {

        bpf_map_delete_elem(
            &oncpu_start_map,
            &prev_tid);

        bpf_map_delete_elem(
            &runnable_ts_map,
            &prev_tid);
    }

    if (ignore_next) {

        bpf_map_delete_elem(
            &oncpu_start_map,
            &next_tid);

        bpf_map_delete_elem(
            &runnable_ts_map,
            &next_tid);
    }

    return 0;
}


char LICENSE[] SEC("license") = "GPL";