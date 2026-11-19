#include "bpf_common.h"
#include "lock_probe.h"

#include <bpf/bpf_core_read.h> //自己的头文件用引号，系统或外部库的头文件用尖括号

/*lock_call_start 保存的是一次 futex 调用刚进入时的临时信息*/
struct lock_call_start {
    __u64 timestamp_ns;
    __u64 lock_addr;
    __u32 pid;
    __u32 tid;
    __u32 futex_op;
    __u32 is_wait;
};

/*下面定义5个BPF Map*/
KYLINRCA_DECLARE_HASH_MAP(start_map, __u64, struct lock_call_start, 16384); //	每个线程进入 futex 调用时的信息
KYLINRCA_DECLARE_RINGBUF(events, 256 * 1024); //准备发送的完整锁事件
KYLINRCA_DECLARE_TRACER_PID_MAP(config_map); //	观测程序自己的 PID

/*lock_config 保存探针配置：要观察谁，以及怎样识别 futex 等待？*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); //类型是数组，只有 1 个位置
    __uint(max_entries, 1); //用 __u32 类型的键 0 访问
    __type(key, __u32);
    __type(value, struct kylinrca_lock_config); //值是"lock_probe.h"中的kylinrca_lock_config，包含目标 PID、futex 编号等。
} lock_config SEC(".maps");

/*lock_stats 保存运行计数*/
struct {
    /*使用 PERCPU_ARRAY，表示每个 CPU 分别维护自己的计数，
    退出时由用户态汇总，减少多个 CPU 同时修改同一计数造成的竞争。*/
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, LOCK_STAT_MAX); //每个统计项占一个位置，总数为 LOCK_STAT_MAX。
    __type(key, __u32);
    __type(value, __u64);
} lock_stats SEC(".maps");

/*把指定统计项的计数加一*/
static __always_inline void inc_lock_stat(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&lock_stats, &key);
    if (value)
        (*value)++;
}

/*找到某个任务在指定 PID 命名空间里的编号，让输出能与你终端看到的编号对应。*/
static __always_inline __u32 visible_id(struct task_struct *task, __u64 inode)
{
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    if (!pid)
        return 0;
    unsigned int level = BPF_CORE_READ(pid, level);
    if (level > 32)
        return 0;
    for (int i = 0; i <= 32; ++i) {
        if (i > level)
            break;
        struct upid number = {};
        if (bpf_core_read(&number, sizeof(number), &pid->numbers[i]) < 0)
            return 0;
        if (number.ns && BPF_CORE_READ(number.ns, ns.inum) == inode) //number.ns：属于哪个命名空间
            return number.nr; //number.nr：在这个命名空间中的编号
    }
    return 0;
}

/*确定当前线程的 PID、TID，并判断是否应该采集它。*/
static __always_inline int current_identity(
    const struct kylinrca_lock_config *config,
    __u32 *pid,
    __u32 *tid)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    *tid = visible_id(task, config->namespace_inode);
    *pid = visible_id(BPF_CORE_READ(task, group_leader), config->namespace_inode);
    if (!*pid || !*tid || !kylinrca_pid_matches(*pid, config->target_pid))
        return 0;
    __u32 key = KYLINRCA_CONFIG_KEY;
    __u32 *tracer_pid = bpf_map_lookup_elem(&config_map, &key);

    //没有查到观测程序的 PID，或者当前进程不是观测程序自身，就返回 1，允许采集。
    return !tracer_pid || *pid != *tracer_pid;
}


/*delete_start() 用线程对应的 key，删除 start_map 中保存的调用起点。
如果删除失败，就增加 LOCK_STAT_DELETE_FAIL 计数。*/
static __always_inline void delete_start(__u64 key)
{
    if (bpf_map_delete_elem(&start_map, &key) < 0)
        inc_lock_stat(LOCK_STAT_DELETE_FAIL);
}

/*handle_lock_enter()：调用进入时保存信息。
  筛选需要观察的 futex 调用，记录线程的 PID/TID、操作类型、对象地址和开始时间，
  按线程保存到 start_map。同时标记它是否属于等待操作。*/
SEC("tracepoint/raw_syscalls/sys_enter") //把 handle_lock_enter() 挂到系统调用进入事件上。
int handle_lock_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 zero = 0;
    struct kylinrca_lock_config *config = bpf_map_lookup_elem(&lock_config, &zero);
    if (!config || !config->namespace_inode || ctx->id != config->futex_syscall_id)
        return 0;

    struct lock_call_start start = {};
    if (!current_identity(config, &start.pid, &start.tid))
        return 0;

    start.futex_op = (__u32)ctx->args[1];
    __u32 command = start.futex_op & config->futex_cmd_mask;
    start.is_wait = command == config->futex_wait || command == config->futex_wait_bitset;
    start.lock_addr = ctx->args[0];
    start.timestamp_ns = bpf_ktime_get_ns();

    inc_lock_stat(LOCK_STAT_FUTEX_ENTER);
    if (start.is_wait)
        inc_lock_stat(LOCK_STAT_WAIT_ENTER);

    __u64 key = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&start_map, &key, &start, BPF_ANY) < 0)
        inc_lock_stat(LOCK_STAT_START_UPDATE_FAIL);
    return 0;
}

/*handle_lock_exit()：调用退出时计算耗时并发送事件。
  找到同一线程保存的起点，取出后删除。如果是等待操作，
  就计算“退出时间减开始时间”，加上返回值等信息，组成锁事件，
  通过 RingBuffer 发给用户态。找不到起点、时间异常或缓冲区无法分配时，会记录对应计数。*/
SEC("tracepoint/raw_syscalls/sys_exit")
int handle_lock_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 zero = 0;
    struct kylinrca_lock_config *config = bpf_map_lookup_elem(&lock_config, &zero);
    if (!config || !config->namespace_inode || ctx->id != config->futex_syscall_id)
        return 0;

    __u64 key = bpf_get_current_pid_tgid();
    struct lock_call_start *found = bpf_map_lookup_elem(&start_map, &key);
    if (!found) {
        __u32 pid = 0, tid = 0;
        if (current_identity(config, &pid, &tid))
            inc_lock_stat(LOCK_STAT_START_MISS);
        return 0;
    }

    struct lock_call_start start = *found;
    __u64 now = bpf_ktime_get_ns();
    delete_start(key);
    if (!start.is_wait)
        return 0;

    inc_lock_stat(LOCK_STAT_WAIT_EXIT);
    if (now < start.timestamp_ns) {
        inc_lock_stat(LOCK_STAT_BAD_TIMESTAMP);
        return 0;
    }

    //向 events 环形缓冲区申请一块空间，用来填写一条锁事件，并把这块空间的地址保存到指针 event 中。
    struct kylinrca_lock_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        inc_lock_stat(LOCK_STAT_RINGBUF_DROP);
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->header.version = KYLINRCA_EVENT_VERSION;
    event->header.type = EVENT_TYPE_LOCK;
    event->header.size = sizeof(*event);
    event->header.timestamp_ns = now;
    event->header.pid = start.pid;
    event->header.tid = start.tid;
    event->lock_addr = start.lock_addr;
    event->duration_ns = now - start.timestamp_ns;
    event->ret = ctx->ret;
    event->futex_op = start.futex_op;
    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*handle_lock_thread_exit()：线程退出时清理。
检查退出线程是否还有起点记录；如果有，就删除并计数，避免残留记录一直占用 Map 空间。*/
SEC("tracepoint/sched/sched_process_exit")
int handle_lock_thread_exit(void *ctx)
{
    (void)ctx;
    __u64 key = bpf_get_current_pid_tgid();
    if (bpf_map_lookup_elem(&start_map, &key)) {
        delete_start(key);
        inc_lock_stat(LOCK_STAT_THREAD_EXIT_CLEANUP);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
