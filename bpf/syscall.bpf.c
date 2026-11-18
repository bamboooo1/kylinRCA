#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "event.h"
#include "bpf_common.h"

struct syscall_start {
	__u64 timestamp_ns;
	__s64 syscall_id;
	__u32 pid;
	__u32 tid;
};

/*
 * Syscall 临时状态：
 *
 * key   = pid_tgid
 * value = syscall enter 时的信息
 */
KYLINRCA_DECLARE_HASH_MAP(
    start_map,
    __u64,
    struct syscall_start,
    16384
); // 创建了一个名叫 start_map 的全局 Map 定义，所以后面的函数可以直接使用

KYLINRCA_DECLARE_RINGBUF(
    events,
    256 * 1024
);// 环形缓冲区，把完整事件传给用户态


/*
 * config_map[0] = tracer PID
 */
KYLINRCA_DECLARE_TRACER_PID_MAP(config_map);

// namespace_config[0] 保存采集程序所在 PID 命名空间的 inode。
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} namespace_config SEC(".maps");

// 查找任务在指定命名空间中的编号；该任务不可见或读取失败时返回 0。
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
        if (number.ns && BPF_CORE_READ(number.ns, ns.inum) == inode)
            return number.nr;
    }
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_enter") //挂载到sys_enter，Linux内核调用
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid;
    struct syscall_start start = {};

    __u32 zero = 0;
    __u64 *inode = bpf_map_lookup_elem(&namespace_config, &zero);
    if (!inode || !*inode)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    start.tid = visible_id(task, *inode);
    start.pid = visible_id(BPF_CORE_READ(task, group_leader), *inode);
    if (!start.pid || !start.tid)
        return 0;

    // config_map 中是 getpid() 的结果，必须用同一命名空间的 PID 比较。
    __u32 *tracer_pid = bpf_map_lookup_elem(&config_map, &zero);
    if (tracer_pid && start.pid == *tracer_pid)
        return 0;

    // 内部配对仍使用内核编号，避免不同命名空间中的相同编号混淆。
    pid_tgid = bpf_get_current_pid_tgid();

    start.timestamp_ns = bpf_ktime_get_ns();
    start.syscall_id = ctx->id;

    bpf_map_update_elem(&start_map, &pid_tgid, &start, BPF_ANY); // （操作哪个 Map，key 的地址， value 的地址， 存在就覆盖，不存在就新增）

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid;
	__u64 end_ns;

	struct syscall_start *start; //bpf_map_lookup_elem() 成功以后返回的是：指向 Map 中 value 的指针
	struct syscall_event *event;				

	pid_tgid = bpf_get_current_pid_tgid();

	start = bpf_map_lookup_elem(&start_map, &pid_tgid);

	if(!start) return 1;

	end_ns = bpf_ktime_get_ns();

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0); //从 events RingBuffer 中预留一块能够存放一个 syscall_event 的空间
	if(!event)
	{
		bpf_map_delete_elem(&start_map, &pid_tgid);
		return 1;
	}

    event->header.version = KYLINRCA_EVENT_VERSION;
    event->header.type = EVENT_TYPE_SYSCALL;
    event->header.size = sizeof(*event);

    event->header.timestamp_ns = start->timestamp_ns;
    event->header.pid = start->pid;
    event->header.tid = start->tid;

    event->syscall_id = start->syscall_id;
    event->ret = ctx->ret; //当前 syscall 最终返回值，做异常定位

    event->duration_ns = end_ns - start->timestamp_ns; //syscall 内核执行路径的elapsed time
	bpf_ringbuf_submit(event, 0); 

	bpf_map_delete_elem(&start_map, &pid_tgid);

	return 0;
}



char LICENSE[] SEC("license") = "GPL";
