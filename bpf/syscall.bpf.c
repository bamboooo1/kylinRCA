#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "event.h"
#include "bpf_common.h"

struct syscall_start {
	__u64 timestamp_ns;
	__s64 syscall_id;
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
			  
SEC("tracepoint/raw_syscalls/sys_enter") //挂载到sys_enter，Linux内核调用
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid;
    struct syscall_start start = {};

    pid_tgid = bpf_get_current_pid_tgid(); // 使用 BPF common 获取 PID/TID 组合值。

    if (kylinrca_should_skip_tracer(&config_map, pid_tgid))
        return 0; // 忽略 KylinRCA tracer 自己产生的 syscall

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

	if (kylinrca_should_skip_tracer(&config_map, pid_tgid))  return 0;

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
    event->header.pid = kylinrca_pid_from_pid_tgid(pid_tgid);
    event->header.tid = kylinrca_tid_from_pid_tgid(pid_tgid);

    event->syscall_id = start->syscall_id;
    event->ret = ctx->ret; //当前 syscall 最终返回值，做异常定位

    event->duration_ns = end_ns - start->timestamp_ns; //syscall 内核执行路径的elapsed time
	bpf_ringbuf_submit(event, 0); 

	bpf_map_delete_elem(&start_map, &pid_tgid);

	return 0;
}



char LICENSE[] SEC("license") = "GPL";
