#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

struct syscall_start {
	__u64 timestamp_ns;
	__s32 syscall_id;
};

struct syscall_event { 
    __u32 pid;
    __u32 tid;

    __s64 syscall_id;
    __s64 ret;

    __u64 timestamp_ns;
    __u64 duration_ns;
};


struct {
	__uint(type, BPF_MAP_TYPE_HASH); //创建一种 Hash 类型的 BPF Map 用于保存syscall临时状态
	__uint(max_entries, 16384); //这个 Hash Map 最多容纳 16384 个 key-value
	__type(key, __u64);
	__type(value, struct syscall_start);
} start_map SEC(".maps"); //把这个对象放到 ELF 文件的 .maps section。
			  
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);// 环形缓冲区，把完整事件传给用户态
	__uint(max_entries, 256 * 1024); //RingBuffer 总容量，单位是 byte
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);// 创建数组保存用户态自身的tracer PID
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} config_map SEC(".maps");
			  
SEC("tracepoint/raw_syscalls/sys_enter") //挂载到sys_enter，Linux内核调用
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	__u64 pid_tgid;
	__u32 config_key = 0;
	__u32 *tracer_pid;
	struct syscall_start start= {}; //把整个结构体初始化为 0

	pid_tgid = bpf_get_current_pid_tgid();//得到的就是这个 syscall 调用者
	tracer_pid = bpf_map_lookup_elem(&config_map, &config_key);

	if(tracer_pid && (__u32)(pid_tgid >> 32) == *tracer_pid) //忽略用户态自身的PID，避免自观测反馈
	{
		return 0;
	}	

	start.timestamp_ns = bpf_ktime_get_ns();
	start.syscall_id = ctx->id; //保存syscall id

	bpf_map_update_elem(&start_map, &pid_tgid, &start, BPF_ANY);

	return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int handle_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid;
	__u64 end_ns;
	__u32 config_key = 0;
	__u32 *tracer_pid;
	struct syscall_start *start; //bpf_map_lookup_elem() 成功以后返回的是：指向 Map 中 value 的指针
	struct syscall_event *event;				

	pid_tgid = bpf_get_current_pid_tgid();

	tracer_pid = bpf_map_lookup_elem(&config_map, &config_key);

	if (tracer_pid && (__u32)(pid_tgid >> 32) == *tracer_pid)
        	return 0;

	start = bpf_map_lookup_elem(&start_map, &pid_tgid);

	if(!start)
	{
		return 1;
	}

	end_ns = bpf_ktime_get_ns();

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0); //从 events RingBuffer 中预留一块能够存放一个 syscall_event 的空间
	if(!event)
	{
		bpf_map_delete_elem(&start_map, &pid_tgid);
		return 1;
	}

	event->pid = pid_tgid >> 32; //右移32位，取高32位得到pid
	event->tid = (__u32)pid_tgid; //强制类型转换，得到低32位；
	event->syscall_id = start->syscall_id;
	event->ret = ctx->ret; //当前 syscall 最终返回值，做异常定位
	event->timestamp_ns = start->timestamp_ns;
	event->duration_ns = end_ns - start->timestamp_ns; //syscall 内核执行路径的elapsed time

	bpf_ringbuf_submit(event, 0); 

	bpf_map_delete_elem(&start_map, &pid_tgid);

	return 0;
}



char LICENSE[] SEC("license") = "GPL";
