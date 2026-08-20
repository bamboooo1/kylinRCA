#include "bpf_common.h"
#include "event.h"

/*
 * 当前 Ubuntu 内核 sched_switch 的 prev_state：
 *
 * 低 8 位表示任务状态。
 * 低 8 位为 0 表示任务仍然 runnable。
 *
 * 当前先按 Ubuntu 实际 tracepoint format 实现。
 * ARM64 / 不同内核版本兼容后续统一处理。
 */
#define KYLINRCA_SCHED_STATE_MASK 0xffUL //掩码，用来取出 `prev_state` 的最低 8 个 bit

KYLINRCA_DECLARE_HASH_MAP(
       runnable_ts_map,
       __u32,
       __u64,
       16384
); //用于获得线程进入cpu等待队列的时间
			      
KYLINRCA_DECLARE_HASH_MAP(
       oncpu_start_map,
       __u32,
       __u64,
       16384
);//用于获得线程正式被cpu处理的时间
				
KYLINRCA_DECLARE_RINGBUF(
       events,
       256 * 1024
);

/*
 * 错误处理：Probe 自身运行状态统计。
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
 * 高频 tracepoint 下不同 CPU 修改自己的 counter，
 * 避免所有 CPU 竞争同一个计数值。
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CPU_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} cpu_stats SEC(".maps");

/* 
 * `__always_inline`：
 * eBPF 特有，强制编译器把这个函数**内联展开**，
 * 不生成独立函数调用（eBPF 字节码限制，很多时候不能普通函数调用）
 */
static __always_inline void inc_cpu_stat(__u32 key)
{
	__u64 *value;

	value = bpf_map_lookup_elem(&cpu_stats, &key);

	if(value)
		(*value)++; //计算错误出现的次数
}

/*
 * sched_switch 结构体中记录了上一线程被中断的状态，
 * 可以用于判断该线程：CPU是否为被抢占（被抢占后会重新等待CPU）
 */
static __always_inline int prev_is_runnable(long prev_state)
{
	return (prev_state & KYLINRCA_SCHED_STATE_MASK) == 0;
}

static __always_inline void emit_cpu_event( // cpu_event发送函数
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
        inc_cpu_stat(CPU_STAT_RINGBUF_DROP);
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

    /*
     * 当前 tracepoint 只能直接得到 TID。
     * TGID 后续再补。
     */
    event->header.pid = 0;
    event->header.tid = tid;

    event->kind = kind;
    event->reserved = 0;

    event->runqueue_delay_ns =
        runqueue_delay_ns;

    event->on_cpu_time_ns =
        on_cpu_time_ns;

    bpf_ringbuf_submit(event, 0);
}



SEC("tracepoint/sched/sched_wakeup") //已有线程被唤醒
int handle_sched_wakeup(
	struct trace_event_raw_sched_wakeup_template *ctx)
{
	__u32 tid;
	__u64 now;
	int ret;

	tid = (__u32)ctx->pid; //获取当前被唤醒的线程tid
			       
	if(tid==0)
		return 0;
	
	now = bpf_ktime_get_ns(); //获取线程被唤醒的时刻
				  
	ret = bpf_map_update_elem(
			&runnable_ts_map,
			&tid,
			&now,
			BPF_ANY);
	if(ret<0)
		inc_cpu_stat(CPU_STAT_WAKEUP_UPDATE_FAIL);

	return 0;
}

SEC("tracepoint/sched/sched_wakeup_new") //新线程第一次被唤醒
int handle_sched_wakeup_new(
    struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 tid;
    __u64 now;
    int ret;

    tid = (__u32)ctx->pid;

    if (tid == 0)
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

SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(
		struct trace_event_raw_sched_switch *ctx)
{
	__u32 next_tid;
	__u32 prev_tid;
	__u64 now;

	__u64 *oncpu_start;
	__u64 on_cpu_time_ns;

	__u64 *wakeup_ts;
	__u64 runqueue_delay_ns;

	int ret;

	prev_tid = (__u32)ctx->prev_pid; //获取CPU上一个刚执行完的线程tid
	next_tid = (__u32)ctx->next_pid; //获取当前CPU正在执行的线程tid
	
	now = bpf_ktime_get_ns();//获取CPU切换线程的时间

	/*
	 * 1、处理被切下CPU的线程：
	 *    计算它刚刚运行了多久。
	 */

	if(prev_tid !=0)
	{
		oncpu_start = bpf_map_lookup_elem(&oncpu_start_map, &prev_tid);
		if(oncpu_start)
		{
			on_cpu_time_ns = now - *oncpu_start;

			emit_cpu_event(prev_tid, CPU_EVENT_ONCPU_TIME, 0, on_cpu_time_ns, now);

			ret = bpf_map_delete_elem(&oncpu_start_map, &prev_tid);

			if(ret<0)
				inc_cpu_stat(CPU_STAT_DELETE_FAIL);
		}

        	else {
            	/*
            	 * 不一定是真正的程序错误。
            	 *
            	 * 例如 Probe 刚 attach 时，
            	 * 这个线程已经在 CPU 上运行，
            	 * 我们没有看到它之前的 switch-in。
            	 */
            		inc_cpu_stat(CPU_STAT_ONCPU_MISS);
        	}
	}

	/*
 	* 如果 prev 被切下 CPU 后仍然 runnable，
 	* 那么它从 now 开始重新进入 runqueue 等待 CPU。
 	*/
	if (prev_tid != 0 && prev_is_runnable(ctx->prev_state)) 
	{
    		ret = bpf_map_update_elem(
        	&runnable_ts_map,
        	&prev_tid,
        	&now,
        	BPF_ANY);

    		if (ret < 0)
        		inc_cpu_stat(CPU_STAT_REQUEUE_UPDATE_FAIL);
	}

	/*
	 * 2、处理即将被调度到CPU上的线程：
	 *   计算它在runqueue中等待了多久。
	 */
	
	if(next_tid !=0) 
	{
		wakeup_ts = bpf_map_lookup_elem(&runnable_ts_map, &next_tid);
		if(wakeup_ts)
		{
			runqueue_delay_ns = now - *wakeup_ts;

			emit_cpu_event(next_tid, CPU_EVENT_RUNQUEUE_DELAY, runqueue_delay_ns, 0, now);

			ret = bpf_map_delete_elem(&runnable_ts_map, &next_tid);

			if(ret<0)
				inc_cpu_stat(CPU_STAT_DELETE_FAIL);
		}
		else {
			inc_cpu_stat(CPU_STAT_WAKEUP_MISS);
		}

		ret = bpf_map_update_elem(&oncpu_start_map, &next_tid, &now, BPF_ANY); //新进程开始时间
		
		if(ret<0)
			inc_cpu_stat(CPU_STAT_ONCPU_UPDATE_FAIL);
	}

	return 0;
}

char LICENSE[] SEC("license") = "GPL";

