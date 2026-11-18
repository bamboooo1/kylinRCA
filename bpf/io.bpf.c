#include "bpf_common.h"
#include "event.h"
#include "io_probe_stats.h"
#include <bpf/bpf_core_read.h>

/*
 * rq 指针仅作为内核内部关联键，不发送给用户态。
 * 普通 HASH 跨 CPU 共享；容量固定，满时计数而不静默淘汰请求。
 */
struct io_request_start {
    __u64 start_ns;
    __u64 bytes; //记录开始时的请求长度，避免之后请求被部分完成而改变
    __u64 sector;
    __u32 major;
    __u32 minor;
    __u32 operation;
    __u32 status; //初始为 0；部分完成遇到错误时，保存错误状态
};
KYLINRCA_DECLARE_HASH_MAP(
    io_starts, // Map 的名字
    __u64, // key：请求地址转换成的整数
    struct io_request_start, // value：开始记录
    16384 // 最多保存多少条记录
);
KYLINRCA_DECLARE_RINGBUF(events, 256 * 1024);
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); //每个CPU分别记录各自的数据
    __uint(max_entries, IO_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} io_stats SEC(".maps");

/* 0 表示采集所有设备；编号与 gendisk 的 major/first_minor 对应。 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kylinrca_io_config);
} io_config SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *value = bpf_map_lookup_elem(&io_stats, &key);
    if (value)
        (*value)++;
}

static __always_inline void forget(__u64 key)
{
    if (bpf_map_delete_elem(&io_starts, &key))
        count(IO_STAT_MAP_DELETE_FAIL);
}

/*
 * 当前内核原始参数：issue(rq)、complete(rq, status, nr_bytes)。
 * 使用 CO-RE 读取成员偏移，raw tracepoint 的参数签名由 Loader 的
 * BTF 检查确认。CO-RE 本身不会自动适配参数数量/顺序。
 *  取得请求地址
        ↓
    记录时间、读取请求信息
        ↓
    检查设备过滤
        ↓
    转换操作编号
        ↓
    把开始记录写入 io_starts
 */
SEC("raw_tracepoint/block_rq_issue")
int handle_io_issue(struct bpf_raw_tracepoint_args *ctx)
{
    struct request *rq = (void *)ctx->args[0]; //取出请求指针
    __u64 key = (__u64)rq;  //请求地址
    struct gendisk *disk = 0;
    struct io_request_start start = {};
    __u32 flags = 0, bytes = 0;

    /* 先取时，避免在记录操作中增加可变开销。 */
    start.start_ns = bpf_ktime_get_ns();
    if (BPF_CORE_READ_INTO(&disk, rq, q, disk) || !disk || // 读取请求对象的请求队列中的磁盘对象
        BPF_CORE_READ_INTO(&start.major, disk, major) || //读取主设备
        BPF_CORE_READ_INTO(&start.minor, disk, first_minor) || //读取副设备
        BPF_CORE_READ_INTO(&flags, rq, cmd_flags) || //读取操作标志
        BPF_CORE_READ_INTO(&bytes, rq, __data_len) || //读取长度
        BPF_CORE_READ_INTO(&start.sector, rq, __sector)) {  //读取扇区位置
        count(IO_STAT_READ_FAIL);
        return 0;
    }
    __u32 zero = 0;
    struct kylinrca_io_config *cfg = bpf_map_lookup_elem(&io_config, &zero);
    if (cfg && cfg->filter_device &&
        (start.major != cfg->major || start.minor != cfg->minor))
        return 0;   //检测设备编号是否匹配
    count(IO_STAT_ISSUE);

    /*
     * Linux 的 REQ_OP_BITS 为 8，其他 cmd_flags 是标志位。
     * 不把内核编号直接当作项目协议编号。
     */
    __u32 op = flags & 0xff; //flags 同时包含操作编号和其他标志，`& 0xff` 取出低 8 位的操作编号，再转换成项目约定的编号。
    start.operation = op == REQ_OP_READ ? IO_OP_READ :
                      op == REQ_OP_WRITE ? IO_OP_WRITE : IO_OP_OTHER;
    start.bytes = bytes;
    if (bpf_map_lookup_elem(&io_starts, &key)) //如果请求已经存在就记录一次reissue
        count(IO_STAT_REISSUE);
    /* 每次 issue 重置：延迟口径是最近一次 issue 到最终完成。 */
    if (bpf_map_update_elem(&io_starts, &key, &start, BPF_ANY))
        count(IO_STAT_MAP_UPDATE_FAIL);
    return 0;
}

SEC("raw_tracepoint/block_rq_complete")
int handle_io_complete(struct bpf_raw_tracepoint_args *ctx)
{
    struct request *rq = (void *)ctx->args[0];
    __u64 key = (__u64)rq;
    struct io_request_start *saved = bpf_map_lookup_elem(&io_starts, &key);
    if (!saved) {
        /* 启动前在途请求、过滤设备的请求也可能没有开始记录。 */
        count(IO_STAT_UNMATCHED);
        return 0;
    }
    __u64 now = bpf_ktime_get_ns(); //完成时间
    __u32 status = (__u8)ctx->args[1]; //本次完成状态
    __u32 completed = (__u32)ctx->args[2]; //本次完成的字节数：比如一个 8192 字节的请求，可能分两次通知完成
    __u32 remaining = 0;
    struct bio *bio = 0;
    count(IO_STAT_COMPLETE);
    if (BPF_CORE_READ_INTO(&remaining, rq, __data_len) || //读取本次请求的剩余字节数
        BPF_CORE_READ_INTO(&bio, rq, bio)) {
        count(IO_STAT_READ_FAIL);
        forget(key);
        return 0;
    }

    /*
     * 遇到第一个非零错误状态，就把它记住
     * 第一次部分完成可能报错，而最后一次完成的状态可能是 0。如果只看最后一次，就可能丢掉之前的错误证据。
     */
    if (status && !saved->status) 
        saved->status = status;

    /*
     * blk_update_request 在更新 bio/__data_len 之前触发 complete。
     * bio 存在且本次只完成一部分时保留记录，不能提前删除。
     * 无 bio（例如 flush）或完成量覆盖剩余量才输出。例如：
     *  第一次通知：
        remaining = 8192
        completed = 4096
        → 部分完成，保留记录

        内核随后把剩余长度更新为 4096

        第二次通知：
        remaining = 4096
        completed = 4096
        → 覆盖剩余长度，可以进入最终完成处理
     */
    if (bio && completed < remaining) {
        count(IO_STAT_PARTIAL);
        return 0;
    }

    struct io_request_start start = *saved;
    forget(key); /* 即使 RingBuffer 满，也回收请求，避免地址复用串联。 */
    if (now < start.start_ns) {
        count(IO_STAT_BAD_TIMESTAMP);
        return 0;
    }
    struct kylinrca_io_event *event =
        bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        count(IO_STAT_RINGBUF_DROP);
        return 0;
    }
    __builtin_memset(event, 0, sizeof(*event));
    event->header.version = KYLINRCA_EVENT_VERSION;
    event->header.type = EVENT_TYPE_IO;
    event->header.size = sizeof(*event);
    event->header.timestamp_ns = now;
    /* 异步 I/O 完成上下文不能代表发起进程；pid/tid 保留为 0。 */
    event->duration_ns = now - start.start_ns;
    event->bytes = start.bytes;
    event->sector = start.sector;
    event->dev_major = start.major;
    event->dev_minor = start.minor;
    event->operation = start.operation;
    event->status = start.status;
    bpf_ringbuf_submit(event, 0); /* 默认自适应通知，不强制每条唤醒。 */
    count(IO_STAT_EMITTED);
    return 0;
}

SEC("raw_tracepoint/block_rq_requeue")
int handle_io_requeue(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 key = ctx->args[0];
    if (bpf_map_lookup_elem(&io_starts, &key)) {
        count(IO_STAT_REQUEUE);
        forget(key); /* 丢弃本次尝试，下一次 issue 重新计时。 */
    }
    return 0; //重排队表示：本次下发没有让请求最终完成，请求被放回队列，等待再次处理。
}

char LICENSE[] SEC("license") = "GPL";
