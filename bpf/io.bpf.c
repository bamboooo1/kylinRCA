#include "bpf_common.h"
#include "event.h"
#include "io_probe_stats.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "io_request_state.h"

/*
 * rq 指针仅作为内核内部关联键，不发送给用户态。
 * 普通 HASH 跨 CPU 共享；容量固定，满时计数而不静默淘汰请求。
 */
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

/* 存放新增的生命周期统计 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, IO_LIFE_MAX);
    __type(key, __u32);
    __type(value, __u64);
} io_lifecycle_stats SEC(".maps");
static __always_inline void lifecycle_add(__u32 key, __u64 amount)
{
    __u64 *value = bpf_map_lookup_elem(&io_lifecycle_stats, &key);
    if (value) {
        if (key == IO_LIFE_MAX_REQUEUES) { //对于“IO_LIFE_MAX_REQUEUES”，只在新值更大时更新value
            if (amount > *value) *value = amount;
        } else {
            *value = amount > ~(__u64)0 - *value ? ~(__u64)0 : *value + amount;
        }
    }
}

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

/* 内核准备释放这个请求时，如果我们的 Map 还留着它的记录，就补充删除。
 * 现在 requeue 不再删除记录，如果某个请求走了释放路径，却没有被我们的最终完成处理清理，旧记录就可能残留。
 * 以后同一个地址被新请求使用时，就可能串到旧记录上。 */
SEC("kprobe/__blk_mq_free_request")
int BPF_KPROBE(handle_io_free, struct request *rq)
{
    __u64 key = (__u64)rq;
    if (bpf_map_lookup_elem(&io_starts, &key)) {
        lifecycle_add(IO_LIFE_RELEASE_CLEANUP, 1);
        forget(key);
    }
    return 0;
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
    struct io_request_start *saved = bpf_map_lookup_elem(&io_starts, &key);
    if (saved) {
        count(IO_STAT_REISSUE); //如果这个地址的issue已经存在，就标记reissue
        if (!io_state_reissue(saved)) //如果没有观察到重新排队，却又发生了 issue
            lifecycle_add(IO_LIFE_UNEXPECTED_REISSUE, 1);
        return 0;
    }
    if (bpf_map_update_elem(&io_starts, &key, &start, BPF_NOEXIST))
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
     * 判断此次为全部完成还是部分完成
     */
    if (!io_state_complete(saved, status, completed, remaining, bio != 0)) {
        count(IO_STAT_PARTIAL);
        return 0;
    }

    struct io_request_start start = *saved;
    if (start.requeue_count) {
        lifecycle_add(IO_LIFE_REQUEUED_COMPLETED, 1);
        lifecycle_add(IO_LIFE_COMPLETED_REQUEUES, start.requeue_count);
        lifecycle_add(IO_LIFE_MAX_REQUEUES, start.requeue_count);
    }
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
    /* 首次观测到 issue -> 最终完成, 包括重排. */
    event->duration_ns = now - start.start_ns;
    event->bytes = start.bytes; /* 第一次issue时的字节长度. */
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
    struct io_request_start *saved = bpf_map_lookup_elem(&io_starts, &key);
    if (saved) {
        count(IO_STAT_REQUEUE);
        io_state_requeue(saved);
    }
    return 0; //重排队表示：本次下发没有让请求最终完成，请求被放回队列，等待再次处理。
}

char LICENSE[] SEC("license") = "GPL";
