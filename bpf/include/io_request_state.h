#ifndef KYLINRCA_IO_REQUEST_STATE_H
#define KYLINRCA_IO_REQUEST_STATE_H
/* Private probe state, shared only with its lifecycle tests/diagnostics.
 * Public event/config/stat headers and event ABI stay unchanged. */
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
struct io_request_start {
    __u64 start_ns;
    __u64 bytes;
    __u64 sector;
    __u32 major;
    __u32 minor;
    __u32 operation;
    __u32 status;
    __u64 requeue_count; //重排次数
    __u32 awaiting_reissue; //重排等待下发的标志
};
enum io_lifecycle_stat {
    IO_LIFE_REQUEUED_COMPLETED, //统计有多少个最终完成的请求经历过 requeue
    IO_LIFE_COMPLETED_REQUEUES, //统计这些完成请求累计经历的 requeue 次数
    IO_LIFE_MAX_REQUEUES, //记录完成请求中，单个请求最多 requeue 多少次
    IO_LIFE_UNEXPECTED_REISSUE, //统计没有先观察到 requeue，却再次收到 issue 的次数
    IO_LIFE_RELEASE_CLEANUP, //统计请求释放时补充清理了多少条遗留记录
    IO_LIFE_MAX //	表示前面共有多少种统计项，用来设置存储容量和遍历范围
};
static __inline __attribute__((always_inline)) void
io_state_requeue(struct io_request_start *s)
{
    if (s->requeue_count != ~(__u64)0) ++s->requeue_count;
    s->awaiting_reissue = 1;
}
/* Return whether the repeat issue was preceded by an observed requeue. */
static __inline __attribute__((always_inline)) int
io_state_reissue(struct io_request_start *s)
{
    int expected = s->awaiting_reissue != 0; //检查此前是否标记了 requeue
    s->awaiting_reissue = 0;
    return expected;
}
static __inline __attribute__((always_inline)) int
io_state_complete(struct io_request_start *s, __u32 status,
                  __u32 completed, __u32 remaining, int has_bio)
{
    if (status && !s->status) s->status = status; //如果本次出现错误，而且之前还没有记录过错误，就把这次错误保存下来。
    return !has_bio || completed >= remaining; //判断是否为部分完成
}
#endif
