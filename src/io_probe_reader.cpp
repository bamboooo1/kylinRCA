#include "io_probe_reader.h"
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <linux/btf.h>
#include <cerrno>
#include <algorithm>
#include <sstream>
#include <vector>

// 兼容性检查的辅助函数：解析给定 BTF 类型，确认它是指向内核 request 结构的指针。
// 找不到类型或解析到其他类型时返回 false，避免把跟踪点参数误当成块请求。
static bool request_pointer(const btf *types, unsigned id)
{
    int resolved = btf__resolve_type(types, id);
    if (resolved < 0) return false;
    auto *t = btf__type_by_id(types, resolved);
    if (!t || btf_kind(t) != BTF_KIND_PTR) return false;
    resolved = btf__resolve_type(types, t->type);
    if (resolved < 0) return false;
    t = btf__type_by_id(types, resolved);
    return t && btf_kind(t) == BTF_KIND_STRUCT &&
           std::string(btf__name_by_offset(types, t->name_off)) == "request";
}

// 检查一个跟踪点的函数原型：核对实际参数数量、请求指针，以及完成通知的状态和字节数类型。
// count 是探针预期的实际参数数量；任何必要类型不匹配都返回 false。
static bool check_prototype(const btf *types, const char *name, unsigned count)
{
    int id = btf__find_by_name_kind(types, name, BTF_KIND_TYPEDEF);
    if (id < 0) return false;
    int resolved = btf__resolve_type(types, id);
    if (resolved < 0) return false;
    auto *t = btf__type_by_id(types, resolved);
    if (!t || btf_kind(t) != BTF_KIND_PTR) return false;
    t = btf__type_by_id(types, t->type);
    // BTF 描述的跟踪处理函数比实际跟踪点多一个前置上下文参数，因此检查时多计一个参数。
    if (!t || btf_kind(t) != BTF_KIND_FUNC_PROTO || btf_vlen(t) != count + 1)
        return false;
    const auto *p = btf_params(t);
    if (!request_pointer(types, p[1].type)) return false;
    if (count == 3) {
        int status_id = btf__resolve_type(types, p[2].type);
        int bytes_id = btf__resolve_type(types, p[3].type);
        auto *s = status_id > 0 ? btf__type_by_id(types, status_id) : nullptr;
        auto *b = bytes_id > 0 ? btf__type_by_id(types, bytes_id) : nullptr;
        if (!s || !b || btf_kind(s) != BTF_KIND_INT ||
            btf_kind(b) != BTF_KIND_INT || s->size != 1 || b->size != 4)
            return false;
    }
    return true;
}


// daemon 加载 I/O 前调用：读取当前内核 BTF，依次检查请求下发、完成和重排三个跟踪点。
// 释放临时 BTF 对象后返回检查结果；不会加载或挂载 I/O 程序。
bool io_probe_compatible()
{
    btf* types = btf__load_vmlinux_btf();
    if (!types || libbpf_get_error(types)) return false;
    const bool compatible = check_prototype(types, "btf_trace_block_rq_issue", 1) &&
        check_prototype(types, "btf_trace_block_rq_complete", 3) &&
        check_prototype(types, "btf_trace_block_rq_requeue", 1);
    btf__free(types);
    return compatible;
}
// 将配置管理器已经校验的设备条件写入 io_config，供内核在记录请求时过滤设备。
// device 为空时关闭过滤；写入发生在程序加载完成之后、开始挂载之前。
bool configure_io_probe(bpf_object* object, const std::string& device)
{
    kylinrca_io_config config{};
    if (!device.empty()) {
        //当 device 非空时（预期格式为 "主设备号:次设备号"，例如 "8:0"）
        const auto colon = device.find(':');
        config.filter_device = 1;
        config.major = std::stoul(device.substr(0, colon));
        config.minor = std::stoul(device.substr(colon + 1));
    }
    const __u32 zero = 0;
    const int fd = bpf_object__find_map_fd_by_name(object, "io_config");
    return fd >= 0 && bpf_map_update_elem(fd, &zero, &config, BPF_ANY) == 0;
}
// 主线程读取累计健康数据：汇总各 CPU 的普通计数、生命周期计数，并遍历未完成请求表。
// 最大重排次数取各 CPU 最大值，其余相应计数求和；运行中读取并非同一时刻的原子快照。
bool read_io_probe_health(bpf_object* object, IoProbeHealth& health)
{
    const int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) return false;
    std::vector<__u64> values(cpus);
    // 读取一张按 CPU 分开的计数表；max_key 指定需要取最大值的项目，其他项目累加。
    const auto read = [&](const char* name, auto& output, int max_key) {
        const int fd = bpf_object__find_map_fd_by_name(object, name);
        if (fd < 0) return false;
        for (__u32 k = 0; k < output.size(); ++k) {
            if (bpf_map_lookup_elem(fd, &k, values.data())) return false;
            output[k] = 0;
            for (auto v : values)
                output[k] = int(k) == max_key ? std::max<uint64_t>(output[k], v) : output[k] + v;
        }
        return true;
    };
    if (!read("io_stats", health.stats, -1) ||
        !read("io_lifecycle_stats", health.lifecycle, IO_LIFE_MAX_REQUEUES)) return false;
    const int fd = bpf_object__find_map_fd_by_name(object, "io_starts");
    if (fd < 0) return false;
    // 采集期间请求表会变化，限制遍历次数以免主线程长期停留；退出后可核对最终残留数量。
    __u64 key = 0, next = 0;
    health.pending = 0;
    int error = bpf_map_get_next_key(fd, nullptr, &next);
    while (!error && health.pending < 16384) {
        ++health.pending;
        key = next;
        error = bpf_map_get_next_key(fd, &key, &next);
    }
    return !error || errno == ENOENT;
}
// 按固定字段名把健康数据转换为 JSON，使丢失、错误、重排和未清理记录能够单独追踪。
// 输入是已读取的数据副本，本函数不读取 BPF map，也不计算设备延迟。
std::string io_probe_health_json(const IoProbeHealth& h)
{
    const char* names[] = {"issue", "complete", "partial", "requeue", "unmatched",
        "map_update_fail", "map_delete_fail", "ringbuf_drop", "bad_timestamp",
        "read_fail", "emitted", "reissue"};
    const char* life[] = {"requeued_completed", "completed_requeues", "max_requeues",
        "unexpected_reissue", "release_cleanup"};
    std::ostringstream out;
    out << "{\"type\":\"io_probe_stats\",\"pending\":" << h.pending;
    for (std::size_t i = 0; i < h.stats.size(); ++i)
        out << ",\"" << names[i] << "\":" << h.stats[i];
    for (std::size_t i = 0; i < h.lifecycle.size(); ++i)
        out << ",\"" << life[i] << "\":" << h.lifecycle[i];
    out << '}';
    return out.str();
}
