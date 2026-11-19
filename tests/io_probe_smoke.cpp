#include "event.h"
#include "io_probe_stats.h"
#include "../bpf/include/io_request_state.h"
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/btf.h>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

static_assert(sizeof(kylinrca_io_event) == 64, "Unexpected I/O event ABI");
static volatile sig_atomic_t running = 1;
static void stop(int) { running = 0; }

struct Consumer {
    unsigned long long received = 0, invalid = 0, reads = 0, writes = 0, bytes = 0;
    unsigned long long limit = 20;
};

/* 定义接收函数：
 * 每消费到一条事件，就调用一次这个函数来处理它 
 */
static int receive(void *ctx, void *data, size_t size)
{
    auto &c = *static_cast<Consumer *>(ctx);
    kylinrca_io_event e{};
    if (size != sizeof(e)) {
        ++c.invalid;
        return 0;
    }
    std::memcpy(&e, data, sizeof(e));
    if (e.header.version != KYLINRCA_EVENT_VERSION ||
        e.header.type != EVENT_TYPE_IO || e.header.size != sizeof(e) ||
        e.header.pid || e.header.tid || e.operation > IO_OP_OTHER ||
        e.duration_ns > e.header.timestamp_ns) {
        ++c.invalid;
        return 0;
    }
    ++c.received;
    c.reads += e.operation == IO_OP_READ;
    c.writes += e.operation == IO_OP_WRITE;
    c.bytes += e.bytes;
    if (c.received <= c.limit)
        std::cout << "[IO] device=" << e.dev_major << ":" << e.dev_minor
                  << " op=" << e.operation << " bytes=" << e.bytes
                  << " sector=" << e.sector << " duration_ns=" << e.duration_ns
                  << " status=" << e.status << " pid=0 tid=0\n";
    return 0;
}

/* raw tracepoint 不会替我们校验函数原型；加载前用运行内核 BTF 验证。 */
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

static bool check_prototype(const btf *types, const char *name, unsigned count)
{
    int id = btf__find_by_name_kind(types, name, BTF_KIND_TYPEDEF);
    if (id < 0) return false;
    int resolved = btf__resolve_type(types, id);
    if (resolved < 0) return false;
    auto *t = btf__type_by_id(types, resolved);
    if (!t || btf_kind(t) != BTF_KIND_PTR) return false;
    t = btf__type_by_id(types, t->type);
    // BTF trace handler 比实际 tracepoint 多一个前置 void * 参数。
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

static unsigned number(const std::string &s)
{
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("expected unsigned decimal number: " + s);
    auto value = std::stoull(s);
    if (value > std::numeric_limits<unsigned>::max())
        throw std::runtime_error("number too large");
    return static_cast<unsigned>(value);
}

int main(int argc, char **argv)
{
    unsigned seconds = 10;
    Consumer consumer;
    kylinrca_io_config config{};
    std::string path = KYLINRCA_IO_BPF_OBJECT;
    try {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help") {
                std::cout << "Usage: " << argv[0]
                          << " [--seconds N] [--device MAJOR:MINOR]"
                             " [--max-print N] [--object PATH]\n";
                return 0;
            }
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + arg);
            std::string value = argv[++i];
            if (arg == "--seconds") {
                seconds = number(value);
                if (!seconds || seconds > 3600)
                    throw std::runtime_error("--seconds must be 1..3600");
            } else if (arg == "--max-print") {
                consumer.limit = number(value);
            } else if (arg == "--object") {
                path = value;
            } else if (arg == "--device") {
                auto colon = value.find(':');
                if (colon == std::string::npos)
                    throw std::runtime_error("--device requires MAJOR:MINOR");
                config.major = number(value.substr(0, colon));
                config.minor = number(value.substr(colon + 1));
                config.filter_device = 1;
            } else throw std::runtime_error("unknown option: " + arg);
        }
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return 2;
    }

    btf *types = btf__load_vmlinux_btf();
    if (libbpf_get_error(types) || !types) {
        std::cerr << "Kernel BTF unavailable; cannot validate raw tracepoint ABI\n";
        return 1;
    }
    bool compatible =
        check_prototype(types, "btf_trace_block_rq_issue", 1) &&
        check_prototype(types, "btf_trace_block_rq_complete", 3) &&
        check_prototype(types, "btf_trace_block_rq_requeue", 1);
    btf__free(types);
    if (!compatible) {
        std::cerr << "Unsupported block raw tracepoint signature; refusing attach\n";
        return 1;
    }

    bpf_object *obj = bpf_object__open_file(path.c_str(), nullptr);
    if (!obj || libbpf_get_error(obj)) {
        std::cerr << "Cannot open BPF object: " << path << "\n";
        return 1;
    }
    ring_buffer *rb = nullptr;
    std::vector<bpf_link *> links;
    int result = 0;
    auto cleanup = [&] {
        // 先停止生产，再消费尾部；所有 link 均显式销毁。
        for (auto it = links.rbegin(); it != links.rend(); ++it)
            bpf_link__destroy(*it);
        if (rb) {
            int err = ring_buffer__consume(rb);
            if (err < 0) result = 1;
            ring_buffer__free(rb);
            rb = nullptr;
        }
    };
    do {
        int err = bpf_object__load(obj);
        if (err) {
            std::cerr << "BPF load failed: " << err << "\n";
            result = 1; break;
        }
        int cfg_fd = bpf_object__find_map_fd_by_name(obj, "io_config");
        unsigned zero = 0;
        if (cfg_fd < 0 || bpf_map_update_elem(cfg_fd, &zero, &config, BPF_ANY)) {
            std::cerr << "Cannot configure device filter\n";
            result = 1; break;
        }
        int fd = bpf_object__find_map_fd_by_name(obj, "events");
        rb = ring_buffer__new(fd, receive, &consumer, nullptr);
        if (!rb || libbpf_get_error(rb)) {
            rb = nullptr;
            std::cerr << "Cannot create RingBuffer consumer\n";
            result = 1; break;
        }
        bpf_program *program;
        bpf_object__for_each_program(program, obj) {
            auto *link = bpf_program__attach(program);
            if (!link || libbpf_get_error(link)) {
                std::cerr << "Attach failed: " << bpf_program__name(program) << "\n";
                result = 1; break;
            }
            links.push_back(link);
        }
        if (result) break;
        std::signal(SIGINT, stop);
        std::signal(SIGTERM, stop);
        std::cout << "READY io_probe seconds=" << seconds << std::endl;
        auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        while (running && std::chrono::steady_clock::now() < end) {
            err = ring_buffer__poll(rb, 100);
            if (err < 0 && err != -EINTR) {
                std::cerr << "RingBuffer poll failed: " << err << "\n";
                result = 1; break;
            }
        }
    } while (false);
    cleanup();

    if (!links.empty()) {
        const char *names[] = {"issue", "complete", "partial", "requeue",
            "unmatched", "map_update_fail", "map_delete_fail", "ringbuf_drop",
            "bad_timestamp", "read_fail", "emitted", "reissue"};
        int cpus = libbpf_num_possible_cpus(); //查找当前设备上的CPU数量
        int fd = bpf_object__find_map_fd_by_name(obj, "io_stats");
        if (cpus <= 0 || fd < 0) result = 1;
        else {
            std::vector<__u64> values(cpus);
            for (__u32 key = 0; key < IO_STAT_MAX; ++key) {
                if (bpf_map_lookup_elem(fd, &key, values.data())) {
                    result = 1; break;
                }
                unsigned long long sum = 0;
                for (auto value : values) sum += value;
                std::cout << "STAT " << names[key] << "=" << sum << "\n";
            }
        }
        const char *life_names[] = {"requeued_completed", "completed_requeues",
            "max_requeues", "unexpected_reissue", "release_cleanup"};
        int life_fd = bpf_object__find_map_fd_by_name(obj, "io_lifecycle_stats");
        if (cpus <= 0 || life_fd < 0) result = 1;
        else {
            std::vector<__u64> values(cpus);
            for (__u32 k = 0; k < IO_LIFE_MAX; ++k) {
                if (bpf_map_lookup_elem(life_fd, &k, values.data())) { result = 1; break; }
                unsigned long long aggregate = 0;
                for (auto v : values) {
                    if (k == IO_LIFE_MAX_REQUEUES) {
                        if (v > aggregate) aggregate = v;
                    } else aggregate += v;
                }
                std::cout << "STAT " << life_names[k] << "=" << aggregate << "\n";
            }
        }
        unsigned pending = 0;
        __u64 key = 0, next = 0;
        int starts = bpf_object__find_map_fd_by_name(obj, "io_starts");
        if (starts < 0) result = 1;
        else {
            int err = bpf_map_get_next_key(starts, nullptr, &next);
            while (!err) {
                ++pending; key = next;
                err = bpf_map_get_next_key(starts, &key, &next);
            }
            if (errno != ENOENT) result = 1;
        }
        std::cout << "SUMMARY received=" << consumer.received
                  << " invalid=" << consumer.invalid
                  << " reads=" << consumer.reads << " writes=" << consumer.writes
                  << " bytes=" << consumer.bytes << " pending=" << pending << "\n";
    }
    if (consumer.invalid) result = 1;
    bpf_object__close(obj);
    return result;
}
