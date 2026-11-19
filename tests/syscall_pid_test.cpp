#include "event.h"
#include "syscall_bpf_config.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// 用真实系统调用的返回值和时间范围，识别测试产生的事件。
struct ExpectedCall {
    uint64_t before_ns = 0;
    uint64_t after_ns = 0;
    long syscall_id = 0;
    long result = 0;
    uint32_t pid = 0;
    uint32_t tid = 0;
    bool collect = true;
    unsigned seen = 0;
    bool correct = true;
};

struct Capture {
    std::vector<ExpectedCall> calls;
    unsigned invalid = 0;
};

// 按依赖顺序释放挂载、RingBuffer 和 BPF 对象。
struct Resources {
    bpf_object* object = nullptr;
    ring_buffer* ring = nullptr;
    std::vector<bpf_link*> links;
    ~Resources()
    {
        for (auto it = links.rbegin(); it != links.rend(); ++it)
            bpf_link__destroy(*it);
        if (ring)
            ring_buffer__free(ring);
        if (object)
            bpf_object__close(object);
    }
};

uint64_t now_ns()
{
    timespec now {};
    clock_gettime(CLOCK_MONOTONIC, &now);
    return static_cast<uint64_t>(now.tv_sec) * 1000000000ULL + now.tv_nsec;
}

ExpectedCall record_call(long id, uint32_t pid, uint32_t tid, bool collect)
{
    ExpectedCall call;
    call.syscall_id = id;
    call.pid = pid;
    call.tid = tid;
    call.collect = collect;
    call.before_ns = now_ns();
    call.result = syscall(id);
    call.after_ns = now_ns();
    return call;
}

int receive(void* opaque, void* data, size_t size)
{
    auto& capture = *static_cast<Capture*>(opaque);
    syscall_event event {};
    if (size != sizeof(event)) {
        ++capture.invalid;
        return 0;
    }
    std::memcpy(&event, data, sizeof(event));
    if (event.header.version != KYLINRCA_EVENT_VERSION ||
        event.header.type != EVENT_TYPE_SYSCALL || event.header.size != sizeof(event)) {
        ++capture.invalid;
        return 0;
    }
    for (auto& call : capture.calls) {
        if (event.syscall_id != call.syscall_id || event.ret != call.result ||
            event.header.timestamp_ns < call.before_ns || event.header.timestamp_ns > call.after_ns)
            continue;
        ++call.seen;
        call.correct = call.correct && event.header.pid == call.pid && event.header.tid == call.tid;
        std::cout << "[SYSCALL PID] expected_pid=" << call.pid << " expected_tid=" << call.tid
                  << " event_pid=" << event.header.pid << " event_tid=" << event.header.tid
                  << " syscall_id=" << event.syscall_id << " ret=" << event.ret << '\n';
    }
    return 0;
}

// 工作线程与主线程属于同一进程，但 TID 不同，可以检查是否混淆了两种编号。
void record_thread_calls(Capture& capture, bool collect)
{
    std::thread worker([&] {
        const uint32_t pid = getpid();
        const uint32_t tid = syscall(SYS_gettid);
        for (int i = 0; i < 3; ++i) {
            capture.calls.push_back(record_call(SYS_getpid, pid, tid, collect));
            capture.calls.push_back(record_call(SYS_gettid, pid, tid, collect));
        }
    });
    worker.join();
}

// 自过滤开启后，让另一个进程继续产生事件，防止把“全部没采到”误判为成功。
bool record_child_calls(Capture& capture)
{
    int fds[2];
    if (pipe(fds) != 0)
        return false;
    const pid_t child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return false;
    }
    if (child == 0) {
        close(fds[0]);
        const uint32_t pid = getpid();
        const uint32_t tid = syscall(SYS_gettid);
        const std::array<ExpectedCall, 2> calls {
            record_call(SYS_getpid, pid, tid, true),
            record_call(SYS_gettid, pid, tid, true)
        };
        ssize_t written;
        do {
            written = write(fds[1], calls.data(), sizeof(calls));
        } while (written < 0 && errno == EINTR);
        _exit(written == static_cast<ssize_t>(sizeof(calls)) ? 0 : 1);
    }
    close(fds[1]);
    std::array<ExpectedCall, 2> calls {};
    size_t received = 0;
    while (received < sizeof(calls)) {
        const ssize_t count = read(fds[0], reinterpret_cast<char*>(calls.data()) + received,
                                   sizeof(calls) - received);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            break;
        received += count;
    }
    close(fds[0]);
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0 || received != sizeof(calls))
        return false;
    capture.calls.insert(capture.calls.end(), calls.begin(), calls.end());
    return true;
}

bool validate(Resources& resources, Capture& capture)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    do {
        const int result = ring_buffer__poll(resources.ring, 100);
        if (result < 0 && result != -EINTR)
            return false;
    } while (std::chrono::steady_clock::now() < deadline);

    bool passed = capture.invalid == 0;
    for (const auto& call : capture.calls) {
        const long expected_result = call.syscall_id == SYS_getpid ? call.pid : call.tid;
        if (call.result != expected_result || !call.correct || call.seen != (call.collect ? 1U : 0U)) {
            std::cerr << "[SYSCALL PID] failed pid=" << call.pid << " tid=" << call.tid
                      << " expected_events=" << call.collect << " received=" << call.seen << '\n';
            passed = false;
        }
    }
    return passed;
}

int main(int argc, char** argv)
{
    if (argc > 2 || (argc == 2 && std::strcmp(argv[1], "--help") == 0)) {
        std::cout << "Usage: " << argv[0] << " [syscall.bpf.o]\nRequires BPF privileges.\n";
        return argc == 2 ? 0 : 1;
    }
    const char* path = argc == 2 ? argv[1] : KYLINRCA_SYSCALL_BPF_OBJECT;
    Resources resources;
    Capture capture;
    resources.object = bpf_object__open_file(path, nullptr);
    if (!resources.object || bpf_object__load(resources.object) != 0) {
        std::cerr << "Cannot load syscall probe; check BPF privileges and libbpf errors.\n";
        return 1;
    }
    if (!configure_syscall_namespace(resources.object)) {
        std::cerr << "Cannot configure PID namespace.\n";
        return 1;
    }
    bpf_map* config = bpf_object__find_map_by_name(resources.object, "config_map");
    bpf_map* events = bpf_object__find_map_by_name(resources.object, "events");
    const uint32_t zero = 0;
    if (!config || !events || bpf_map_update_elem(bpf_map__fd(config), &zero, &zero, BPF_ANY) != 0)
        return 1;
    resources.ring = ring_buffer__new(bpf_map__fd(events), receive, &capture, nullptr);
    if (!resources.ring)
        return 1;

    // 先挂退出探针，再挂进入探针，保证测试调用有完整的起止采集。
    for (const char* name : {"handle_sys_exit", "handle_sys_enter"}) {
        bpf_program* program = bpf_object__find_program_by_name(resources.object, name);
        if (!program)
            return 1;
        bpf_link* link = bpf_program__attach(program);
        if (!link)
            return 1;
        resources.links.push_back(link);
    }

    // 第一阶段允许采集自身，核对工作线程的 PID 和 TID。
    record_thread_calls(capture, true);
    if (!validate(resources, capture))
        return 1;
    std::cout << "[SYSCALL PID] identity=PASS matched_calls=6\n";

    // 第二阶段排除自身：本进程所有线程均不应出现，子进程应正常出现。
    const uint32_t tracer_pid = getpid();
    if (bpf_map_update_elem(bpf_map__fd(config), &zero, &tracer_pid, BPF_ANY) != 0)
        return 1;
    capture.calls.clear();
    record_thread_calls(capture, false);
    if (!record_child_calls(capture) || !validate(resources, capture))
        return 1;
    std::cout << "[SYSCALL PID] self_filter=PASS excluded_calls=6 child_calls=2\n";
    return 0;
}
