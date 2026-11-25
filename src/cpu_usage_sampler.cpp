#include "cpu_usage_sampler.h"

#include "cpu_probe_stats.h"
#include "cpu_runtime_sampler.h"

#include <bpf/libbpf.h>
#include <unistd.h>

#include <utility>

namespace {

std::optional<uint64_t> read_probe_errors(int fd)
{
    const int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0)
        return std::nullopt;

    const uint32_t keys[] = {CPU_STAT_RINGBUF_DROP, CPU_STAT_BAD_RUNQUEUE_TIMESTAMP,
        CPU_STAT_BAD_ONCPU_TIMESTAMP, CPU_STAT_WAKEUP_UPDATE_FAIL,
        CPU_STAT_ONCPU_UPDATE_FAIL, CPU_STAT_REQUEUE_UPDATE_FAIL};
    std::vector<uint64_t> values(cpus);
    uint64_t total = 0;
    for (const uint32_t key : keys) {
        if (bpf_map_lookup_elem(fd, &key, values.data()) != 0)
            return std::nullopt;
        for (uint64_t value : values)
            total += value;
    }
    return total;
}

std::vector<CpuProcessUsageObservation> build_process_observations(
    const ThreadCpuStatMap& previous, const ThreadCpuStatMap& current,
    double elapsed_seconds, long clock_ticks)
{
    std::vector<CpuProcessUsageObservation> processes;
    std::unordered_map<uint32_t, std::size_t> indexes;
    const auto tracer_pid = getpid();

    for (const auto& [tid, sample] : current) {
        if (sample.pid == tracer_pid)
            continue;
        const auto prior = previous.find(tid);
        double usage = 0.0;
        if (prior == previous.end() ||
            !calculate_thread_cpu_usage(prior->second, sample, elapsed_seconds,
                                        clock_ticks, usage))
            continue;

        const auto pid = static_cast<uint32_t>(sample.pid);
        const auto [index, inserted] = indexes.emplace(pid, processes.size());
        if (inserted) {
            processes.emplace_back();
            processes.back().pid = pid;
        }
        auto& process = processes[index->second];
        if (process.comm.empty() || sample.tid == sample.pid)
            process.comm = sample.comm;
        process.process_usage_percent += usage;

        CpuThreadUsageObservation thread;
        thread.tid = static_cast<uint32_t>(sample.tid);
        thread.comm = sample.comm;
        thread.usage_percent = usage;
        thread.runtime_valid = calculate_runtime_delta(prior->second, sample,
                                                       thread.runtime_ns,
                                                       thread.runtime_window_ns);
        thread.runtime_uncertainty_ns = prior->second.bpf_uncertainty_ns +
                                        sample.bpf_uncertainty_ns;
        process.threads.push_back(std::move(thread));
    }

    return processes;
}

} // namespace

bool CpuUsageSampler::start(bpf_object* object)
{
    runtime_fd_ = bpf_object__find_map_fd_by_name(object, "runtime_map");
    stats_fd_ = bpf_object__find_map_fd_by_name(object, "cpu_stats");
    clock_ticks_ = sysconf(_SC_CLK_TCK);
    return runtime_fd_ >= 0 && stats_fd_ >= 0 && clock_ticks_ > 0 && read(previous_);
}

bool CpuUsageSampler::read(Snapshot& snapshot) const
{
    const ThreadSnapshotHook runtime_hook = [this](ThreadCpuStatSample& thread) {
        read_cpu_runtime(runtime_fd_, thread);
    };
    if (!read_system_cpu_stat(snapshot.system) ||
        !read_all_thread_cpu_stats(snapshot.threads, runtime_hook))
        return false;

    snapshot.timestamp_ns = cpu_monotonic_ns();
    snapshot.probe_errors = read_probe_errors(stats_fd_);
    return true;
}

bool CpuUsageSampler::sample(std::optional<CpuUsageObservation>& observation)
{
    Snapshot current;
    if (!read(current))
        return false;

    observation.reset();
    double usage = 0.0;
    if (current.timestamp_ns > previous_.timestamp_ns &&
        calculate_system_cpu_usage(previous_.system, current.system, usage)) {
        auto& result = observation.emplace();
        result.timestamp_ns = current.timestamp_ns;
        result.window_start_ns = previous_.timestamp_ns;
        result.system_usage_percent = usage;
        result.has_runtime_snapshots = true;
        result.scheduling_evidence_valid = current.probe_errors &&
                                           current.probe_errors == previous_.probe_errors;
        const double elapsed = (current.timestamp_ns - previous_.timestamp_ns) / 1e9;
        result.processes = build_process_observations(previous_.threads, current.threads,
                                                      elapsed, clock_ticks_);
    }
    previous_ = std::move(current);
    return true;
}
