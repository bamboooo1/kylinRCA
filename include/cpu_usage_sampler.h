#ifndef KYLINRCA_CPU_USAGE_SAMPLER_H
#define KYLINRCA_CPU_USAGE_SAMPLER_H

#include "cpu_analyzer.h"
#include "proc_cpu_sampler.h"

#include <optional>

struct bpf_object;

class CpuUsageSampler {
public:
    bool start(bpf_object* object);
    // A readable snapshot can still have no usage delta (e.g. zero elapsed ticks).
    bool sample(std::optional<CpuUsageObservation>& observation);

private:
    struct Snapshot {
        CpuStatSample system;
        ThreadCpuStatMap threads;
        uint64_t timestamp_ns = 0;
        std::optional<uint64_t> probe_errors;
    };

    bool read(Snapshot& snapshot) const;

    int runtime_fd_ = -1;
    int stats_fd_ = -1;
    long clock_ticks_ = 0;
    Snapshot previous_;
};

#endif
