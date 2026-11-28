#include "daemon_snapshot.h"
#include "json_reporter.h"

#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <tuple>
#include <utility>
#include <vector>
#include <unistd.h>

namespace {

constexpr std::size_t hotspot_limit = 10;

// 根据实际启用模块和分析进度生成 status，计数包含已消费的四类事件，不包含 tick。
std::string make_status_json(const kylinrca::AppConfig& settings,
                             const AnalysisProgress& progress)
{
    std::ostringstream output;
    output << std::boolalpha
           << "{\"state\":\"running\",\"pid\":" << getpid()
           << ",\"started_ns\":" << progress.started_ns
           << ",\"updated_ns\":" << progress.updated_ns
           << ",\"completed_windows\":" << progress.completed_windows
           << ",\"window_ms\":" << settings.window_ms
           << ",\"modules\":{\"syscall\":" << settings.enable_syscall
           << ",\"cpu\":" << settings.enable_cpu
           << ",\"lock\":" << settings.enable_lock << ",\"io\":" << settings.enable_io << '}'
           << ",\"processed_events\":{\"syscall\":" << progress.syscall_events
           << ",\"cpu\":" << progress.cpu_events
           << ",\"lock\":" << progress.lock_events
           << ",\"io\":" << progress.io_events << "}}";
    return output.str();
}

// 展开本轮 PID/系统调用统计，按累计耗时排序后最多输出 10 个对象。
void write_syscall_top(std::ostream& output, const SyscallAnalyzer& syscall_window)
{
    struct SyscallHotspot {
        uint32_t pid;
        int64_t syscall_id;
        SyscallStats metrics;
    };
    std::vector<SyscallHotspot> hotspots;
    /*例如hotspots：
        [进程100，read，30毫秒]
        [进程100，write，80毫秒]
        [进程200，read，20毫秒]*/
    for (const auto& [pid, syscall_metrics] : syscall_window.stats())
        for (const auto& [syscall_id, metrics] : syscall_metrics)
            hotspots.push_back({pid, syscall_id, metrics});
    //按累计耗时排序
    std::sort(hotspots.begin(), hotspots.end(), [](const auto& left, const auto& right) {
        if (left.metrics.total_duration_ns != right.metrics.total_duration_ns)
            return left.metrics.total_duration_ns > right.metrics.total_duration_ns;
        return std::tie(left.pid, left.syscall_id) < std::tie(right.pid, right.syscall_id);
    });
    output << "[";
    for (std::size_t index = 0; index < std::min(hotspot_limit, hotspots.size()); ++index) {
        const auto& entry = hotspots[index];
        if (index)
            output << ',';
        output << "{\"pid\":" << entry.pid << ",\"syscall_id\":" << entry.syscall_id
               << ",\"name\":\"" << SyscallAnalyzer::syscall_name(entry.syscall_id)
               << "\",\"count\":" << entry.metrics.count
               << ",\"total_duration_ns\":" << entry.metrics.total_duration_ns
               << ",\"max_duration_ns\":" << entry.metrics.max_duration_ns
               << ",\"error_count\":" << entry.metrics.error_count << '}';
    }
    output << ']';
}

// 按本轮线程使用率进行全局排序，保留 runtime 的有效性和测量区间。
void write_cpu_top(std::ostream& output, const CpuUsageObservation& cpu_window)
{
    output << std::setprecision(std::numeric_limits<double>::max_digits10);
    /*struct CpuThreadUsageObservation {
    uint32_t tid = 0;
    std::string comm;
    double usage_percent = 0.0;
    bool runtime_valid = false; //本次 BPF 运行时间读数是否通过检查、可以使用
    uint64_t runtime_ns = 0; //这个窗口里，线程实际占用 CPU 的累计时间
    uint64_t runtime_window_ns = 0; // 前后两次 BPF 读数之间经过的时间
    uint64_t runtime_uncertainty_ns = 0; //两次读取操作耗时之和，用来表示读取过程带来的时间不确定度
    };*/
    struct CpuHotspot {
        uint32_t pid;
        const CpuThreadUsageObservation* metrics;
    };
    std::vector<CpuHotspot> hotspots;
    for (const auto& process_usage : cpu_window.processes)
        for (const auto& thread_usage : process_usage.threads)
            hotspots.push_back({process_usage.pid, &thread_usage});
    //cpu热点事件的排序依据就是首先找到pid和pid下的线程cpu分析表，
    //然后比较所有进程下的线程的cpu使用率，使用率大的排在左边，一样的话就比较pid和tid，
    //小的排左边。这样排序完成后，相同pid的不同线程不一定排在一起
    std::sort(hotspots.begin(), hotspots.end(), [](const auto& left, const auto& right) {
        if (left.metrics->usage_percent != right.metrics->usage_percent)
            return left.metrics->usage_percent > right.metrics->usage_percent;
        return std::tie(left.pid, left.metrics->tid) < std::tie(right.pid, right.metrics->tid);
    });
    output << '[';
    for (std::size_t index = 0; index < std::min(hotspot_limit, hotspots.size()); ++index) {
        const auto& entry = hotspots[index];
        const auto& metrics = *entry.metrics;
        if (index)
            output << ',';
        output << "{\"pid\":" << entry.pid << ",\"tid\":" << metrics.tid
               << ",\"usage_percent\":" << metrics.usage_percent
               << ",\"runtime_valid\":" << std::boolalpha << metrics.runtime_valid
               << ",\"runtime_ns\":" << metrics.runtime_ns
               << ",\"runtime_window_ns\":" << metrics.runtime_window_ns
               << ",\"runtime_uncertainty_ns\":" << metrics.runtime_uncertainty_ns << '}';
    }
    output << ']';
}

// 展开最近结算的锁窗口，按累计成功明显等待排序；失败与短等待仍保留在报告中。
void write_lock_top(std::ostream& output, const LockAnalyzer& lock_analysis)
{
    /*struct LockStats {
    uint64_t event_count = 0; // 包括成功、短等待和失败返回。
    uint64_t wait_count = 0; // 达到最短等待时长的成功调用次数。
    uint64_t total_wait_ns = 0;
    uint64_t max_wait_ns = 0;
    uint64_t short_wait_count = 0;
    uint64_t eagain_count = 0; // 值不匹配，不能证明发生了阻塞。
    uint64_t timeout_count = 0;
    uint64_t interrupted_count = 0;
    uint64_t other_error_count = 0;
    std::set<uint32_t> waiting_tids; // 集合（Set），用来保存发生过锁等待的线程 ID（TID）。std::set：C++ 标准库中的集合容器，自动去重、自动排序，保证同一线程多次等待只计一个线程。

    uint64_t average_wait_ns() const
    {
        return wait_count ? total_wait_ns / wait_count : 0;
    }
    };*/
    struct LockHotspot {
        uint32_t pid;
        uint64_t address;
        const LockStats* metrics;
    };
    std::vector<LockHotspot> hotspots;
    for (const auto& [pid, lock_metrics] : lock_analysis.stats())
        for (const auto& [address, metrics] : lock_metrics)
            if (metrics.wait_count)
                hotspots.push_back({pid, address, &metrics});
    //lock的排序依据是总的等待时间，等待时间大的排在左边，一样的话就比较pid和锁地址，pid小的排左边，锁地址小的排左边
    std::sort(hotspots.begin(), hotspots.end(), [](const auto& left, const auto& right) {
        if (left.metrics->total_wait_ns != right.metrics->total_wait_ns)
            return left.metrics->total_wait_ns > right.metrics->total_wait_ns;
        return std::tie(left.pid, left.address) < std::tie(right.pid, right.address);
    });
    output << '[';
    for (std::size_t index = 0; index < std::min(hotspot_limit, hotspots.size()); ++index) {
        const auto& entry = hotspots[index];
        if (index)
            output << ',';
        output << "{\"pid\":" << entry.pid << ",\"lock_addr\":\"0x"
               << std::hex << entry.address << std::dec
               << "\",\"wait_count\":" << entry.metrics->wait_count
               << ",\"total_wait_ns\":" << entry.metrics->total_wait_ns
               << ",\"max_wait_ns\":" << entry.metrics->max_wait_ns
               << ",\"waiting_threads\":" << entry.metrics->waiting_tids.size() << '}';
    }
    output << ']';
}

// 按设备最近窗口的 P95 耗时排序；无样本的持续告警仍由 report 返回。
void write_io_top(std::ostream& output, const IoReport& report)
{
    std::vector<const IoStats*> hotspots;
    for (const auto& device_stats : report.devices)
        if (device_stats.count)
            hotspots.push_back(&device_stats);
    std::sort(hotspots.begin(), hotspots.end(), [](const auto* left, const auto* right) {
        if (left->p95_duration_ns != right->p95_duration_ns)
            return left->p95_duration_ns > right->p95_duration_ns;
        return std::tie(left->major, left->minor) < std::tie(right->major, right->minor);
    });
    output << '[';
    for (std::size_t index = 0; index < std::min(hotspot_limit, hotspots.size()); ++index) {
        const auto& device_stats = *hotspots[index];
        if (index)
            output << ',';
        output << "{\"device\":\"" << device_stats.major << ':' << device_stats.minor
               << "\",\"dev_major\":" << device_stats.major << ",\"dev_minor\":" << device_stats.minor
               << ",\"sample_count\":" << device_stats.count << ",\"bytes\":" << device_stats.bytes
               << ",\"avg_duration_ns\":" << device_stats.avg_duration_ns
               << ",\"p95_duration_ns\":" << device_stats.p95_duration_ns
               << ",\"p99_duration_ns\":" << device_stats.p99_duration_ns
               << ",\"error_count\":" << device_stats.errors << '}';
    }
    output << ']';
}

} // 本文件序列化辅助函数命名空间结束

/*创建 SnapshotStore 对象时，用传入的 initial_snapshot 创建一份只读快照，
    并把管理它的共享指针保存到内部成员变量 current_snapshot_ 中。*/
SnapshotStore::SnapshotStore(DaemonSnapshot initial_snapshot)
    : current_snapshot_(std::make_shared<const DaemonSnapshot>(std::move(initial_snapshot)))
{
}

void SnapshotStore::publish(DaemonSnapshot next_snapshot)
{
    auto replacement = std::make_shared<const DaemonSnapshot>(std::move(next_snapshot));
    {
        std::lock_guard<std::mutex> guard(mutex_);
        current_snapshot_.swap(replacement);
    }
    // 在锁外释放旧快照；已有查询持有共享指针时，旧快照会继续保留。
}

std::shared_ptr<const DaemonSnapshot> SnapshotStore::read() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return current_snapshot_;
}

DaemonSnapshot make_daemon_snapshot(const kylinrca::AppConfig& settings,
                                  const AnalysisProgress& progress,
                                  const SyscallAnalyzer& syscall_totals,
                                  const SyscallAnalyzer& syscall_window,
                                  const CpuUsageObservation& cpu_window,
                                  const CpuAnalyzer& cpu_analysis,
                                  const LockAnalyzer& lock_analysis,
                                  const IoSnapshot& io_state)
{
    //创建一个叫 hotspots 的“文字收集器”，可以不断往里面追加内容
    std::ostringstream hotspots;
    hotspots << "{\"updated_ns\":" << progress.updated_ns << ",\"limit\":" << hotspot_limit;
    hotspots << ",\"syscall\":";
    if (settings.enable_syscall && progress.completed_windows) {
        hotspots << "{\"window_start_ns\":" << progress.window_start_ns
             << ",\"window_end_ns\":" << progress.updated_ns
             << ",\"sort_by\":\"total_duration_ns_desc\",\"items\":";
        write_syscall_top(hotspots, syscall_window);
        hotspots << '}';
    } else {
        hotspots << "null";
    }
    hotspots << ",\"cpu\":";
    if (settings.enable_cpu && cpu_window.timestamp_ns) {
        hotspots << "{\"window_start_ns\":" << cpu_window.window_start_ns
             << ",\"window_end_ns\":" << cpu_window.timestamp_ns
             << ",\"sort_by\":\"usage_percent_desc\",\"items\":";
        write_cpu_top(hotspots, cpu_window);
        hotspots << '}';
    } else {
        hotspots << "null";
    }
    hotspots << ",\"lock\":";
    if (settings.enable_lock && lock_analysis.window_end_ns()) {
        hotspots << "{\"window_start_ns\":" << lock_analysis.window_start_ns()
             << ",\"window_end_ns\":" << lock_analysis.window_end_ns()
             << ",\"sort_by\":\"total_wait_ns_desc\",\"items\":";
        write_lock_top(hotspots, lock_analysis);
        hotspots << '}';
    } else {
        hotspots << "null";
    }
    hotspots << ",\"io\":";
    if (io_state.enabled && io_state.report) {
        const auto& io_report = *io_state.report;
        hotspots << "{\"window_start_ns\":" << io_report.window_start_ns
                 << ",\"window_end_ns\":" << io_report.window_end_ns
                 << ",\"window_complete\":" << std::boolalpha << io_report.window_complete
                 << ",\"sort_by\":\"p95_duration_ns_desc\",\"items\":";
        write_io_top(hotspots, io_report);
        hotspots << '}';
    } else {
        hotspots << "null";
    }
    hotspots << '}';

    std::ostringstream reports;
    reports << "{\"updated_ns\":" << progress.updated_ns << ",\"syscall\":";
    if (settings.enable_syscall)
        reports << "{\"since_ns\":" << progress.started_ns << ",\"until_ns\":"
                << progress.updated_ns << ",\"summary\":"
                << JsonReporter::report_syscalls(syscall_totals) << '}';
    else
        reports << "null";
    reports << ",\"cpu\":";
    if (settings.enable_cpu && cpu_window.timestamp_ns)
        reports << JsonReporter::report_cpu(cpu_analysis.diagnosis(), cpu_window.window_start_ns,
                                           cpu_window.timestamp_ns, progress.cpu_events, &cpu_analysis.config());
    else
        reports << "null";
    reports << ",\"lock\":";
    if (settings.enable_lock && lock_analysis.window_end_ns())
        reports << JsonReporter::report_locks(lock_analysis);
    else
        reports << "null";
    reports << ",\"io\":" << (io_state.enabled ? io_snapshot_json(io_state) : "null") << '}';

    return {make_status_json(settings, progress), hotspots.str(), reports.str(), io_state};
}
