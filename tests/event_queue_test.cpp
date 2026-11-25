#include "event_queue.h"

#include <iostream>
#include <thread>
#include <vector>

int main()
{
    EventQueue queue;
    syscall_event syscall{};
    syscall.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_SYSCALL, sizeof(syscall), 1, 42, 43};
    cpu_event cpu{};
    cpu.header = {KYLINRCA_EVENT_VERSION, EVENT_TYPE_CPU, sizeof(cpu), 2, 42, 43};

    cpu.header.type = EVENT_TYPE_UNKNOWN;
    if (queue.push_record(&cpu, sizeof(cpu)) ||
        queue.push_record(&cpu, sizeof(cpu.header) - 1)) {
        std::cerr << "Accepted an unknown type or truncated header\n";
        return 1;
    }
    cpu.header.type = EVENT_TYPE_CPU;
    cpu.header.size = sizeof(cpu.header);
    if (queue.push_record(&cpu, sizeof(cpu.header))) {
        std::cerr << "Accepted a header without its event payload\n";
        return 1;
    }

    std::vector<QueuedEvent> events;
    std::thread worker([&] {
        while (auto event = queue.wait_pop())
            events.push_back(std::move(*event));
    });

    cpu.header.size = sizeof(cpu);
    const bool accepted = queue.push_record(&syscall, sizeof(syscall)) &&
                          queue.push_record(&cpu, sizeof(cpu));
    syscall.header.tid = 0;
    queue.push(AnalysisTick{3, std::nullopt});
    queue.close();
    worker.join();

    const auto* captured_syscall = events.size() == 3 ? std::get_if<syscall_event>(&events[0]) : nullptr;
    const auto* captured_cpu = events.size() == 3 ? std::get_if<cpu_event>(&events[1]) : nullptr;
    const auto* tick = events.size() == 3 ? std::get_if<AnalysisTick>(&events[2]) : nullptr;
    if (!accepted || !captured_syscall || captured_syscall->header.tid != 43 ||
        !captured_cpu || captured_cpu->header.timestamp_ns != 2 || !tick ||
        tick->timestamp_ns != 3) {
        std::cerr << "Queue did not preserve owned records and window order on close\n";
        return 1;
    }

    EventQueue idle;
    bool woke_without_event = false;
    std::thread waiting([&] { woke_without_event = !idle.wait_pop(); });
    idle.close();
    waiting.join();
    if (!woke_without_event) {
        std::cerr << "Empty queue did not end on close\n";
        return 1;
    }
}
