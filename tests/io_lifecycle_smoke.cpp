#include "../bpf/include/io_request_state.h"
#include <stdexcept>
#include <iostream>
static void check(bool b) { if (!b) throw std::runtime_error("lifecycle assertion failed"); }
static io_request_start first() {
    io_request_start s{}; s.start_ns=1000000; s.bytes=8192;
    s.sector=128; s.major=7; s.minor=1; s.operation=2; return s;
}
int main() {
    auto s=first();
    // Partial completion does not imply requeue.
    check(!io_state_complete(&s,0,4096,8192,1));
    check(s.requeue_count==0 && !s.awaiting_reissue);
    check(io_state_complete(&s,0,4096,4096,1));
    check(s.bytes==8192);
    s=first();
    check(!io_state_complete(&s,3,4096,8192,1));
    for (int i=0;i<3;++i) {
        io_state_requeue(&s); check(s.awaiting_reissue);
        check(io_state_reissue(&s)); check(!s.awaiting_reissue);
    }
    check(s.requeue_count==3 && s.start_ns==1000000 && s.bytes==8192);
    check(s.sector==128 && s.status==3);
    check(io_state_complete(&s,0,4096,4096,1));
    check(s.status==3 && 18000000-s.start_ns==17000000);
    check(!io_state_reissue(&s)); // unexpected duplicate preserves evidence
    check(s.bytes==8192 && s.status==3 && s.requeue_count==3);
    check(io_state_complete(&s,0,0,0,0)); // no-bio/flush
    s.requeue_count=~(__u64)0; io_state_requeue(&s);
    check(s.requeue_count==~(__u64)0); // saturate, never wrap
    std::cout << "I/O request lifecycle checks passed\n";
}
