# W1 B - eBPF Development Environment

## Platform

- OS: Ubuntu 26.04 LTS
- Environment: WSL2
- Kernel: 6.18.33.2-microsoft-standard-WSL2
- Architecture: x86_64

## Toolchain

- Clang/LLVM: 21.1.8
- GCC: 15.2.0
- bpftool: 7.7.0
- libbpf-dev: 1.6.3
- CMake

## Kernel Capabilities

Kernel BTF is available at:

```text
/sys/kernel/btf/vmlinux

The Linux tracing subsystem is available under:

```text
/sys/kernel/debug/tracing

Clang supports the following BPF targets:
bpf
bpfeb
bpfel

## vmlinux.h generation

Run:
./scripts/gen_vmlinux.sh

The script generates:
bpf/include/vmlinux.h

The generated vmlinux.h is excluded from Git because it is derived from the target kernel BTF.

##Day1 Result
The basic eBPF development environment and BPF build infrastructure are ready for the W1 syscall probe implementation.
