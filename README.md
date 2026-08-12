# kylinRCA
Cross-architecture eBPF anomaly observability and root cause analysis agent for Linux

## Development Environment

KylinRCA is currently developed and tested on:

- Ubuntu 26.04 LTS
- WSL2 Linux Kernel 6.18+
- x86_64
- GCC 15+
- Clang/LLVM 21+
- CMake 3.16+
- bpftool 7+
- libbpf 1.6+

### Required packages

```bash
sudo apt install -y \
    git make cmake gcc g++ clang llvm \
    bpftool libbpf-dev libelf-dev zlib1g-dev pkg-config
```

### Generate vmlinux.h

The eBPF programs use BTF/CO-RE.
Generate the kernel type header with:

```bash
./scripts/gen_vmlinux.sh
```
The generated file is: bpf/include/vmlinux.h

vmlinux.h is generated from the target kernel BTF and is therefore not committed to the repository.

### Build

Configure:
```bash
cmake -S . -B build
```

BUild:
```bash
cmake --build build
```
