#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/build}"

BTF_FILE="/sys/kernel/btf/vmlinux"
JOBS="${JOBS:-2}"

echo "KylinRCA ARM64 build precheck"
echo "Project: $PROJECT_DIR"

ARCH="$(uname -m)"

if [[ "$ARCH" != "aarch64" && "$ARCH" != "arm64" ]]; then
    echo "Error: ARM64 build script requires aarch64/arm64 host."
    echo "Detected architecture: $ARCH"
    exit 1
fi

echo "[OK] Architecture: $ARCH"

for cmd in clang cmake pkg-config bpftool; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command not found: $cmd"
        exit 1
    fi
done

echo "[OK] clang: $(clang --version | head -n 1)"
echo "[OK] bpftool: $(bpftool version | head -n 1)"

if ! pkg-config --exists libbpf; then
    echo "Error: libbpf development package is unavailable."
    exit 1
fi

echo "[OK] libbpf: $(pkg-config --modversion libbpf)"

if [[ ! -r "$BTF_FILE" ]]; then
    echo
    echo "[BLOCKED] Kernel BTF is unavailable: $BTF_FILE"
    echo
    echo "The Raspberry Pi supports eBPF, tracepoints, hash maps and ring buffers,"
    echo "but the current KylinRCA build requires kernel BTF to generate vmlinux.h."
    echo
    echo "Week 2 result: ARM64 toolchain is ready; CO-RE/BTF fallback is required."
    exit 2
fi

echo "[OK] Kernel BTF: $BTF_FILE"

"$PROJECT_DIR/scripts/gen_vmlinux.sh"

cmake \
    -S "$PROJECT_DIR" \
    -B "$BUILD_DIR"

cmake \
    --build "$BUILD_DIR" \
    -j"$JOBS"

echo
echo "[OK] KylinRCA ARM64 build completed."