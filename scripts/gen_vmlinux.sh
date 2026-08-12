#!/usr/bin/env bash

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPTS_DIR")"

BTF_FILE="/sys/kernel/btf/vmlinux"
OUTPUT_FILE="$PROJECT_DIR/bpf/include/vmlinux.h"

if ! command -v bpftool > /dev/null 2>&1; then
	echo "Error: bpftool is not installed."
	exit 1
fi

if [[ ! -r "$BTF_FILE" ]]; then
	echo "Error: kernel BTF not found or not readable:$BTF_FILE"
	exit 1
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

echo "Generating vmlinux.h from $BTF_FILE ..."

bpftool btf dump file "$BTF_FILE" format c > "$OUTPUT_FILE"

echo "Generated: $OUTPUT_FILE"
