#!/usr/bin/env python3
"""无需 BPF 权限，检查 daemon 的模块选项、读取错误、重复参数和公共配置边界。"""
from pathlib import Path
import subprocess
import sys
import tempfile


def run(binary, args, success):
    """执行一次参数检查，核对退出状态；失败用例必须在挂载探针前给出配置错误。"""
    result = subprocess.run([binary, *args], text=True, capture_output=True, timeout=5)
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected exit: {args}: {result.stderr}")
    if not success and ("[config]" not in result.stderr or "BPF probe attached" in result.stderr):
        raise AssertionError(f"did not fail during config parsing: {args}: {result.stderr}")
    return result


def main():
    """用临时文件覆盖各选项缺值、缺文件、非法字段和合法选项任意顺序组合；不实际启动采集。"""
    binary = sys.argv[1]
    help_text = run(binary, ["--help"], True).stdout
    for option in ("--config", "--cpu-config", "--lock-config", "--io-config"):
        if option not in help_text:
            raise AssertionError("missing option in help: " + option)
    with tempfile.TemporaryDirectory(prefix="kylinrca-config-options-") as directory:
        root = Path(directory)
        empty = root / "empty.conf"
        empty.write_text("")
        for option in ("--cpu-config", "--lock-config", "--io-config"):
            run(binary, [option], False)
            run(binary, [option, str(root / "missing.conf")], False)
            run(binary, [option, str(empty), option, str(empty)], False)
            invalid = root / "invalid.conf"
            invalid.write_text("window_ms=1000\n")
            run(binary, [option, str(invalid)], False)
        cpu = root / "cpu.conf"
        cpu.write_text("high_usage_threshold_percent=80.5\nrecovery_threshold_percent=50.25\n")
        lock = root / "lock.conf"
        lock.write_text("recovery_windows=1\n")
        # 最后故意放入未知选项，确保前面全部合法配置被读取，再在挂载前退出。
        result = run(binary, ["--lock-config", str(lock), "--io-config", str(empty),
                              "--cpu-config", str(cpu), "--config", str(empty), "--unknown", "x"], False)
        if "unknown or duplicate option: --unknown" not in result.stderr:
            raise AssertionError(result.stderr)
        for field in ("high_usage_threshold_percent", "minimum_wait_us"):
            invalid = root / "public.conf"
            invalid.write_text(field + "=1\n")
            run(binary, ["--config", str(invalid)], False)


if __name__ == "__main__":
    main()
