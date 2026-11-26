#!/usr/bin/env python3
"""Validate real BPF data through daemon queries; keep logs and stop owned processes."""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time

##脚本会自动完成：
# 1. 启动 daemon，开启 Syscall、CPU、Lock。
# 2. 创建三个真实负载，记住它们的 PID。
# 3. 连续查询 status、`top`、`report`。
# 4. 核对 Syscall PID、CPU PID/TID/runtime、Lock PID 和地址。
# 5. 检查排序、前 10 名限制、窗口和事件计数持续增长。
# 6. 检查错误命令、超长命令、分段请求和提前断开。
# 7. 用 SIGINT 停止 daemon，确认 Socket 被清理。
# 8. 关闭 CPU 模块后重新启动，检查禁用结果。
# 9. 用 SIGTERM 停止，再次确认清理。
def query(socket_path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(socket_path))
        connection.sendall((command + "\n").encode())
        with connection.makefile("rb") as response:
            line = response.readline()
            assert line.endswith(b"\n"), "Response has no final newline"
            return json.loads(line)


def stop_process(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def start_daemon(repository, run_directory, label):
    log_path = run_directory / (label + ".log")
    with (run_directory / (label + ".json")).open("w") as reports, log_path.open("w") as logs:
        process = subprocess.Popen(
            [str(repository / "build/kylinrcad"), "--config", str(run_directory / "daemon.conf")],
            stdout=reports, stderr=logs,
        )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Daemon exited during startup:\n" + log_path.read_text())
            if "[daemon] Ready" in log_path.read_text():
                return process
            time.sleep(0.05)
        raise RuntimeError("Daemon did not become ready; see " + str(log_path))
    except Exception:
        stop_process(process)
        raise


def check_protocol(socket_path):
    assert query(socket_path, "bogus") == {"ok": False, "error": "unknown_command"}
    assert query(socket_path, "x" * 64) == {"ok": False, "error": "request_too_long"}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as fragmented:
        fragmented.settimeout(3)
        fragmented.connect(str(socket_path))
        fragmented.sendall(b"sta")
        time.sleep(0.05)
        fragmented.sendall(b"tus\n")
        with fragmented.makefile("rb") as response:
            assert json.loads(response.readline())["ok"]
    for partial_request in (b"", b"sta", b"report\n"):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as disconnected:
            disconnected.settimeout(3)
            disconnected.connect(str(socket_path))
            disconnected.sendall(partial_request)
    assert query(socket_path, "status")["ok"], "Daemon stopped answering after disconnects"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="/tmp/kylinrca-issue38")
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("请使用 sudo python3 scripts/check_daemon_socket.py")

    repository = Path(__file__).resolve().parents[1]
    run_directory = Path(arguments.output_dir).resolve() / ("run-" + str(time.time_ns()))
    run_directory.mkdir(parents=True)
    socket_path = run_directory / "daemon.sock"
    configuration = run_directory / "daemon.conf"
    configuration.write_text(
        f"socket_path={socket_path}\nwindow_ms=500\n"
        "enable_syscall=true\nenable_cpu=true\nenable_lock=true\nenable_io=false\n"
    )
    summary = {"passed": False, "output_dir": str(run_directory), "checks": {}}
    checks = summary["checks"]
    daemon_process = None
    workloads = []
    print("验证记录：" + str(run_directory), flush=True)
    try:
        daemon_process = start_daemon(repository, run_directory, "daemon")
        baseline = query(socket_path, "status")["data"]
        summary["baseline"] = baseline
        assert baseline["pid"] == daemon_process.pid
        assert baseline["state"] == "running"
        assert baseline["modules"] == {"syscall": True, "cpu": True, "lock": True, "io": False}
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o600
        checks["status_and_permissions"] = True

        syscall_workload = subprocess.Popen([sys.executable, "-c",
            'import os,time\nfd=os.open("/dev/null",os.O_WRONLY)\n'
            'deadline=time.monotonic()+6\nwhile time.monotonic()<deadline:\n'
            ' os.write(fd,b"x"); time.sleep(0.001)\nos.close(fd)'])
        workloads.append(syscall_workload)
        cpu_workload = subprocess.Popen([sys.executable, "-c",
            'import time\ndeadline=time.monotonic()+6\n'
            'while time.monotonic()<deadline:\n sum(range(20000))'])
        workloads.append(cpu_workload)
        lock_log = run_directory / "lock-workload.txt"
        with lock_log.open("w") as lock_output:
            lock_workload = subprocess.Popen([
                str(repository / "build/kylinrca_lock_test"), "--scenario", "contention",
                "--threads", "8", "--hold-ms", "600", "--auto"], stdout=lock_output)
        workloads.append(lock_workload)
        summary["workload_pids"] = {"syscall": syscall_workload.pid,
                                    "cpu": cpu_workload.pid, "lock": lock_workload.pid}
        print("正在连续查询并核对三个负载，约需 8 秒……", flush=True)

        syscall_seen = False
        cpu_seen = False
        cpu_runtime_seen = False
        lock_addresses = set()
        deadline = time.monotonic() + 8
        with (run_directory / "queries.jsonl").open("w") as query_log:
            while time.monotonic() < deadline:
                replies = {command: query(socket_path, command)
                           for command in ("status", "top", "report")}
                for command, reply in replies.items():
                    assert reply["ok"] and reply["command"] == command
                    query_log.write(json.dumps({"command": command, "response": reply}) + "\n")
                hotspots = replies["top"]["data"]
                for module, metric in (("syscall", "total_duration_ns"),
                                       ("cpu", "usage_percent"), ("lock", "total_wait_ns")):
                    if hotspots[module] is not None:
                        values = [entry[metric] for entry in hotspots[module]["items"]]
                        assert len(values) <= 10 and values == sorted(values, reverse=True)
                if hotspots["cpu"] is not None:
                    for entry in hotspots["cpu"]["items"]:
                        if entry["pid"] == cpu_workload.pid and entry["tid"] == cpu_workload.pid:
                            cpu_seen |= entry["usage_percent"] > 0
                            cpu_runtime_seen |= entry["runtime_valid"] and entry["runtime_ns"] > 0
                reports = replies["report"]["data"]
                syscall_seen |= any(entry["pid"] == syscall_workload.pid
                                    for entry in reports["syscall"]["summary"]["processes"])
                if reports["lock"] is not None:
                    for process_stats in reports["lock"]["processes"]:
                        if process_stats["pid"] == lock_workload.pid:
                            lock_addresses.update(int(entry["lock_addr"], 16)
                                                  for entry in process_stats["locks"]
                                                  if entry["wait_count"] > 0)
                time.sleep(0.1)
        for workload in workloads:
            assert workload.wait(timeout=5) == 0, "A test workload failed"

        lock_text = lock_log.read_text()
        ready_line = next(line for line in lock_text.splitlines() if line.startswith("[MUTEX WORKLOAD]"))
        lock_fields = dict(token.split("=", 1) for token in ready_line.split() if "=" in token)
        mutex_address = int(lock_fields["mutex_addr"], 16)
        mutex_size = int(lock_fields["mutex_size"])
        latest = query(socket_path, "status")["data"]
        summary["latest"] = latest
        summary["observed_lock_addresses"] = [hex(address) for address in sorted(lock_addresses)]
        checks.update({
            "syscall_workload_pid": syscall_seen,
            "cpu_workload_pid_tid": cpu_seen,
            "cpu_runtime_evidence": cpu_runtime_seen,
            "lock_workload_pid_address": any(mutex_address <= address < mutex_address + mutex_size
                                             for address in lock_addresses) and "passed=1" in lock_text,
            "hotspot_sort_and_limit": True,
            "windows_keep_advancing": latest["completed_windows"] > baseline["completed_windows"]
                                      and latest["updated_ns"] > baseline["updated_ns"],
            "events_keep_arriving": all(latest["processed_events"][module] > baseline["processed_events"][module]
                                       for module in ("syscall", "cpu", "lock")),
        })
        check_protocol(socket_path)
        checks["invalid_fragmented_and_disconnected_clients"] = True

        daemon_process.send_signal(signal.SIGINT)
        assert daemon_process.wait(timeout=5) == 0 and not socket_path.exists()
        checks["sigint_cleanup"] = True
        configuration.write_text(configuration.read_text().replace("enable_cpu=true", "enable_cpu=false"))
        daemon_process = start_daemon(repository, run_directory, "restart")
        assert query(socket_path, "status")["data"]["modules"]["cpu"] is False
        assert query(socket_path, "top")["data"]["cpu"] is None
        assert query(socket_path, "report")["data"]["cpu"] is None
        checks["restart_and_disabled_module"] = True
        daemon_process.send_signal(signal.SIGTERM)
        assert daemon_process.wait(timeout=5) == 0 and not socket_path.exists()
        checks["sigterm_cleanup"] = True
        summary["passed"] = all(checks.values())
    except Exception as error:
        summary["error"] = str(error) or type(error).__name__
    finally:
        for workload in workloads:
            stop_process(workload)
        stop_process(daemon_process)
        (run_directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    for name, passed in checks.items():
        print(("PASS: " if passed else "FAIL: ") + name)
    print(json.dumps(summary, indent=2))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
