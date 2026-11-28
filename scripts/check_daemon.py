#!/usr/bin/env python3
"""统一 daemon 实采验收入口：Socket、模块配置、四模块重叠 I/O 和开关模式。"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

from check_io_analyzer import require, run, save, stop_monitor, validate

ROOT = Path(__file__).resolve().parents[1]


def query(socket_path, command):
    """连接本轮 daemon，发送一个 LF 结尾的请求并读取单行 JSON；连接或协议错误直接抛出。"""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3)
        connection.connect(str(socket_path))
        connection.sendall((command + "\n").encode())
        with connection.makefile("rb") as response:
            line = response.readline()
            if not line.endswith(b"\n"):
                raise ValueError("response has no final newline")
            return json.loads(line)


def check_protocol(socket_path):
    """在真实服务上验证错误响应、分段请求和提前断开；最后正常查询确认进程仍可接待。"""
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
    assert query(socket_path, "status")["ok"]


def read_documents(path):
    """解析 daemon 标准输出中的连续 JSON 文档，保留跨行的 Syscall 总结；未完成文档抛异常。"""
    text = path.read_text()
    decoder = json.JSONDecoder()
    documents = []
    while text.strip():
        text = text.lstrip()
        document, end = decoder.raw_decode(text)
        documents.append(document)
        text = text[end:]
    return documents


class QueryRecorder:
    """负载期间定期记录三个真实查询；退出上下文时回收线程并报告查询错误，不吞掉用例异常。"""

    def __init__(self, socket_path, output_path):
        """记录本轮 Socket 与日志路径，创建尚未启动的采样线程。"""
        self.socket_path = socket_path
        self.output_path = output_path
        self.replies = []
        self.stopped = threading.Event()
        self.error = None
        self.worker = threading.Thread(target=self.capture, daemon=True)

    def __enter__(self):
        """daemon 已就绪后进入，启动采样线程并返回可读取响应的记录器。"""
        self.worker.start()
        return self

    def capture(self):
        """每次保存完整响应及命令；出现连接、解码或错误响应时记录失败并结束采样。"""
        try:
            with self.output_path.open("w") as output:
                while not self.stopped.is_set():
                    for command in ("status", "top", "report"):
                        reply = query(self.socket_path, command)
                        if not reply["ok"]:
                            raise ValueError(str(reply))
                        frame = {"command": command, "response": reply}
                        self.replies.append(frame)
                        output.write(json.dumps(frame) + "\n")
                    self.stopped.wait(0.2)
        except Exception as error:
            self.error = error

    def __exit__(self, exception_type, exception, traceback):
        """停止并等待采样；用例本身成功时，将采样异常传给调用方判定失败。"""
        self.stopped.set()
        self.worker.join(timeout=5)
        if exception_type is None:
            if self.worker.is_alive():
                raise RuntimeError("query recorder did not stop")
            if self.error is not None:
                raise RuntimeError("query recorder failed: " + str(self.error)) from self.error


def module_config_case(output, build, module, active):
    """运行一个模块配置用例，核对实际阈值、有效事件和预期诊断，成功失败均回收进程并保存结果。"""
    output.mkdir()
    daemon = None
    workload = None
    result = {"passed": False, "module": module, "expected_alert": active}
    try:
        common = output / "daemon.conf"
        socket_path = output / "daemon.sock"
        common.write_text(f"socket_path={socket_path}\n" + "window_ms=200\nenable_syscall=false\nenable_io=false\n"
                          f"enable_cpu={str(module == 'cpu').lower()}\n"
                          f"enable_lock={str(module == 'lock').lower()}\n")
        specific = output / f"{module}.conf"
        if module == "cpu":
            settings = {"high_usage_threshold_percent": 1 if active else 100,
                        "recovery_threshold_percent": .5 if active else 99,
                        "runqueue_delay_threshold_us": 4294967295,
                        "alert_consecutive_samples": 1 if active else 100000,
                        "recovery_consecutive_samples": 1}
            expected = dict(settings)
            expected["runqueue_delay_threshold_ns"] = expected.pop("runqueue_delay_threshold_us") * 1000
            load_command = ["stress-ng", "--cpu", "2", "--timeout", "2s"]
            state = "CPU_HIGH_USAGE"
        else:
            settings = {"minimum_wait_us": 1 if active else 4294967295,
                        "average_wait_threshold_us": 1 if active else 4294967295,
                        "max_wait_threshold_us": 1 if active else 4294967295,
                        "minimum_waiting_threads": 2, "recovery_windows": 1}
            expected = {"minimum_wait_ns": settings["minimum_wait_us"] * 1000,
                        "average_wait_threshold_ns": settings["average_wait_threshold_us"] * 1000,
                        "max_wait_threshold_ns": settings["max_wait_threshold_us"] * 1000,
                        "minimum_waiting_threads": 2, "recovery_windows": 1, "window_ns": 200000000}
            load_command = [str(build / "kylinrca_lock_test"), "--scenario",
                            "contention", "--threads", "8", "--auto"]
            state = "LOCK_CONTENTION"
        # 这些是验证专用规则，不覆盖产品示例或分析器默认值。
        specific.write_text("\n".join(f"{key}={value}" for key, value in settings.items()) + "\n")
        command = [str(build / "kylinrcad"), "--config", str(common),
                   f"--{module}-config", str(specific)]
        result.update(daemon_command=command, workload_command=load_command, settings=settings)
        with (output / "reports.json").open("w") as out, (output / "daemon.log").open("w") as log, \
             (output / "workload.log").open("w") as load_log:
            daemon = subprocess.Popen(command, cwd=ROOT, stdout=out, stderr=log)
            for _ in range(200):
                require(daemon.poll() is None, "daemon exited before Ready")
                if "[daemon] Ready" in (output / "daemon.log").read_text():
                    break
                time.sleep(.05)
            else:
                raise RuntimeError("readiness timeout")
            with QueryRecorder(socket_path, output / "queries.jsonl") as recorder:
                time.sleep(.3)
                workload = subprocess.Popen(load_command, stdout=load_log, stderr=load_log)
                result["workload_pid"] = workload.pid
                require(workload.wait(timeout=15) == 0, "workload failed")
                time.sleep(.8)
            query_reports = [frame["response"]["data"][module] for frame in recorder.replies
                             if frame["command"] == "report" and frame["response"]["data"][module] is not None]
            require(query_reports and all(report["thresholds"] == expected for report in query_reports),
                    "Socket thresholds differ from module file")
            daemon.send_signal(signal.SIGTERM)
            require(daemon.wait(timeout=10) == 0, "daemon failed on shutdown")
            require(not socket_path.exists(), "Socket path remains after shutdown")
        rows = [r for r in read_documents(output / "reports.json") if r["type"] == module + "_summary"]
        require(rows, "no module reports")
        require(all(r.get("thresholds") == expected for r in rows), "module thresholds differ from file")
        require(any(r["received_events"] > 0 for r in rows), "no real events")
        if module == "lock":
            require(any(p["pid"] == workload.pid and any(s["event_count"] > 0 for s in p["locks"])
                        for r in rows for p in r["processes"]), "target lock events missing")
            require(all(r["rejected_events"] == 0 for r in rows), "invalid lock event")
        alert_rows = [r for r in rows if r["diagnosis"]["type"] == state]
        if active:
            if module == "cpu":
                require(alert_rows, "custom rules did not trigger expected alert")
                require(any(r["diagnosis"]["system_usage_percent"] >= settings["high_usage_threshold_percent"]
                            for r in alert_rows), "CPU diagnosis lacks usage evidence")
            else:
                # 其他进程可能在测试锁恢复后再次告警；按诊断的 PID 和窗口顺序核对本次负载。
                alert_rows = [r for r in alert_rows if r["diagnosis"]["pid"] == workload.pid]
                require(alert_rows, "target workload did not trigger Lock contention")
                last_alert_end_ns = alert_rows[-1]["window_end_ns"]
                recovered_window = next((r for r in rows if r["window_start_ns"] >= last_alert_end_ns
                                         and r["window_end_ns"] - r["window_start_ns"] == expected["window_ns"]
                                         and r["diagnosis"]["type"] == "NORMAL"), None)
                require(recovered_window is not None, "Lock did not recover after the target workload alert")
                result.update(target_alert_end_ns=last_alert_end_ns,
                              recovered_window_end_ns=recovered_window["window_end_ns"])
        else:
            require(all(r["diagnosis"]["type"] == "NORMAL" for r in rows),
                    "control rules unexpectedly produced alert")
        result.update(passed=True, windows=len(rows), alert_windows=len(alert_rows),
                      final_diagnosis=rows[-1]["diagnosis"]["type"])
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        stop_monitor(workload)
        stop_monitor(daemon)
        save(output / "results.json", result)
    return result


def start_daemon(build, run_directory, label):
    """启动指定配置并等待 Ready；启动失败保留日志，清理已创建的进程并抛出异常。"""
    log_path = run_directory / (label + ".log")
    with (run_directory / (label + ".json")).open("w") as reports, log_path.open("w") as logs:
        process = subprocess.Popen(
            [str(build / "kylinrcad"), "--config", str(run_directory / "daemon.conf")],
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
        stop_monitor(process)
        raise


def run_socket_case(build, run_directory):
    """验证三模块热点身份、runtime、协议和两种退出信号；成功失败都清理进程并保存结果。"""
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
        daemon_process = start_daemon(build, run_directory, "daemon")
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
                str(build / "kylinrca_lock_test"), "--scenario", "contention",
                "--threads", "8", "--hold-ms", "600", "--auto"], stdout=lock_output)
        workloads.append(lock_workload)
        lock_workloads = [lock_workload]
        lock_load_deadline = time.monotonic() + 6
        summary["workload_pids"] = {"syscall": syscall_workload.pid,
                                    "cpu": cpu_workload.pid, "lock": lock_workload.pid}
        print("正在连续查询并核对三个负载，约需 8 秒……", flush=True)

        syscall_seen = False
        cpu_seen = False
        cpu_runtime_seen = False
        lock_addresses = {}
        deadline = time.monotonic() + 8
        with (run_directory / "queries.jsonl").open("w") as query_log:
            while time.monotonic() < deadline:
                # 单次锁竞争很短，可能落在两次快照发布之间；持续制造六秒负载，逐个记录真实 PID。
                if time.monotonic() < lock_load_deadline and lock_workloads[-1].poll() is not None:
                    require(lock_workloads[-1].returncode == 0, "Lock workload failed")
                    with lock_log.open("a") as lock_output:
                        lock_workload = subprocess.Popen([
                            str(build / "kylinrca_lock_test"), "--scenario", "contention",
                            "--threads", "8", "--hold-ms", "600", "--auto"], stdout=lock_output)
                    lock_workloads.append(lock_workload)
                    workloads.append(lock_workload)
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
                        if process_stats["pid"] in {process.pid for process in lock_workloads}:
                            lock_addresses.setdefault(process_stats["pid"], set()).update(
                                int(entry["lock_addr"], 16) for entry in process_stats["locks"]
                                if entry["wait_count"] > 0)
                time.sleep(0.1)
        for workload in workloads:
            assert workload.wait(timeout=5) == 0, "A test workload failed"

        lock_text = lock_log.read_text()
        matched_lock = False
        for ready_line in lock_text.splitlines():
            if not ready_line.startswith("[MUTEX WORKLOAD]"):
                continue
            lock_fields = dict(token.split("=", 1) for token in ready_line.split() if "=" in token)
            mutex_address = int(lock_fields["mutex_addr"], 16)
            mutex_size = int(lock_fields["mutex_size"])
            matched_lock |= any(mutex_address <= address < mutex_address + mutex_size
                                for address in lock_addresses.get(int(lock_fields["pid"]), set()))
        latest = query(socket_path, "status")["data"]
        summary["latest"] = latest
        summary["lock_workload_pids"] = [process.pid for process in lock_workloads]
        summary["observed_lock_addresses"] = {
            str(pid): [hex(address) for address in sorted(addresses)]
            for pid, addresses in lock_addresses.items()
        }
        checks.update({
            "syscall_workload_pid": syscall_seen,
            "cpu_workload_pid_tid": cpu_seen,
            "cpu_runtime_evidence": cpu_runtime_seen,
            "lock_workload_pid_address": matched_lock and "passed=1" in lock_text,
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
        daemon_process = start_daemon(build, run_directory, "restart")
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
            stop_monitor(workload)
        stop_monitor(daemon_process)
        (run_directory / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    if not summary["passed"]:
        failed_checks = [name for name, passed in checks.items() if not passed]
        reason = summary.get("error") or ", ".join(failed_checks)
        raise RuntimeError("Socket 验收失败：" + reason + "，查看 " + str(run_directory / "summary.json"))
    return summary


def run_io_case(output, args):
    """执行一轮真实验收并返回结果字典。

    在新建镜像上创建 loop 设备，启动四模块 daemon，等待就绪后叠加 fio、CPU、锁和 Syscall 负载；
    停载后等待恢复，正常终止 daemon，再核对窗口、目标 PID、重叠时间和内核/用户态数量闭环。
    成功或异常都记录结果并清理进程和本轮设备；解除设备失败时保留镜像，异常继续向上抛出。
    """
    output.mkdir()
    temp = Path(tempfile.mkdtemp(prefix="kylinrca-daemon-io-"))
    image = temp / "disk.img"
    loop = None
    daemon = None
    workloads = []
    metadata = {"passed": False, "cleanup_complete": False}
    try:
        # 只写本轮新建的 128MiB 镜像，通过 loop 映射为测试设备，不选择已有业务磁盘。
        with image.open("wb") as stream:
            stream.truncate(128 * 1024 * 1024)
        loop = run(["losetup", "--find", "--show", str(image)])
        require(re.fullmatch(r"/dev/loop[0-9]+", loop), "unexpected loop device")
        if shutil.which("udevadm"):
            run(["udevadm", "settle", "--timeout=10"])
        info = os.stat(loop)
        device = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        config = output / "daemon.conf"
        socket_path = output / "daemon.sock"
        # 公共配置只控制 daemon，I/O 专用规则通过独立模块文件传入。
        config.write_text(f"socket_path={socket_path}\n" + "window_ms=1000\nenable_syscall=true\nenable_cpu=true\n"
                          "enable_lock=true\nenable_io=true\n")
        io_config = output / "io.conf"
        io_config.write_text(f"latency_threshold_us={args.threshold_us}\n"
                             f"min_samples={args.min_samples}\ndevice={device}\n")
        command = [str(args.build / "kylinrcad"), "--config", str(config),
                   "--io-config", str(io_config)]
        # 可显式传入其他模块文件，验证四模块同时使用各自配置时仍能共存。
        if args.cpu_config is not None:
            command.extend(["--cpu-config", str(args.cpu_config.resolve())])
        if args.lock_config is not None:
            command.extend(["--lock-config", str(args.lock_config.resolve())])
        fio_command = ["fio", str(ROOT / "scenarios/io_latency.fio"),
                       "--filename=" + loop, "--runtime=6", "--output-format=json"]
        cpu_command = ["stress-ng", "--cpu", str(min(os.cpu_count() or 1, 4)), "--timeout", "6s"]
        lock_command = [str(args.build / "kylinrca_lock_test"), "--scenario",
                        "contention", "--threads", "8", "--auto"]
        metadata.update(device=device, daemon_command=command, fio_command=fio_command,
                        cpu_command=cpu_command, lock_command=lock_command,
                        threshold_us=args.threshold_us, min_samples=args.min_samples)
        save(output / "metadata.json", metadata)
        with (output / "reports.json").open("w") as reports, (output / "daemon.log").open("w") as log:
            daemon = subprocess.Popen(command, stdout=reports, stderr=log, cwd=ROOT)
            for _ in range(200):
                require(daemon.poll() is None, "daemon exited before Ready")
                if "[daemon] Ready" in (output / "daemon.log").read_text():
                    break
                time.sleep(.05)
            else:
                raise RuntimeError("daemon readiness timeout")
            baseline = query(socket_path, "status")["data"]
            with QueryRecorder(socket_path, output / "queries.jsonl") as recorder:
                time.sleep(2.2)  # 先记录空闲基线，避免一启动就进入压力阶段而缺少正常对照。
                # fio 初始化可能比短时锁竞争更慢；先确认隔离设备已有真实样本，再启动其他负载。
                # 不能仅凭“进程同时创建”声称并发，后面仍独立核对报告窗口重叠。
                with (output / "cpu.log").open("w") as cpu_log, \
                     (output / "lock.log").open("w") as lock_log, \
                     (output / "fio.json").open("w") as fio_log, \
                     (output / "fio.stderr").open("w") as fio_error:
                    fio_process = subprocess.Popen(fio_command, stdout=fio_log, stderr=fio_error)
                    workloads.append(fio_process)
                    for _ in range(300):
                        require(daemon.poll() is None, "daemon exited while waiting for fio activity")
                        require(fio_process.poll() is None, "fio ended before confirmed I/O activity")
                        try:
                            current = read_documents(output / "reports.json")
                        except json.JSONDecodeError:
                            # 正在写入的最后一份文档可能尚未完整，下次重读，不把部分文档当作报告。
                            current = []
                        active = [r for r in current if r["type"] == "io_summary" and
                                  any(d["device"] == device and d["sample_count"] > 0 for d in r["devices"])]
                        if active:
                            metadata["io_activity_confirmed_window"] = {
                                "start_ns": active[-1]["window_start_ns"],
                                "end_ns": active[-1]["window_end_ns"]}
                            break
                        time.sleep(.05)
                    else:
                        raise RuntimeError("no real I/O samples before overlap workloads")
                    metadata["peer_workloads_started_ns"] = time.monotonic_ns()
                    cpu = subprocess.Popen(cpu_command, stdout=cpu_log, stderr=cpu_log)
                    workloads.append(cpu)
                    lock = subprocess.Popen(lock_command, stdout=lock_log, stderr=lock_log)
                    workloads.append(lock)
                    metadata["cpu_workload_pid"] = cpu.pid
                    metadata["lock_workload_pid"] = lock.pid
                    target = subprocess.Popen(["cat", "/proc/self/status"], stdout=subprocess.DEVNULL)
                    metadata["syscall_pid"] = target.pid
                    require(target.wait(timeout=5) == 0, "syscall workload failed")
                    require(fio_process.wait(timeout=30) == 0, "fio failed")
                    require(cpu.wait(timeout=15) == 0 and lock.wait(timeout=15) == 0, "overlap workload failed")
                time.sleep(7)  # 停载后预留足够时间，覆盖三个恢复窗口和恢复后的空闲尾部。
                check_protocol(socket_path)
                latest = query(socket_path, "status")["data"]
                require(latest["completed_windows"] > baseline["completed_windows"], "query stalled windows")
                require(all(latest["processed_events"][module] > baseline["processed_events"][module]
                            for module in ("syscall", "cpu", "lock", "io")), "query stalled event processing")
            io_queries = [frame["response"]["data"]["io"] for frame in recorder.replies
                          if frame["command"] == "report"]
            require(any(state["report"] and any(d["device"] == device and d["sample_count"] > 0
                        for d in state["report"]["devices"]) for state in io_queries), "Socket lost real I/O data")
            require(any(state["report"] and state["report"]["diagnoses"] for state in io_queries),
                    "Socket did not expose I/O alert")
            require(io_queries[-1]["report"] and not io_queries[-1]["report"]["diagnoses"],
                    "Socket did not expose I/O recovery")
            metadata["socket_queries"] = len(recorder.replies)
            daemon.send_signal(signal.SIGINT if args.sigint else signal.SIGTERM)
            require(daemon.wait(timeout=10) == 0, "daemon shutdown failed")
            require(not socket_path.exists(), "Socket path remains after shutdown")
        documents = read_documents(output / "reports.json")
        rows = [r for r in documents if r["type"] == "io_summary"]
        statuses = [r for r in documents if r["type"] == "io_status"]
        require(len(statuses) == 1, "missing final I/O snapshot")
        status = statuses[0]
        stats = status["probe"]
        # 复用第三周的独立验收规则，重放状态机并核对指标、字节数与传输丢失。
        devices = [d for r in rows for d in r["devices"]]
        health = "\n".join(f"STAT {k}={v}" for k, v in stats.items() if isinstance(v, int))
        health += (f"\nSUMMARY received={status['received']} invalid={status['invalid']} "
                   f"reads={status['reads']} "
                   f"writes={status['writes']} "
                   f"bytes={status['bytes']} pending={stats['pending']}\n")
        result = validate(rows, health, json.loads((output / "fio.json").read_text()),
                          device, args.threshold_us, args.min_samples)
        require(all(r["latency_threshold_ns"] == args.threshold_us * 1000 for r in rows),
                "threshold config ignored")
        require(status["enabled"] and status["capacity_drops"] == 0, "invalid I/O status")
        syscalls = [r for r in documents if r["type"] == "syscall_summary"]
        cpus = [r for r in documents if r["type"] == "cpu_summary"]
        locks = [r for r in documents if r["type"] == "lock_summary"]
        require(syscalls and cpus and locks, "missing one of the other three pipelines")
        # 先确认目标 PID 出现在输出中，再按实际报告字段核对目标进程、有效事件和窗口重叠。
        require(str(metadata["syscall_pid"]) in json.dumps(syscalls), "target syscall PID missing")
        require(any(r.get("received_events", 0) > 0 for r in cpus), "no CPU events")
        require(any(p["pid"] == lock.pid and any(s["wait_count"] > 0 for s in p["locks"])
                    for r in locks for p in r["processes"]), "target Lock wait events missing")
        require(all(r["rejected_events"] == 0 for r in locks), "Lock ABI corruption")
        require(any(p["pid"] == metadata["syscall_pid"] for r in syscalls for p in r["processes"]),
                "target Syscall statistics missing")
        # 取确实有 I/O 样本的窗口，与 CPU 和目标锁进程所在窗口比较，避免仅检查四种输出“出现过”。
        overlap = [(i["window_start_ns"], i["window_end_ns"]) for i in rows if i["devices"]]
        require(any(r["received_events"] > 0 and any(
                    r["window_start_ns"] < end and r["window_end_ns"] > start
                    for start, end in overlap) for r in cpus), "CPU/I/O did not overlap")
        require(any(p["pid"] == lock.pid for r in locks
                    if any(r["window_start_ns"] < end and r["window_end_ns"] > start
                           for start, end in overlap) for p in r["processes"]),
                "Lock/I/O did not overlap")
        metadata.update(result)
        metadata.update(modules=sorted({r["type"] for r in documents}),
                        cpu_windows=len(cpus), lock_windows=len(locks),
                        final_io_status=status, signal="SIGINT" if args.sigint else "SIGTERM")
    except BaseException as error:
        metadata["passed"] = False
        metadata["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        # 先结束进程，再解除设备关联；确认解除成功后才删除镜像，并将清理状态写入结果。
        stop_monitor(daemon)
        for process in workloads:
            stop_monitor(process)
        try:
            if loop:
                run(["losetup", "--detach", loop])
                for _ in range(50):
                    if not run(["losetup", "--associated", str(image)]):
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError("loop remains associated; image retained")
            shutil.rmtree(temp)
            metadata["cleanup_complete"] = True
        except BaseException as error:
            metadata.update(passed=False, cleanup_error=str(error))
            raise
        finally:
            save(output / "results.json", metadata)
    return metadata


def validate_modes(build, output):
    """按构建目录启动三种配置，验证仅启用 I/O 时默认阈值仍为 10ms、禁用 I/O 不输出采集数据、
    全关闭时明确非零退出；保存各模式日志和结果，失败时抛异常并回收当前进程。
    """
    results = []
    for name, switches in (("io-only-default", (False, False, False, True)),
                           ("io-disabled", (True, True, True, False)),
                           ("all-disabled", (False, False, False, False))):
        directory = output / name
        directory.mkdir()
        config = directory / "daemon.conf"
        socket_path = directory / "daemon.sock"
        config.write_text(f"socket_path={socket_path}\n" + "\n".join(f"enable_{key}={str(value).lower()}"
                          for key, value in zip(("syscall", "cpu", "lock", "io"), switches)) + "\n")
        command = [str(build / "kylinrcad"), "--config", str(config)]
        process = None
        with (directory / "reports.json").open("w") as out, (directory / "daemon.log").open("w") as log:
            try:
                process = subprocess.Popen(command, stdout=out, stderr=log, cwd=ROOT)
                if not any(switches):
                    require(process.wait(timeout=10) != 0, "all-disabled config accepted")
                    require("Enable at least one" in (directory / "daemon.log").read_text(),
                            "missing all-disabled error")
                else:
                    for _ in range(200):
                        require(process.poll() is None, name + " exited before Ready")
                        if "[daemon] Ready" in (directory / "daemon.log").read_text():
                            break
                        time.sleep(.05)
                    else:
                        raise RuntimeError(name + " readiness timeout")
                    time.sleep(2.2)
                    replies = {command: query(socket_path, command) for command in ("status", "top", "report")}
                    save(directory / "queries.json", replies)
                    require(replies["status"]["data"]["modules"] == dict(zip(("syscall", "cpu", "lock", "io"), switches)),
                            name + " wrong Socket module state")
                    require((replies["report"]["data"]["io"] is not None) == switches[3],
                            name + " wrong Socket I/O result")
                    process.send_signal(signal.SIGINT)
                    require(process.wait(timeout=10) == 0, name + " shutdown failed")
                    require(not socket_path.exists(), name + " Socket path remains")
                    rows = read_documents(directory / "reports.json")
                    status = next(r for r in rows if r["type"] == "io_status")
                    require(status["enabled"] == switches[3], name + " wrong I/O state")
                    if switches[3]:
                        require(all(r["latency_threshold_ns"] == 10000000 for r in rows
                                    if r["type"] == "io_summary"), "product default changed")
                        require(not any(r["type"] in ("cpu_summary", "lock_summary", "syscall_summary")
                                        for r in rows), "disabled module emitted report")
                    else:
                        require(not any(r["type"] in ("io_summary", "io_probe_stats") for r in rows)
                                and status["report"] is None, "disabled I/O emitted data")
            finally:
                stop_monitor(process)
        results.append({"mode": name, "passed": True, "command": command})
    save(output / "modes.json", results)
    return results


def main():
    """检查权限和依赖，按所选场景调用验收；任一场景失败即保存失败汇总并返回非零值。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--suite", choices=("all", "socket", "config", "io", "modes"), default="all")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--threshold-us", type=int, default=100, help="仅调整临时 loop 验收阈值，产品默认仍为 10ms")
    parser.add_argument("--min-samples", type=int, default=10)
    parser.add_argument("--sigint", action="store_true")
    parser.add_argument("--cpu-config", type=Path)
    parser.add_argument("--lock-config", type=Path)
    arguments = parser.parse_args()
    require(os.geteuid() == 0, "请使用 sudo python3 scripts/check_daemon.py")
    require(1 <= arguments.repeat <= 20 and arguments.threshold_us > 0 and arguments.min_samples > 0,
            "重复次数、阈值或最小样本数不合法")
    dependencies = set()
    if arguments.suite in ("all", "io"):
        dependencies.update(("fio", "losetup", "stress-ng"))
    if arguments.suite in ("all", "config"):
        dependencies.add("stress-ng")
    for executable in sorted(dependencies):
        require(shutil.which(executable), "缺少验收依赖：" + executable)
    arguments.build = arguments.build.resolve()
    output = (arguments.output or Path("/tmp/kylinrca-daemon-validation") / ("run-" + str(time.time_ns()))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    save(output / "environment.json", {
        "started_utc": datetime.now(timezone.utc).isoformat(), "kernel": platform.release(),
        "architecture": platform.machine(), "build": str(arguments.build),
        "git_commit": run(["git", "-c", "safe.directory=" + str(ROOT), "rev-parse", "HEAD"]),
        "git_status": run(["git", "-c", "safe.directory=" + str(ROOT), "status", "--short"]),
    })
    summary = {"passed": False, "output": str(output), "suite": arguments.suite, "cases": {}}

    def interrupted(signum, frame):
        """将终止信号转换为异常，使当前场景先执行资源清理，再保存失败汇总。"""
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    print("验证记录：" + str(output), flush=True)
    try:
        if arguments.suite in ("all", "socket"):
            summary["cases"]["socket"] = run_socket_case(arguments.build, output / "socket")
            print("PASS Socket、热点、runtime、重启与退出清理", flush=True)
        if arguments.suite in ("all", "config"):
            for module in ("cpu", "lock"):
                for active in (True, False):
                    name = module + ("-alert" if active else "-control")
                    summary["cases"][name] = module_config_case(output / name, arguments.build, module, active)
                    print("PASS " + name, flush=True)
        if arguments.suite in ("all", "io"):
            for index in range(arguments.repeat):
                name = f"io-{index + 1:02d}"
                summary["cases"][name] = run_io_case(output / name, arguments)
                print("PASS " + name, flush=True)
        if arguments.suite in ("all", "modes"):
            summary["cases"]["modes"] = validate_modes(arguments.build, output)
            print("PASS 仅 I/O、禁用 I/O、全部禁用", flush=True)
        summary["passed"] = True
    except (Exception, KeyboardInterrupt) as error:
        summary["error"] = f"{type(error).__name__}: {error}"
    finally:
        save(output / "results.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
