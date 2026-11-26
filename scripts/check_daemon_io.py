#!/usr/bin/env python3
"""用临时 loop 设备验证统一 daemon 的四模块共存、I/O 告警与恢复，并保存命令、报告和清理结果。"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import tempfile
import time

from check_io_analyzer import require, run, save, stop_monitor, validate

ROOT = Path(__file__).resolve().parents[1]


def read_documents(path):
    """读取连续 JSON 文档并返回列表；支持跨行的 Syscall 报告，不能把整个文件当作逐行 JSON。"""
    text = path.read_text()
    decoder = json.JSONDecoder()
    documents = []
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        documents.append(value)
        text = text[end:]
    return documents


def trial(output, args):
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
        # 公共配置只控制 daemon，I/O 专用规则通过独立模块文件传入。
        config.write_text("window_ms=1000\nenable_syscall=true\nenable_cpu=true\n"
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
            daemon.send_signal(signal.SIGINT if args.sigint else signal.SIGTERM)
            require(daemon.wait(timeout=10) == 0, "daemon shutdown failed")
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
        config.write_text("\n".join(f"enable_{key}={str(value).lower()}"
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
                    process.send_signal(signal.SIGINT)
                    require(process.wait(timeout=10) == 0, name + " shutdown failed")
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
    """验收脚本入口：解析目录、轮数和阈值，检查权限依赖，保存环境，再执行负载轮次或配置模式。
    输出目录必须是新目录；最终汇总只有全部请求的验证通过才标记成功，中断或失败仍保存当前结果。
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cpu-config", type=Path)
    parser.add_argument("--lock-config", type=Path)
    parser.add_argument("--repeat", type=int, default=3)
    # 100μs 只用于虚拟 loop 负载验收；不修改产品配置和分析器默认的 10ms。
    parser.add_argument("--threshold-us", type=int, default=100)
    parser.add_argument("--min-samples", type=int, default=10)
    parser.add_argument("--sigint", action="store_true")
    parser.add_argument("--modes-only", action="store_true", help="check I/O-only default, disabled I/O and all-disabled configurations")
    args = parser.parse_args()
    require(os.geteuid() == 0, "run as root for BPF and isolated loop devices")
    require(1 <= args.repeat <= 20 and args.threshold_us > 0 and args.min_samples > 0,
            "invalid repeat/threshold/min-samples")
    args.build = args.build.resolve()
    output = (args.output or ROOT / "build" / ("daemon-io-" +
              datetime.now().strftime("%Y%m%d-%H%M%S"))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    for executable in ("fio", "losetup", "stress-ng"):
        require(shutil.which(executable), "missing " + executable)
    environment = {"started_utc": datetime.now(timezone.utc).isoformat(),
                   "kernel": platform.release(), "architecture": platform.machine(),
                   "git_commit": run(["git", "-c", "safe.directory=" + str(ROOT), "rev-parse", "HEAD"]),
                   "git_status": run(["git", "-c", "safe.directory=" + str(ROOT), "status", "--short"]),
                   "build": str(args.build)}
    save(output / "environment.json", environment)
    summary = {"passed": False, "completed_trials": 0, "requested_trials": args.repeat}
    def interrupted(signum, frame):
        """把终止信号转换为异常，让正在执行的验收进入清理和结果保存流程。"""
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.modes_only:
            summary["modes"] = validate_modes(args.build, output)
            summary["requested_trials"] = 0
        for index in range(0 if args.modes_only else args.repeat):
            trial(output / f"run-{index+1:02d}", args)
            summary["completed_trials"] += 1
            print(f"trial {index+1}: passed", flush=True)
        summary["passed"] = True
    finally:
        save(output / "results.json", summary)
    print(json.dumps(dict(summary, output=str(output))))


if __name__ == "__main__":
    main()
