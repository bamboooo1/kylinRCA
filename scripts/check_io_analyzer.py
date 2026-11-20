#!/usr/bin/env python3
"""在临时 loop 设备上重复执行 fio，验证真实 I/O 采集、延迟诊断和空闲恢复。

每轮依次创建镜像、启动监控、运行负载、核对结果，最后释放设备和临时文件。
"""
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

# 根据脚本位置查找仓库，避免依赖启动命令时所在的目录。
ROOT = Path(__file__).resolve().parents[1]
# 这些探针错误计数必须存在且为零，才能通过验收。
ZERO_STATS = ("ringbuf_drop", "map_update_fail", "map_delete_fail",
              "bad_timestamp", "read_fail")


def run(args):
    """执行外部命令并返回文本；命令失败或超时则抛出异常。"""
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=30).stdout.strip()


def require(condition, message):
    """条件不满足时终止验收；与 assert 不同，不受 Python 优化选项影响。"""
    if not condition:
        raise ValueError(message)


def validate(rows, health, fio, device, threshold_us, min_samples):
    """核对窗口报告、探针日志与 fio 结果，全部通过后返回汇总。

    rows 是各时间窗口的 JSON 报告；health 是监控进程的健康日志。
    device 是目标设备编号；threshold_us 和 min_samples 是诊断门槛。
    """
    require(len(rows) >= 8, "too few report windows")
    # 一个窗口可能包含多个设备，先展开，再核对设备归属和统计指标。
    devices = [d for row in rows for d in row["devices"]]
    require(devices and all(d["device"] == device for d in devices),
            "missing block events or wrong device")
    for d in devices:
        require(d["sample_count"] > 0 and d["bytes"] > 0
                and d["avg_duration_ns"] > 0
                and d["p99_duration_ns"] >= d["p95_duration_ns"] > 0,
                "invalid device metrics")
    # 独立重放设备状态，检查第三次才触发、第三次正常才恢复。
    states = {}
    alerts = []
    for row in rows:
        require(row["alert_consecutive_windows"] == 3 and row["recovery_consecutive_windows"] == 3,
                "unexpected consecutive-window configuration")
        current = {d["device"]: d for d in row["devices"]}
        if row["window_complete"]:
            for key in set(states) | set(current):
                d = current.get(key)
                abnormal = d is not None and d["sample_count"] >= min_samples and d["p95_duration_ns"] >= threshold_us * 1000
                state = states.setdefault(key, {"active": False, "abnormal": 0, "recovery": 0})
                if abnormal:
                    state["abnormal"] = min(state["abnormal"] + 1, 3)
                    state["recovery"] = 0
                    state["active"] = state["active"] or state["abnormal"] == 3
                else:
                    state["abnormal"] = 0
                    if state["active"]:
                        state["recovery"] += 1
                        state["active"] = state["recovery"] < 3
                if not state["active"] and not state["abnormal"]:
                    del states[key]
        expected = {key: {"device": key, "diagnosis": "IO_LATENCY",
                          "abnormal_windows": state["abnormal"], "recovery_windows": state["recovery"]}
                    for key, state in states.items() if state["active"]}
        actual = {d["device"]: d for d in row["diagnoses"]}
        require(actual == expected, "persistent diagnosis or recovery sequence differs")
        for key, d in current.items():
            state = states.get(key, {"active": False, "abnormal": 0, "recovery": 0})
            abnormal = d["sample_count"] >= min_samples and d["p95_duration_ns"] >= threshold_us * 1000
            require(d["window_abnormal"] == abnormal
                    and d["diagnosis"] == ("IO_LATENCY" if state["active"] else "NORMAL")
                    and d["abnormal_windows"] == state["abnormal"]
                    and d["recovery_windows"] == state["recovery"], "device state differs")
            if state["active"]:
                alerts.append(d)
    require(alerts, "fio did not trigger confirmed IO_LATENCY")
    # 空闲末尾不仅没有新样本，持续告警也必须已经解除。
    require(all(not r["devices"] and not r["diagnoses"] for r in rows[-3:]),
            "idle tail retains events/alerts")
    require(all(r[k] == 0 for r in rows
                for k in ("invalid_events", "capacity_drops")),
            "analyzer rejected or dropped events")
    # STAT 来自内核探针；SUMMARY 来自用户态事件接收程序。
    # 两侧数量一致，才能排除已输出事件在传输或接收环节丢失。
    stats = {k: int(v) for k, v in re.findall(r"^STAT (\w+)=(\d+)$", health, re.M)}
    require(all(stats.get(k) == 0 for k in ZERO_STATS), "missing/nonzero probe health counter")
    match = re.search(r"^SUMMARY received=(\d+) invalid=(\d+) reads=(\d+) "
                      r"writes=(\d+) bytes=(\d+) pending=(\d+)$", health, re.M)
    require(match is not None, "missing consumer summary")
    received, invalid, reads, writes, byte_count, pending = map(int, match.groups())
    require(received > 0 and received == stats.get("emitted") and invalid == pending == 0,
            "consumer loss, invalid record or pending request")
    # 已关闭窗口的迟到事件不会重新聚合，但必须计入接收总数。
    late = sum(r["late_events"] for r in rows)
    accepted = sum(d["sample_count"] for d in devices)
    accepted_bytes = sum(d["bytes"] for d in devices)
    require(accepted + late == received and writes > 0,
            "accepted + explicitly late events differ from consumer total")
    # 迟到事件未计入设备 bytes，存在迟到时两侧 bytes 不一定相等。
    require(0 < accepted_bytes <= byte_count and (late > 0 or accepted_bytes == byte_count),
            "report/consumer bytes differ without late events")
    require(not rows[0]["devices"], "idle baseline contains events")
    # 同时检查负载自身的执行结果，避免将 fio 启动失败当成正常对照。
    jobs = fio["jobs"]
    require(jobs and all(j["error"] == 0 for j in jobs)
            and sum(j["write"]["io_bytes"] for j in jobs) > 0,
            "fio failed or wrote no data")
    return {"passed": True, "device": device, "windows": len(rows),
            "alert_device_windows": len(alerts), "idle_tail_windows": 3,
            "threshold_ns": threshold_us * 1000, "min_samples": min_samples,
            "received": received, "bytes": byte_count, "accepted_samples": accepted,
            "late_events": late, "accepted_bytes": accepted_bytes, "probe_stats": stats,
            "example_alert": alerts[0]}


def save(path, value):
    """将记录保存为带缩进的 JSON，便于人工复查。"""
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def stop_monitor(process):
    """优先请求监控程序正常退出；超时后强制结束并回收子进程。"""
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def trial(output, args, environment):
    """执行一轮完整验收；失败或中断时仍尝试清理本轮资源。"""
    output.mkdir()
    tmp = Path(tempfile.mkdtemp(prefix="kylinrca-fio-"))
    image = tmp / "disk.img"
    loop = None
    monitor = None
    # 先写入失败状态；只有校验和清理均完成后才生成本轮成功结果。
    metadata = dict(environment, passed=False, image=str(image),
                    image_size_bytes=128 * 1024 * 1024, cleanup_complete=False)
    save(output / "metadata.json", metadata)
    try:
        # loop 将普通文件映射为块设备，fio 只写本次创建的镜像。
        with image.open("wb") as stream:
            stream.truncate(metadata["image_size_bytes"])
        loop = run(["losetup", "--find", "--show", str(image)])
        metadata["loop"] = loop
        require(re.fullmatch(r"/dev/loop[0-9]+", loop), "unexpected loop path")
        if shutil.which("udevadm"):
            run(["udevadm", "settle", "--timeout=10"])
        # 从设备文件读取主、次设备号，用于限定探针采集范围。
        info = os.stat(loop)
        device = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
        monitor_cmd = [str(ROOT / "build/kylinrca_io_rca_smoke"),
                       "--seconds", "12", "--device", device, "--window-ms", "1000",
                       "--threshold-us", str(args.threshold_us),
                       "--min-samples", str(args.min_samples)]
        fio_cmd = ["fio", str(ROOT / "scenarios/io_latency.fio"),
                   "--filename=" + loop, "--output-format=json"]
        # 启动前保存完整命令和配置，即使中途失败也可追查。
        metadata.update(device=device, monitor_command=monitor_cmd, fio_command=fio_cmd,
                        fio_job=(ROOT / "scenarios/io_latency.fio").read_text(),
                        detach_command=["losetup", "--detach", loop])
        save(output / "metadata.json", metadata)
        with (output / "reports.jsonl").open("w") as reports, (output / "probe.log").open("w") as log:
            monitor = subprocess.Popen(monitor_cmd, cwd=ROOT, stdout=reports, stderr=log)
            # 最多等待约 5 秒，确认探针就绪后再施加 I/O 负载。
            for _ in range(100):
                require(monitor.poll() is None, "monitor failed before READY")
                if "READY io_rca" in (output / "probe.log").read_text():
                    break
                time.sleep(.05)
            else:
                raise RuntimeError("monitor readiness timeout")
            # 先保留空闲基线；4 秒负载结束后，监控继续记录恢复窗口。
            time.sleep(2)
            with (output / "fio.json").open("w") as out, (output / "fio.stderr").open("w") as err:
                subprocess.run(fio_cmd, check=True, text=True, stdout=out, stderr=err, timeout=30)
            require(monitor.wait(timeout=20) == 0, "monitor failed")
        result = validate([json.loads(line) for line in (output / "reports.jsonl").read_text().splitlines()],
                          (output / "probe.log").read_text(),
                          json.loads((output / "fio.json").read_text()),
                          device, args.threshold_us, args.min_samples)
        metadata.update(result)
    except BaseException as error:
        # 包含 KeyboardInterrupt，使 Ctrl+C 或 SIGTERM 也能留下中断记录。
        metadata["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        try:
            # 按顺序停止采集、解除设备关联，再删除 backing file（镜像文件）。
            stop_monitor(monitor)
            if loop is not None:
                run(["losetup", "--detach", loop])
                # detach 可能延迟生效，因此确认关联已解除后才能删除镜像。
                for _ in range(50):
                    if not run(["losetup", "--associated", str(image)]):
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError("loop still associated; backing file retained")
            # 上面的步骤失败会跳过删除，保留仍可能被使用的镜像。
            shutil.rmtree(tmp)
            metadata["cleanup_complete"] = True
        except BaseException as error:
            metadata["passed"] = False
            metadata["cleanup_error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            save(output / "metadata.json", metadata)
    # 异常会继续向外传播，只有验收及清理成功才会执行到这里。
    save(output / "results.json", metadata)
    return metadata


def interrupted(signum, frame):
    """将 SIGTERM 转为异常，让控制流程进入 finally 执行清理。"""
    raise KeyboardInterrupt(f"signal {signum}")


def main():
    """检查运行条件、逐轮执行验收，并保存整体结果。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeat", type=int, default=3)
    # 100 微秒是虚拟 loop 场景的验收阈值，不修改 Analyzer 默认的 10 毫秒。
    parser.add_argument("--threshold-us", type=int, default=100)
    parser.add_argument("--min-samples", type=int, default=10)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 20 or args.threshold_us <= 0 or args.min_samples <= 0:
        parser.error("repeat must be 1..20; threshold-us and min-samples must be positive")
    if os.geteuid() != 0:
        parser.error("requires root for BPF and temporary loop device")
    for program in ("fio", "losetup"):
        require(shutil.which(program), f"install {program} first")
    require((ROOT / "build/kylinrca_io_rca_smoke").is_file(), "build the project first")
    output = args.output or ROOT / "build" / ("io-fio-" + datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    output = output.resolve()
    # 拒绝复用已有目录，防止旧的成功记录混入本次结果。
    output.mkdir(parents=True, exist_ok=False)
    signal.signal(signal.SIGTERM, interrupted)
    # 保存环境与 Git 基线；safe.directory 仅对本次 Git 命令生效，
    # 允许以 root 身份读取普通用户拥有的仓库，不修改全局 Git 配置。
    environment = {"started_utc": datetime.now(timezone.utc).isoformat(),
                   "kernel": platform.release(), "architecture": platform.machine(),
                   "os_release": Path("/etc/os-release").read_text(),
                   "fio_version": run(["fio", "--version"]),
                   "losetup_version": run(["losetup", "--version"]),
                   "git_commit": run(["git", "-c", "safe.directory=" + str(ROOT), "-C", str(ROOT), "rev-parse", "HEAD"]),
                   "git_status": run(["git", "-c", "safe.directory=" + str(ROOT), "-C", str(ROOT), "status", "--short"]),
                   "threshold_us": args.threshold_us, "min_samples": args.min_samples,
                   "window_ms": 1000, "repeat": args.repeat}
    save(output / "environment.json", environment)
    results = []
    summary = {"passed": False, "requested_trials": args.repeat, "output": str(output)}
    try:
        for index in range(args.repeat):
            result = trial(output / f"run-{index + 1:02d}", args, environment)
            results.append(result)
            print(json.dumps({"trial": index + 1, "passed": True,
                              "alerts": result["alert_device_windows"], "output": str(output)}), flush=True)
        # 只有全部轮次通过，整体结果才标记为成功。
        summary["passed"] = True
    finally:
        # 任一轮失败或中断时也保存总结果，passed 保持 False。
        summary["completed_trials"] = len(results)
        save(output / "results.json", summary)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
