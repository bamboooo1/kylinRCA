#!/usr/bin/env python3
"""真实 CPU 链路回归：空闲、全核压力、恢复、热点身份与窗口证据。需 root。"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("--label", default="full")
parser.add_argument("--output-dir", default="/tmp/kylinrca-cpu-validation")
parser.add_argument("--oversubscribe", action="store_true")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
out = Path(args.output_dir)
out.mkdir(parents=True, exist_ok=True)
if os.geteuid() != 0:
    raise SystemExit("请使用 sudo 运行本脚本；脚本不读取或保存密码")
log_path = out / (args.label + ".log")
start = time.monotonic()
with log_path.open("w") as log:
    probe = subprocess.Popen([str(root / "build/kylinrca_cpu_rca_smoke"), "32"],
                             cwd=root, stdout=log, stderr=subprocess.STDOUT)
    load = None
    try:
        time.sleep(6)
        if probe.poll() is not None:
            raise RuntimeError("探针在启动压力前退出，检查完整日志")
        load_started = time.monotonic_ns()
        load = subprocess.Popen(["stress-ng", "--cpu", str(os.cpu_count() * (2 if args.oversubscribe else 1)),
                                 "--timeout", "15s", "--metrics-brief"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                text=True)
        time.sleep(3)
        # stress-ng 的 worker 是独立子进程，记录真实 PID，校验 namespace 映射。
        workers = set()
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():
                continue
            try:
                status = (path / "status").read_text()
                ppid = int(next(x for x in status.splitlines() if x.startswith("PPid:")).split()[1])
                if ppid == load.pid and (path / "comm").read_text().strip() == "stress-ng-cpu":
                    workers.add(int(path.name))
            except (OSError, StopIteration, ValueError):
                continue
        _, load_stderr = load.communicate(timeout=25)
        (out / (args.label + "-stress.log")).write_text(load_stderr)
        code = probe.wait(timeout=25)
    finally:
        for process in (load, probe):
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

samples = []
counters = {}
for line in log_path.read_text().splitlines():
    if line.startswith("[CPU RCA]"):
        samples.append(dict(token.split("=", 1) for token in line.split()[2:] if "=" in token))
    elif line.startswith("[CPU PROBE]"):
        key, value = line.split()[2].split("=")
        counters[key] = int(value)

def percent(value):
    return float(value.rstrip("%"))

hot = [s for s in samples if s.get("thread_comm") == "stress-ng-cpu"
       and percent(s["thread_usage"]) >= (20 if args.oversubscribe else 80)]
alerts = [s for s in samples if s["state"] != "NORMAL"]
latency = ((int(alerts[0]["sample_ns"]) - load_started) / 1e9) if alerts else None
errors = []
usage_differences = []
if code != 0 or load.returncode != 0:
    errors.append("探针或负载退出码非零")
for key in ("bad_runqueue_timestamp", "bad_oncpu_timestamp", "ringbuf_drop",
            "wakeup_update_fail", "oncpu_update_fail", "requeue_update_fail"):
    if counters.get(key) != 0:
        errors.append(key + " 非零或缺失")
if not workers or not hot:
    errors.append("没有获得负载 PID 或热点样本")
for sample in hot:
    if int(sample["culprit_pid"]) not in workers:
        errors.append("热点 PID 未匹配本轮真实 worker")
    if sample["runtime_valid"] != "1" or int(sample["culprit_oncpu_ns"]) <= 0:
        errors.append("高占用线程缺失有效 BPF 运行证据")
    if int(sample["culprit_oncpu_ns"]) > int(sample["runtime_window_ns"]) + int(sample["runtime_uncertainty_ns"]):
        errors.append("运行时间超过窗口加读取不确定度")
    if sample["runtime_valid"] == "1" and int(sample["runtime_window_ns"]) > 0:
        bpf_percent = int(sample["culprit_oncpu_ns"]) / int(sample["runtime_window_ns"]) * 100
        difference = abs(bpf_percent - percent(sample["thread_usage"]))
        usage_differences.append(difference)
        # tick 量化、读取时刻及探针/中断开销允许小偏差，但不能仅因非零就判正确。
        if difference > 15:
            errors.append("BPF 与 proc 热点使用率相差超过15个百分点")
if not alerts or latency is None or not 0 <= latency <= 10:
    errors.append("未在负载开始后 10 秒内告警")
if not samples or any(s["state"] != "NORMAL" for s in samples[:3] + samples[-3:]):
    errors.append("空闲误报或负载停止后未恢复")
ratios = [int(s["culprit_oncpu_ns"]) / int(s["runtime_window_ns"]) * 100 for s in hot
          if s["runtime_valid"] == "1" and int(s["runtime_window_ns"]) > 0]
report = dict(label=args.label, passed=not errors, errors=sorted(set(errors)),
              elapsed_seconds=round(time.monotonic()-start, 3), samples=len(samples),
              hot_samples=len(hot), worker_pids=sorted(workers),
              alert_latency_seconds=latency, counters=counters,
              min_hot_bpf_percent=min(ratios) if ratios else None,
              max_hot_bpf_percent=max(ratios) if ratios else None,
              max_usage_difference_pp=max(usage_differences) if usage_differences else None,
              log=str(log_path))
(out / (args.label + ".json")).write_text(json.dumps(report, ensure_ascii=False, indent=2))
print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
raise SystemExit(0 if not errors else 1)
