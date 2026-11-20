#!/usr/bin/env python3
"""自动验证真实 mutex 竞争、正常对照和告警恢复。"""
import argparse
import errno
import json
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from check_mutex_probe import CapturedProcess, evaluate, fields


# 使用 #22 的默认规则，验收时不降低阈值。
THRESHOLDS = {
    "window_ns": 1_000_000_000,
    "minimum_wait_ns": 1_000_000,
    "average_wait_threshold_ns": 10_000_000,
    "max_wait_threshold_ns": 50_000_000,
    "minimum_waiting_threads": 2,
    "recovery_windows": 2,
}
IDLE_SECONDS = 4


def empty_stats():
    return dict(event_count=0, wait_count=0, waiting_threads=0,
                total_wait_ns=0, avg_wait_ns=0, max_wait_ns=0,
                short_wait_count=0, eagain_count=0, timeout_count=0,
                interrupted_count=0, other_error_count=0, waiting_tids=[])


def window_stats(events, start, end):
    """从原始事件重算每个地址的指标，供报告核对。"""
    result = {}
    errors = {-errno.EAGAIN: "eagain_count", -errno.ETIMEDOUT: "timeout_count",
              -errno.EINTR: "interrupted_count"}
    for event in events:
        if not start <= int(event["timestamp_ns"]) < end:
            continue
        address = int(event["lock_addr"], 0)
        stat = result.setdefault(address, empty_stats())
        stat["event_count"] += 1
        ret = int(event["ret"])
        duration = int(event["duration_ns"])
        if ret:
            stat[errors.get(ret, "other_error_count")] += 1
        elif duration < THRESHOLDS["minimum_wait_ns"]:
            stat["short_wait_count"] += 1
        else:
            stat["wait_count"] += 1
            stat["total_wait_ns"] += duration
            stat["max_wait_ns"] = max(stat["max_wait_ns"], duration)
            stat["waiting_tids"].append(int(event["tid"]))
    for stat in result.values():
        stat["waiting_tids"] = sorted(set(stat["waiting_tids"]))
        stat["waiting_threads"] = len(stat["waiting_tids"])
        stat["avg_wait_ns"] = stat["total_wait_ns"] // stat["wait_count"] if stat["wait_count"] else 0
    return result


def parse_probe(lines):
    """同时读取原始记录、JSON 和探针计数；坏 JSON 直接报错。"""
    events, reports, counters = [], [], {}
    for line in lines:
        if line.startswith("[LOCK]"):
            events.append(fields(line))
        elif line.startswith("{"):
            report = json.loads(line)
            if not isinstance(report, dict) or report.get("type") != "lock_summary":
                raise ValueError("Unexpected JSON report type")
            reports.append(report)
        elif line.startswith("[LOCK PROBE]") and "ready" not in line:
            counters.update({key: int(value) for key, value in fields(line).items()})
    return events, reports, counters


def report_stats(report, pid):
    """读取报告中的逐锁统计，拒绝重复分组和其他 PID。"""
    result = {}
    processes = report["processes"]
    if len(processes) > 1:
        raise ValueError("Unexpected process groups in a PID-filtered report")
    for process in processes:
        if process["pid"] != pid:
            raise ValueError("JSON PID did not match the workload")
        for stat in process["locks"]:
            address = int(stat["lock_addr"], 0)
            if address in result:
                raise ValueError("Duplicate lock address in JSON")
            result[address] = {key: stat[key] for key in empty_stats()}
    return result


def evaluate_reports(scenario, ready, workers, events, reports):
    """逐窗口核对统计、主要对象和恢复状态。"""
    if not reports:
        raise ValueError("No lock_summary JSON; check --analyze and probe logs")
    pid = int(ready["pid"])
    base = int(ready["mutex_addr"], 0)
    size = int(ready["mutex_size"])
    worker_tids = {int(worker["tid"]) for worker in workers}
    errors, alerts = [], []
    previous_end = None
    received = 0
    active = None
    normal_windows = 0
    recovered = False
    for event in events:
        timestamp, duration = int(event["timestamp_ns"]), int(event["duration_ns"])
        if (int(event["pid"]) != pid or int(event["tid"]) <= 0 or
                int(event["lock_addr"], 0) <= 0 or not 0 <= duration <= timestamp or
                timestamp <= 0 or int(event["ret"]) > 0 or
                (int(event["futex_op"]) & ~(128 | 256)) not in (0, 9)):
            raise ValueError("Invalid raw futex event")
    if events and (min(int(e["timestamp_ns"]) for e in events) < reports[0]["window_start_ns"] or
                   max(int(e["timestamp_ns"]) for e in events) >= reports[-1]["window_end_ns"]):
        raise ValueError("JSON windows did not cover all raw events")
    for index, report in enumerate(reports):
        start, end = report["window_start_ns"], report["window_end_ns"]
        if not 0 < end - start <= THRESHOLDS["window_ns"]:
            raise ValueError("Invalid report window")
        if previous_end is not None and start != previous_end:
            raise ValueError("Report windows were missing, duplicated or out of order")
        previous_end = end
        if report["thresholds"] != THRESHOLDS:
            raise ValueError("RCA thresholds differ from the documented defaults")
        if report["wait_metric"] != "completed_futex_wait_ns":
            raise ValueError("Unexpected wait metric")
        if not received <= report["received_events"] <= len(events):
            raise ValueError("Invalid cumulative received_events")
        received = report["received_events"]
        if report["rejected_events"] or report["late_events"]:
            errors.append("analyzer rejected or late event counters were nonzero")

        expected = window_stats(events, start, end)
        if report_stats(report, pid) != expected:
            errors.append(f"window {index}: JSON statistics did not match raw events")
        qualified = [address for address, stat in expected.items()
                     if stat["waiting_threads"] >= THRESHOLDS["minimum_waiting_threads"]
                     and stat["avg_wait_ns"] >= THRESHOLDS["average_wait_threshold_ns"]
                     and stat["max_wait_ns"] >= THRESHOLDS["max_wait_threshold_ns"]]
        if qualified:
            address = min(qualified, key=lambda key: (-expected[key]["total_wait_ns"], key))
            active = dict(address=address, stats=expected[address], start=start, end=end)
            normal_windows = 0
            alerts.append(dict(window_start_ns=start, window_end_ns=end,
                               lock_addr=hex(address), **expected[address]))
            if (scenario == "uncontended" or not base <= address < base + size or
                    not set(expected[address]["waiting_tids"]) <= worker_tids):
                errors.append("alert did not identify the shared workload mutex and workers")
        elif active:
            # 空窗口也要计入恢复；只把完整窗口当作恢复证据。
            if end - start != THRESHOLDS["window_ns"]:
                errors.append("recovery relied on a partial window")
            normal_windows += 1
            if normal_windows >= THRESHOLDS["recovery_windows"]:
                active = None
                recovered = True

        diagnosis = report["diagnosis"]
        expected_diagnosis = dict(
            type="LOCK_CONTENTION" if active else "NORMAL",
            pid=pid if active else 0,
            lock_addr=hex(active["address"]) if active else "0x0",
            evidence_window_start_ns=active["start"] if active else 0,
            evidence_window_end_ns=active["end"] if active else 0,
            recovery_windows=normal_windows if active else 0,
            **(active["stats"] if active else empty_stats()),
        )
        if any(diagnosis[key] != value for key, value in expected_diagnosis.items()):
            errors.append(f"window {index}: diagnosis or recovery evidence was incorrect")

    if received != len(events):
        errors.append("final JSON received_events did not match raw records")
    if scenario == "contention" and (not alerts or not recovered or active):
        errors.append("shared mutex must trigger LOCK_CONTENTION and then recover")
    if scenario == "uncontended" and alerts:
        errors.append("uncontended scenario triggered an alert")
    # 两种场景都需要保留负载结束后的正常空窗口。
    if len(reports) < 3 or reports[-1]["processes"] or reports[-1]["diagnosis"]["type"] != "NORMAL":
        errors.append("missing idle NORMAL report after the workload")
    return dict(errors=errors, window_count=len(reports), alert_windows=alerts,
                recovery_observed=recovered, thresholds=THRESHOLDS.copy())


def evaluate_case(scenario, ready, workers, summary, events, counters, reports):
    # 复用 #21 的真实 mutex 地址、TID、时间区间和采集健康检查。
    result = evaluate(scenario, ready, workers, summary, events, counters)
    analysis = evaluate_reports(scenario, ready, workers, events, reports)
    result["errors"].extend(analysis.pop("errors"))
    result.update(analysis)
    result["errors"] = sorted(set(result["errors"]))
    result["passed"] = not result["errors"]
    return result


def run_case(options, scenario, output_dir):
    """先挂探针再放行负载，退出后保留完整日志。"""
    output_dir.mkdir(parents=True)
    workload = probe = None
    report = dict(passed=False, scenario=scenario, errors=[])
    try:
        workload_command = [str(options.build_dir / "kylinrca_lock_test"),
                            "--scenario", scenario, "--threads", str(options.threads),
                            "--hold-ms", str(options.hold_ms)]
        report["workload_command"] = workload_command
        workload = CapturedProcess(workload_command, "[MUTEX WORKLOAD] ready")
        ready = workload.wait_ready()
        if int(ready["pid"]) != workload.process.pid:
            raise ValueError("Workload PID did not match the observer namespace")
        if int(ready["threads"]) != options.threads or int(ready["hold_ms"]) != options.hold_ms:
            raise ValueError("Workload parameters did not match the requested configuration")
        probe_command = [str(options.build_dir / "kylinrca_lock_probe_smoke"),
                         "--pid", str(workload.process.pid), "--duration", "30", "--analyze",
                         "--object", str(options.build_dir / "lock.bpf.o")]
        report["probe_command"] = probe_command
        probe = CapturedProcess(probe_command, "[LOCK PROBE] ready")
        if int(probe.wait_ready()["target_pid"]) != workload.process.pid:
            raise ValueError("Probe target PID did not match the workload")
        workload.process.stdin.write("start\n")
        workload.process.stdin.flush()
        workload.process.stdin.close()
        workload_code = workload.wait()
        # 保持采集，让完整正常窗口证明告警已恢复。
        if probe.finished.wait(IDLE_SECONDS):
            raise RuntimeError("Probe exited before idle recovery observation completed")
        probe.process.send_signal(signal.SIGINT)
        probe_code = probe.wait()
        events, reports, counters = parse_probe(probe.lines)
        workers = [fields(line) for line in workload.lines if line.startswith("[MUTEX WORKER]")]
        summaries = [fields(line) for line in workload.lines if line.startswith("[MUTEX RESULT]")]
        commands = {key: report[key] for key in ("workload_command", "probe_command")}
        report = evaluate_case(scenario, ready, workers, summaries[-1] if summaries else {},
                               events, counters, reports)
        report.update(commands, workload_returncode=workload_code, probe_returncode=probe_code)
        if workload_code or probe_code:
            report["errors"].append("Workload or probe returned a nonzero exit code")
            report["passed"] = False
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        report["passed"] = False
        report["errors"].append(str(error))
    except KeyboardInterrupt:
        report["errors"].append("Interrupted by user")
        raise
    finally:
        for name, process in (("probe", probe), ("workload", workload)):
            if process is not None:
                process.stop()
                path = output_dir / f"{name}.log"
                path.write_text("".join(process.lines))
                report[f"{name}_log"] = str(path)
        if probe is not None:
            (output_dir / "reports.jsonl").write_text(
                "".join(line for line in probe.lines if line.startswith("{")))
        report.update(kernel=platform.release(), architecture=platform.machine())
        (output_dir / "result.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=("both", "contention", "uncontended"), default="both")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--hold-ms", type=int, default=100)
    parser.add_argument("--build-dir", type=Path, default=root / "build")
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/kylinrca-lock-rca-validation"))
    options = parser.parse_args()
    if not 1 <= options.rounds <= 20 or not 8 <= options.threads <= 64 or not 100 <= options.hold_ms <= 1000:
        parser.error("rounds must be 1..20, threads 8..64, hold-ms 100..1000")
    options.build_dir = options.build_dir.resolve()
    for name in ("kylinrca_lock_test", "kylinrca_lock_probe_smoke", "lock.bpf.o"):
        if not (options.build_dir / name).is_file():
            parser.error(f"Missing {name}; build the project first")
    options.output_dir.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=options.output_dir.resolve()))
    run_dir.chmod(0o755) # sudo 运行后，普通用户也能进入目录查看报告。
    scenarios = ("contention", "uncontended") if options.scenario == "both" else (options.scenario,)
    result = dict(passed=False, rounds=options.rounds, scenarios=list(scenarios),
                  output_dir=str(run_dir), cases=[])
    interrupted = False
    try:
        for iteration in range(1, options.rounds + 1):
            for scenario in scenarios:
                case_dir = run_dir / f"round-{iteration:02d}" / scenario
                case = run_case(options, scenario, case_dir)
                result["cases"].append(case)
                print(f"round={iteration} scenario={scenario} passed={case['passed']} logs={case_dir}",
                      file=sys.stderr, flush=True)
    except KeyboardInterrupt:
        interrupted = True
    result["interrupted"] = interrupted
    result["passed"] = (not interrupted and len(result["cases"]) == options.rounds * len(scenarios)
                        and all(case["passed"] for case in result["cases"]))
    (run_dir / "results.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 130 if interrupted else (0 if result["passed"] else 1)


if __name__ == "__main__":
    raise SystemExit(main())
