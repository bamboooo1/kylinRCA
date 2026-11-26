#!/usr/bin/env python3
"""用真实 CPU/锁负载和两组相反规则，验证模块文件经 daemon 传入分析器并实际影响诊断。"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import time

from check_daemon_io import read_documents
from check_io_analyzer import require, save, stop_monitor, run

ROOT = Path(__file__).resolve().parents[1]


def case(output, build, module, active):
    """运行一个模块配置用例，核对实际阈值、有效事件和预期诊断，成功失败均回收进程并保存结果。"""
    output.mkdir()
    daemon = None
    workload = None
    result = {"passed": False, "module": module, "expected_alert": active}
    try:
        common = output / "daemon.conf"
        common.write_text("window_ms=200\nenable_syscall=false\nenable_io=false\n"
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
            time.sleep(.3)
            workload = subprocess.Popen(load_command, stdout=load_log, stderr=load_log)
            result["workload_pid"] = workload.pid
            require(workload.wait(timeout=15) == 0, "workload failed")
            time.sleep(.8)
            daemon.send_signal(signal.SIGTERM)
            require(daemon.wait(timeout=10) == 0, "daemon failed on shutdown")
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
            require(alert_rows, "custom rules did not trigger expected alert")
            if module == "cpu":
                require(any(r["diagnosis"]["system_usage_percent"] >= settings["high_usage_threshold_percent"]
                            for r in alert_rows), "CPU diagnosis lacks usage evidence")
            else:
                require(rows[-1]["diagnosis"]["type"] == "NORMAL", "Lock did not recover")
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


def main():
    """检查真实采集依赖，按 CPU/Lock 的触发和对照四个用例执行，记录环境与完整结果。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=ROOT / "build")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    require(os.geteuid() == 0, "requires root to load BPF")
    require(shutil.which("stress-ng"), "install stress-ng")
    args.build = args.build.resolve()
    output = (args.output or ROOT / "build" / ("module-config-" +
              datetime.now().strftime("%Y%m%d-%H%M%S"))).resolve()
    output.mkdir(parents=True, exist_ok=False)
    save(output / "environment.json", {"started_utc": datetime.now(timezone.utc).isoformat(),
         "kernel": platform.release(), "architecture": platform.machine(),
         "base_commit": run(["git", "-c", "safe.directory=" + str(ROOT), "rev-parse", "HEAD"]),
         "build": str(args.build)})
    summary = {"passed": False, "cases": []}
    def interrupted(signum, frame):
        """将终止信号转为异常，进入当前用例的清理和结果保存流程。"""
        raise KeyboardInterrupt(f"signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        for module in ("cpu", "lock"):
            for active in (True, False):
                name = module + ("-alert" if active else "-control")
                summary["cases"].append(case(output / name, args.build, module, active))
                print(name + ": passed", flush=True)
        summary["passed"] = True
    finally:
        save(output / "results.json", summary)
    print(json.dumps(dict(summary, output=str(output))))


if __name__ == "__main__":
    main()
