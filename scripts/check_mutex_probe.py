import argparse
import json
from pathlib import Path
import platform
import signal
import subprocess
import threading
import time


def fields(line):
    return dict(token.split("=", 1) for token in line.split() if "=" in token)


class CapturedProcess:
    def __init__(self, command, prefix):
        self.lines = []
        self.prefix = prefix
        self.ready_line = None
        self.ready = threading.Event()
        self.finished = threading.Event()
        self.process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        self.reader = threading.Thread(target=self.read_output, daemon=True)
        self.reader.start()

    def read_output(self):
        try:
            for line in self.process.stdout:
                self.lines.append(line)
                if line.startswith(self.prefix):
                    self.ready_line = line
                    self.ready.set()
        finally:
            self.finished.set()

    def wait_ready(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.ready.wait(0.05):
                return fields(self.ready_line)
            if self.finished.is_set():
                break
        raise RuntimeError(f"{self.prefix} was not received; see the saved process log")

    def wait(self, timeout=10):
        result = self.process.wait(timeout=timeout)
        self.reader.join(timeout=5)
        if self.reader.is_alive():
            raise RuntimeError("process output did not close")
        return result

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        for pipe in (self.process.stdin, self.process.stdout):
            try:
                pipe.close()
            except OSError:
                pass


def evaluate(scenario, ready, workers, summary, observed, counters):
    errors = []
    pid = int(ready["pid"])
    count = int(ready["threads"])
    base = int(ready["mutex_addr"], 0)
    size = int(ready["mutex_size"])
    mutex_count = int(ready["mutex_count"])
    worker_by_tid = {int(worker["tid"]): worker for worker in workers}
    expected_mutex_count = 1 if scenario == "contention" else count
    if (count < 2 or size <= 0 or mutex_count != expected_mutex_count or
            ready["scenario"] != scenario):
        errors.append("invalid scenario or mutex layout")
    if len(workers) != count or len(worker_by_tid) != count:
        errors.append("worker thread records were missing or duplicated")
    if (summary.get("passed") != "1" or int(summary.get("counter", -1)) != count or
            int(summary.get("acquisitions", -1)) != count):
        errors.append("pthread mutex acquisitions or protected counter were incorrect")

    for worker in workers:
        address = int(worker["mutex_addr"], 0)
        if (int(worker["pid"]) != pid or int(worker["lock_ret"]) != 0 or
                int(worker["unlock_ret"]) != 0 or
                not base <= address < base + size * mutex_count or
                int(worker["mutex_size"]) != size):
            errors.append("invalid worker identity, mutex address or return value")
        if scenario == "contention" and address != base:
            errors.append("workers did not contend for the same mutex")
    if scenario == "uncontended" and len({worker["mutex_addr"] for worker in workers}) != count:
        errors.append("control workers did not use independent mutexes")

    matched = []
    long_waiters = set()
    minimum = int(ready["hold_ms"]) * 500_000
    for event in observed:
        if int(event["pid"]) != pid:
            errors.append("PID filtering failed")
        address = int(event["lock_addr"], 0)
        worker = worker_by_tid.get(int(event["tid"]))
        if worker is None:
            continue
        worker_base = int(worker["mutex_addr"], 0)
        if not worker_base <= address < worker_base + size:
            continue
        matched.append(event)
        duration = int(event["duration_ns"])
        timestamp = int(event["timestamp_ns"])
        if (duration < 0 or timestamp - duration < int(worker["wait_start_ns"]) or
                timestamp > int(worker["acquired_ns"])):
            errors.append("BPF wait was outside the pthread_mutex_lock interval")
        command = int(event["futex_op"]) & ~(128 | 256)
        if command not in (0, 9):
            errors.append("non-wait futex operation was emitted")
        if int(event["ret"]) == 0 and duration >= minimum:
            long_waiters.add(int(event["tid"]))

    addresses = sorted({event["lock_addr"] for event in matched})
    if scenario == "contention":
        if long_waiters != set(worker_by_tid) or not matched:
            errors.append("not every worker had a successful BPF wait of at least half the hold time")
        if len(addresses) != 1:
            errors.append("contention events did not identify one shared futex word")
    elif matched:
        errors.append("uncontended mutexes unexpectedly produced futex wait events")

    for key in ("start_update_fail", "start_miss", "delete_fail", "ringbuf_drop",
                "bad_timestamp", "rejected"):
        if counters.get(key) != 0:
            errors.append(f"{key} was nonzero or missing")
    if (counters.get("wait_exit") != counters.get("received") or
            counters.get("received") != len(observed)):
        errors.append("completed waits, received events and output records did not match")
    return {
        "passed": not errors,
        "scenario": scenario,
        "pid": pid,
        "threads": count,
        "worker_tids": sorted(worker_by_tid),
        "hold_ms": int(ready["hold_ms"]),
        "minimum_wait_ns": minimum,
        "mutex_addr": ready["mutex_addr"],
        "mutex_size": size,
        "mutex_count": mutex_count,
        "matched_events": len(matched),
        "long_waiters": len(long_waiters),
        "futex_addresses": addresses,
        "max_duration_ns": max((int(event["duration_ns"]) for event in matched), default=0),
        "counters": counters,
        "errors": sorted(set(errors)),
    }


def run_case(options, scenario):
    workload = None
    probe = None
    report = {"passed": False, "scenario": scenario, "errors": []}
    try:
        workload = CapturedProcess(
            [str(options.build_dir / "kylinrca_lock_test"), "--scenario", scenario,
             "--threads", str(options.threads), "--hold-ms", str(options.hold_ms)],
            "[MUTEX WORKLOAD] ready",
        )
        ready = workload.wait_ready()
        if int(ready["pid"]) != workload.process.pid:
            raise RuntimeError("workload PID did not match the observer PID namespace")
        probe = CapturedProcess(
            [str(options.build_dir / "kylinrca_lock_probe_smoke"), "--pid", str(workload.process.pid),
             "--duration", "20", "--object", str(options.build_dir / "lock.bpf.o")],
            "[LOCK PROBE] ready",
        )
        probe.wait_ready()
        workload.process.stdin.write("start\n")
        workload.process.stdin.flush()
        workload.process.stdin.close()
        workload_code = workload.wait()
        probe.process.send_signal(signal.SIGINT)
        probe_code = probe.wait()
        workers = [fields(line) for line in workload.lines if line.startswith("[MUTEX WORKER]")]
        summaries = [fields(line) for line in workload.lines if line.startswith("[MUTEX RESULT]")]
        observed = [fields(line) for line in probe.lines if line.startswith("[LOCK]")]
        counters = {}
        for line in probe.lines:
            if line.startswith("[LOCK PROBE]") and "ready" not in line:
                counters.update({key: int(value) for key, value in fields(line).items()})
        report = evaluate(scenario, ready, workers, summaries[-1] if summaries else {}, observed, counters)
        if workload_code != 0 or probe_code != 0:
            report["errors"].append("workload or probe returned a nonzero exit code")
            report["passed"] = False
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        report["passed"] = False
        report["errors"].append(str(error))
    finally:
        for name, process in (("probe", probe), ("workload", workload)):
            if process is not None:
                process.stop()
                path = options.output_dir / f"{scenario}-{name}.log"
                path.write_text("".join(process.lines))
                report[f"{name}_log"] = str(path)
        report["kernel"] = platform.release()
        report["architecture"] = platform.machine()
        (options.output_dir / f"{scenario}.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=("contention", "uncontended", "both"), default="both")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--hold-ms", type=int, default=100)
    parser.add_argument("--build-dir", type=Path, default=root / "build")
    parser.add_argument("--output-dir", type=Path, default=Path("/tmp/kylinrca-mutex-validation"))
    options = parser.parse_args()
    if not 2 <= options.threads <= 64 or not 20 <= options.hold_ms <= 1000:
        parser.error("threads must be 2..64 and hold-ms must be 20..1000")
    options.build_dir = options.build_dir.resolve()
    options.output_dir = options.output_dir.resolve()
    options.output_dir.mkdir(parents=True, exist_ok=True)
    scenarios = ("contention", "uncontended") if options.scenario == "both" else (options.scenario,)
    reports = [run_case(options, scenario) for scenario in scenarios]
    result = {"passed": all(report["passed"] for report in reports), "scenarios": reports}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
