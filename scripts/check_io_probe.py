#!/usr/bin/env python3
"""W3 I/O Probe 特权集成验证。仅写入新建临时镜像关联的 loop 设备。"""
import argparse
import concurrent.futures
import json
import mmap
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import subprocess
import tempfile
import time


def command(args):
    p = subprocess.run(args, text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(f"command failed: {args}: {p.stderr}")
    return p


def parse(text):
    values = {}
    for line in text.splitlines():
        if line.startswith(("STAT ", "SUMMARY ")):
            for key, value in re.findall(r"(\w+)=(\d+)", line):
                values[key] = int(value)
    return values


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--probe", default="build/kylinrca_io_probe_smoke")
    ap.add_argument("--output", default="build/io-validation")
    args = ap.parse_args()
    if os.geteuid() != 0:
        ap.error("requires root for BPF and a temporary loop device")
    probe = str(Path(args.probe).resolve())
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []
    def io_program_ids():
        data = json.loads(command(["bpftool", "-j", "prog", "show"]).stdout)
        return sorted(p["id"] for p in data
                      if p.get("name", "").startswith("handle_io_"))
    programs_before = io_program_ids()
    kernel = os.uname().release

    with tempfile.TemporaryDirectory(prefix="kylinrca-io-") as tmp:
        image = Path(tmp) / "disk.img"
        with image.open("wb") as f:
            f.truncate(64 * 1024 * 1024)
        loop = command(["losetup", "--find", "--show", str(image)]).stdout.strip()
        # 所有 dd 目标必须是本次 losetup 返回的 loop；不接受外部设备参数。
        if not re.fullmatch(r"/dev/loop\d+", loop):
            raise RuntimeError("unexpected losetup response")
        try:
            info = os.stat(loop)
            if not stat.S_ISBLK(info.st_mode):
                raise RuntimeError("loop path is not a block device")
            device = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
            # 新建 loop 会触发 udev/分区探测；先等待这些真实后台读结束。
            if shutil.which("udevadm"):
                command(["udevadm", "settle", "--timeout=10"])
            time.sleep(1)

            def direct_io(write, count, offset=0):
                # 页对齐缓冲区满足 O_DIRECT；避免依赖本机 dd 的缓冲区实现。
                fd = os.open(loop, (os.O_WRONLY if write else os.O_RDONLY) | os.O_DIRECT)
                try:
                    os.lseek(fd, offset * 4096, os.SEEK_SET)
                    with mmap.mmap(-1, 4096) as buffer:
                        for _ in range(count):
                            n = os.write(fd, buffer) if write else os.readv(fd, [buffer])
                            if n != 4096:
                                raise RuntimeError(f"short direct I/O: {n}")
                finally:
                    os.close(fd)

            def exercise():
                direct_io(True, 128)
                direct_io(False, 128)

            def concurrent_workload():
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                    list(pool.map(lambda i: direct_io(True, 128, i * 128), range(4)))
                    list(pool.map(lambda i: direct_io(False, 128, i * 128), range(4)))

            def run_case(name, workload=None, selected=device, overflow=False):
                with tempfile.TemporaryFile(mode="w+") as log:
                    p = subprocess.Popen(
                        [probe, "--seconds", "30", "--device", selected,
                         "--max-print", "8"], stdout=log, stderr=log, text=True)
                    stopped = False
                    try:
                        for _ in range(100):
                            log.seek(0)
                            if "READY " in log.read():
                                break
                            if p.poll() is not None:
                                raise RuntimeError("probe exited before READY")
                            time.sleep(0.05)
                        else:
                            raise RuntimeError("probe readiness timeout")
                        if overflow:
                            p.send_signal(signal.SIGSTOP)
                            stopped = True
                            # 确认用户态已停；BPF 探针仍在内核执行。
                            for _ in range(100):
                                state = Path(f"/proc/{p.pid}/status").read_text()
                                if re.search(r"State:\s+T", state):
                                    break
                                time.sleep(0.01)
                            else:
                                raise RuntimeError("probe did not stop")
                        if workload:
                            workload()
                        else:
                            time.sleep(0.3)
                        if stopped:
                            p.send_signal(signal.SIGCONT)
                            stopped = False
                        time.sleep(0.3)
                        p.send_signal(signal.SIGINT)
                        p.wait(timeout=10)
                    finally:
                        if stopped:
                            p.send_signal(signal.SIGCONT)
                        if p.poll() is None:
                            p.send_signal(signal.SIGTERM)
                            try:
                                p.wait(timeout=5)
                            except subprocess.TimeoutExpired:
                                p.kill()
                                p.wait()
                        log.seek(0)
                        text = log.read()
                        (output / f"{name}.txt").write_text(text)
                if p.returncode:
                    raise RuntimeError(f"{name}: probe exit={p.returncode}\n{text}")
                values = parse(text)
                for key in ("invalid", "map_update_fail", "map_delete_fail",
                            "bad_timestamp", "read_fail", "pending"):
                    if values.get(key) != 0:
                        raise AssertionError(f"{name}: {key}={values.get(key)}")
                if values["received"] != values["emitted"]:
                    raise AssertionError(f"{name}: consumer/emitter mismatch")
                for line in text.splitlines():
                    if line.startswith("[IO]") and f"device={selected} " not in line:
                        raise AssertionError(f"{name}: wrong device: {line}")
                if name in ("idle", "filter_miss"):
                    assert values["received"] == 0, values
                else:
                    assert values["writes"] > 0, values
                    if not overflow:
                        assert values["reads"] >= 128, values
                        minimum = 4 * 1024 * 1024 if name == "concurrent" else 1024 * 1024
                        assert values["bytes"] >= minimum, values
                if overflow:
                    assert values["ringbuf_drop"] > 0, values
                else:
                    assert values["ringbuf_drop"] == 0, values
                results.append({"case": name, "passed": True, "stats": values})
                print(f"PASS {name}: " + json.dumps(values), flush=True)

            run_case("idle")
            run_case("direct_read_write", exercise)
            run_case("concurrent", concurrent_workload)
            run_case("filter_miss", exercise, selected="4294967295:0")
            run_case("ringbuf_overflow", lambda: direct_io(True, 8192), overflow=True)

            # 另启一个 Probe，验证 SIGTERM 和显式的错误路径。
            for name, options, expected in (
                ("invalid_seconds", ["--seconds", "0"], 2),
                ("invalid_device", ["--device", "bad"], 2),
                ("missing_object", ["--object", "/nonexistent/kylinrca-io.bpf.o"], 1),
            ):
                p = subprocess.run([probe] + options, capture_output=True, text=True)
                (output / f"{name}.txt").write_text(p.stdout + p.stderr)
                assert p.returncode == expected, (name, p.returncode)
                results.append({"case": name, "passed": True, "exit": p.returncode})
                print(f"PASS {name}", flush=True)
            p = subprocess.Popen([probe, "--seconds", "30", "--device", device,
                                  "--max-print", "0"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                first = p.stdout.readline()
                assert first.startswith("READY "), first
                p.send_signal(signal.SIGTERM)
                out, err = p.communicate(timeout=10)
                assert p.returncode == 0, (p.returncode, err)
                (output / "sigterm.txt").write_text(first + out + err)
                results.append({"case": "sigterm", "passed": True})
                print("PASS sigterm", flush=True)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.communicate()
        finally:
            command(["losetup", "--detach", loop])
        remaining = command(["losetup", "--associated", str(image)]).stdout
        if remaining.strip():
            raise AssertionError("temporary loop was not detached")

    # 进程退出后 BPF 程序经 RCU 延迟释放；给内核最多 3 秒。
    for _ in range(30):
        programs_after = io_program_ids()
        if programs_after == programs_before:
            break
        time.sleep(0.1)
    if programs_before != programs_after:
        raise AssertionError("I/O BPF programs remain after process exit")
    results.append({"case": "resource_cleanup", "passed": True})
    print("PASS resource_cleanup", flush=True)
    report = {"kernel": kernel,
              "io_program_ids_before": programs_before,
              "io_program_ids_after": programs_after, "device": device, "results": results,
              "temporary_loop_detached": True}
    (output / "results.json").write_text(json.dumps(report, indent=2))
    print(f"Results: {output / 'results.json'}", flush=True)


if __name__ == "__main__":
    main()
