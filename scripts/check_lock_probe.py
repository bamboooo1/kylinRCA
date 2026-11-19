# 自动核对采集结果。
# 先启动测试程序等待，再启动探针，确认就绪后放行测试，避免漏掉最早的事件。
# 比较预期和采集记录中的身份、地址、操作、返回值、耗时及错误计数，输出 JSON。
import collections
import json
from pathlib import Path
import select
import signal
import subprocess
import time


# 最多等待 10 秒，读取子进程输出中以指定文字开头的就绪消息。
def read_ready(process, prefix):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        # 每次最多等待 0.1 秒，同时留出检查进程是否退出的机会。
        readable, _, _ = select.select([process.stdout], [], [], 0.1)
        if readable:
            line = process.stdout.readline()
            if line.startswith(prefix):
                return line
            # 空字符串表示输出管道已经关闭。
            if not line:
                break
        if process.poll() is not None:
            break
    # 超时或提前退出都视为启动失败。
    raise RuntimeError(f"{prefix} was not received; check BPF load/attach and privileges")


# 将一行输出中的 key=value 拆成字典，字段值暂时保留为字符串。
def fields(line):
    return dict(token.split("=", 1) for token in line.split() if "=" in token)


# 提取五个用于匹配的字段；int(..., 0) 同时支持十进制编号和十六进制地址。
def identity(record):
    return tuple(int(record[key], 0) for key in ("pid", "tid", "lock_addr", "futex_op", "ret"))


# 依次完成启动、放行、收集、核对和清理。
def main():
    # 根据脚本位置定位项目，使用 build 目录中的测试程序和探针。
    root = Path(__file__).resolve().parents[1]
    workload = None
    probe = None
    try:
        # 启动一轮测试，通过管道控制何时开始，并读取其预期记录。
        workload = subprocess.Popen(
            [str(root / "build/kylinrca_lock_wait_workload"), "--iterations", "1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        ready = read_ready(workload, "[WORKLOAD] ready")
        # 只观察测试进程；20 秒运行上限用于避免探针长期驻留。
        probe = subprocess.Popen(
            [str(root / "build/kylinrca_lock_probe_smoke"),
             "--pid", str(workload.pid), "--duration", "20"],
            stdout=subprocess.PIPE, text=True,
        )
        # 确认探针挂载就绪后，才向测试程序发送启动指令。
        read_ready(probe, "[LOCK PROBE] ready")
        expected_output, _ = workload.communicate("start\n", timeout=10)
        # 测试结束后通知探针正常退出，接收尾部事件和统计输出。
        probe.send_signal(signal.SIGINT)
        observed_output, _ = probe.communicate(timeout=10)

        # 分别解析测试程序的预期记录和探针实际收到的锁事件。
        expected = [fields(line) for line in expected_output.splitlines()
                    if line.startswith("[EXPECT]")]
        observed = [fields(line) for line in observed_output.splitlines()
                    if line.startswith("[LOCK]")]
        # 将探针汇总行中的计数字段转换为整数。
        counters = {}
        for line in observed_output.splitlines():
            if line.startswith("[LOCK PROBE]"):
                counters.update({key: int(value) for key, value in fields(line).items()})

        # Counter 同时比较记录内容和出现次数，避免重复或丢失事件被忽略。
        wanted = collections.Counter(identity(record) for record in expected)
        address = int(fields(ready)["lock_addr"], 0)
        # 仅匹配主线程在指定地址上的测试等待，排除线程退出同步等额外事件。
        matched = [record for record in observed
                   if int(record["lock_addr"], 0) == address
                   and int(record["tid"]) == workload.pid]
        actual = collections.Counter(identity(record) for record in matched)
        # 逐项收集失败原因，任一检查失败都会影响最终 passed 结果。
        errors = []
        if workload.returncode or probe.returncode:
            errors.append("workload or probe failed")
        # 一轮应产生六条预期记录，实际匹配内容和次数必须完全一致。
        if len(expected) != 6 or wanted != actual:
            errors.append("WAIT, WAIT_BITSET, PRIVATE or return-value records did not match")
        # 所有收到的事件都应属于指定测试进程。
        if any(int(record["pid"]) != workload.pid for record in observed):
            errors.append("PID filtering failed")
        # 检查最低耗时要求，以及结束时间戳不能小于本次经过时间。
        for record in expected:
            matching = [event for event in matched if identity(event) == identity(record)]
            if any(int(event["duration_ns"]) < int(record["min_duration_ns"])
                   or int(event["timestamp_ns"]) < int(event["duration_ns"])
                   for event in matching):
                errors.append("invalid wait duration or timestamp")
        # 关键错误计数必须存在且为 0。
        for key in ("start_update_fail", "delete_fail", "ringbuf_drop", "bad_timestamp", "rejected"):
            if counters.get(key) != 0:
                errors.append(f"{key} was nonzero or missing")
        # 完成的等待数应等于最终接收到的有效事件数。
        if counters.get("wait_exit") != counters.get("received"):
            errors.append("completed waits and received events did not match")

        # 输出机器可读的验收结果；失败时同时打印原始记录帮助排查。
        report = {
            "passed": not errors,
            "expected_events": len(expected),
            "matched_events": len(matched),
            "counters": counters,
            "errors": errors,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if errors:
            print(expected_output)
            print(observed_output)
        return 1 if errors else 0
    finally:
        # 无论正常结束还是发生异常，都回收仍在运行的子进程。
        for process in (probe, workload):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    # 正常终止超过 5 秒仍未结束时，强制结束并等待回收。
                    process.kill()
                    process.communicate()


# 直接运行脚本时进入 main，并将返回值作为退出码；预期异常打印简短原因。
if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
