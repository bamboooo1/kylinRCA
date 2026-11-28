"""统一 daemon 回归：复用真实分析循环，检查四模块快照、队列、配置、Socket 和客户端查询。"""

import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest


FIXTURE = sys.argv.pop(1)
DAEMON = sys.argv.pop(1)
CLIENT = sys.argv.pop(1)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_daemon import QueryRecorder, check_protocol


def run_client(*args):
    """运行一次客户端并返回标准输出、标准错误和退出码。挂起时由测试超时报告失败。"""
    return subprocess.run([CLIENT, *args], text=True, capture_output=True, timeout=5)


class DaemonQueryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="kylinrca-socket-")
        self.addCleanup(self.directory.cleanup)
        self.socket_path = str(Path(self.directory.name) / "nested" / "daemon.sock")
        self.server_process = subprocess.Popen(
            [FIXTURE, self.socket_path], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(self.stop_server)
        self.assertEqual(self.server_process.stdout.readline(), "ready\n")

    def stop_server(self):
        if self.server_process.poll() is None:
            self.server_process.stdin.write("stop\n")
            self.server_process.stdin.flush()
        try:
            self.server_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.server_process.kill()
            self.server_process.wait()
            self.fail("Server did not stop while a client was idle")
        for stream in (self.server_process.stdin, self.server_process.stdout,
                       self.server_process.stderr):
            stream.close()

    def connect_client(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(3)
        connection.connect(self.socket_path)
        return connection

    def receive_response(self, connection):
        chunks = []
        while chunk := connection.recv(65536):
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        raw_response = b"".join(chunks)
        self.assertTrue(raw_response.endswith(b"\n"))
        self.assertEqual(raw_response.count(b"\n"), 1)
        return json.loads(raw_response)

    def query(self, command):
        with self.connect_client() as connection:
            connection.sendall(command.encode() + b"\n")
            return self.receive_response(connection)

    def publish(self, phase):
        self.server_process.stdin.write(phase + "\n")
        self.server_process.stdin.flush()
        self.assertEqual(self.server_process.stdout.readline(), "published\n")

    def test_cli_matches_daemon_snapshot(self):
        """固定快照后分别直查 Socket 和运行客户端，逐字段核对三种输出。"""
        for phase in ("busy", "disabled"):
            self.publish(phase)
            for command in ("status", "top", "report"):
                with self.subTest(phase=phase, command=command):
                    expected = self.query(command)
                    result = run_client("--socket", self.socket_path, command)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(json.loads(result.stdout), expected)

    def test_real_analyzer_results_and_window_scope(self):
        initial_status = self.query("status")["data"]
        self.assertEqual(initial_status["completed_windows"], 0)
        self.assertEqual(initial_status["pid"], self.server_process.pid)
        self.assertIsNone(self.query("top")["data"]["cpu"])

        self.publish("busy")
        status_response = self.query("status")
        self.assertTrue(status_response["ok"])
        self.assertEqual(status_response["command"], "status")
        self.assertEqual(status_response["data"]["processed_events"],
                         {"syscall": 14, "cpu": 0, "lock": 4, "io": 2})
        self.assertEqual(status_response["data"]["modules"],
                         {"syscall": True, "cpu": True, "lock": True, "io": True})

        top_data = self.query("top")["data"]
        self.assertEqual(top_data["syscall"]["window_start_ns"], 2_000_000_000)
        self.assertEqual(top_data["syscall"]["window_end_ns"], 3_000_000_000)
        syscall_items = top_data["syscall"]["items"]
        self.assertEqual([entry["pid"] for entry in syscall_items], list(range(112, 102, -1)))
        self.assertEqual(syscall_items[0]["total_duration_ns"], 13_000_000)
        self.assertEqual(top_data["syscall"]["sort_by"], "total_duration_ns_desc")
        cpu_items = top_data["cpu"]["items"]
        self.assertEqual([entry["tid"] for entry in cpu_items], [201, 211, 202])
        self.assertTrue(cpu_items[0]["runtime_valid"])
        self.assertEqual(cpu_items[0]["runtime_ns"], 875_000_000)
        self.assertFalse(cpu_items[2]["runtime_valid"])
        self.assertEqual(top_data["lock"]["items"][0]["lock_addr"], "0xaaa")
        self.assertEqual(top_data["lock"]["items"][0]["total_wait_ns"], 120_000_000)

        report_data = self.query("report")["data"]
        reported_processes = report_data["syscall"]["summary"]["processes"]
        self.assertIn(9999, [entry["pid"] for entry in reported_processes])
        self.assertEqual(report_data["cpu"]["diagnosis"]["culprit_tid"], 201)
        self.assertEqual(report_data["cpu"]["thresholds"]["high_usage_threshold_percent"], 80.5)
        self.assertTrue(report_data["io"]["enabled"])
        self.assertEqual(report_data["io"]["received"], 2)
        self.assertEqual(report_data["io"]["bytes"], 8192)
        self.assertEqual(report_data["io"]["probe"]["pending"], 2)
        self.assertEqual([entry["device"] for entry in top_data["io"]["items"]], ["7:1", "7:0"])
        self.assertEqual([entry["p95_duration_ns"] for entry in top_data["io"]["items"]], [30, 10])
        self.assertEqual(report_data["lock"]["diagnosis"]["type"], "LOCK_CONTENTION")

        self.publish("idle")
        idle_top = self.query("top")["data"]
        for module in ("syscall", "cpu", "lock", "io"):
            self.assertEqual(idle_top[module]["items"], [])
            self.assertEqual(idle_top[module]["window_end_ns"], 4_000_000_000)
        self.publish("disabled")
        self.assertIsNone(self.query("report")["data"]["syscall"])
        self.assertIsNone(self.query("top")["data"]["lock"])
        self.assertIsNone(self.query("report")["data"]["io"])
        self.assertFalse(self.query("status")["data"]["modules"]["io"])
        self.publish("missing_cpu_sample")
        self.assertEqual(self.query("status")["data"]["completed_windows"], 1)
        self.assertIsNone(self.query("top")["data"]["cpu"])
        self.assertIsNone(self.query("report")["data"]["cpu"])

    def test_tick_closes_lock_and_io_windows_without_mixing_events(self):
        for phase, window, ticks in (("tick_first_window", 0, 1),
                                     ("tick_second_window", 1, 2),
                                     ("tick_catch_up", 1, 1)):
            with self.subTest(phase=phase):
                self.publish(phase)
                status = self.query("status")["data"]
                self.assertEqual(status["completed_windows"], ticks)
                top = self.query("top")["data"]
                end_ns = (window + 2) * 1_000_000_000
                self.assertEqual(top["lock"]["window_end_ns"], end_ns)
                self.assertEqual(top["io"]["window_end_ns"], end_ns)
                self.assertEqual([item["lock_addr"] for item in top["lock"]["items"]],
                                 [hex(0xaaa + window)])
                self.assertEqual([item["dev_minor"] for item in top["io"]["items"]], [window])

    def test_io_top_limit_and_device_ties(self):
        self.publish("io_rank")
        io_top = self.query("top")["data"]["io"]
        self.assertEqual([item["dev_minor"] for item in io_top["items"]], [2, 5, 8, 11, 1, 4, 7, 10, 0, 3])
        self.assertEqual([item["p95_duration_ns"] for item in io_top["items"]], [30] * 4 + [20] * 4 + [10] * 2)
        self.assertEqual(self.query("report")["data"]["io"]["received"], 13)

    def test_final_tick_flushes_lock_when_io_is_disabled(self):
        self.publish("lock_tail")
        self.assertFalse(self.query("status")["data"]["modules"]["io"])
        self.assertIsNone(self.query("report")["data"]["io"])
        lock_report = self.query("report")["data"]["lock"]
        self.assertEqual(lock_report["window_end_ns"], 1_300_000_000)
        self.assertEqual(lock_report["processes"][0]["locks"][0]["wait_count"], 1)

    def test_live_validation_query_recorder(self):
        self.publish("busy")
        output_path = Path(self.directory.name) / "queries.jsonl"
        with QueryRecorder(self.socket_path, output_path) as recorder:
            deadline = time.monotonic() + 3
            while len(recorder.replies) < 6 and time.monotonic() < deadline:
                time.sleep(0.02)
        self.assertGreaterEqual(len(recorder.replies), 6)
        self.assertEqual({frame["command"] for frame in recorder.replies}, {"status", "top", "report"})
        self.assertTrue(all(json.loads(line)["response"]["ok"] for line in output_path.read_text().splitlines()))
        check_protocol(self.socket_path)

    def test_io_alert_recovery_tail_and_health(self):
        self.assertIsNone(self.query("top")["data"]["io"])
        self.assertIsNone(self.query("report")["data"]["io"]["report"])
        self.publish("io_alert")
        io_state = self.query("report")["data"]["io"]
        self.assertEqual(io_state["received"], 3)
        self.assertEqual(io_state["report"]["diagnoses"][0]["diagnosis"], "IO_LATENCY")
        self.assertEqual(io_state["report"]["window_end_ns"], 4_000_000_000)
        self.publish("io_recovery")
        recovered = self.query("report")["data"]["io"]
        self.assertEqual(recovered["received"], 3)
        self.assertEqual(recovered["report"]["diagnoses"], [])
        self.assertEqual(self.query("top")["data"]["io"]["items"], [])
        self.publish("io_tail")
        tail = self.query("report")["data"]["io"]
        self.assertFalse(tail["report"]["window_complete"])
        self.assertEqual(tail["report"]["window_end_ns"], 1_300_000_000)
        self.assertEqual(tail["probe"]["pending"], 2)
        self.assertEqual(self.query("status")["data"]["completed_windows"], 0)

    def test_protocol_errors_fragmentation_and_disconnect(self):
        for command in ("", "unknown", "status extra", "status\r"):
            self.assertEqual(self.query(command), {"ok": False, "error": "unknown_command"})
        self.assertEqual(self.query("x" * 64), {"ok": False, "error": "request_too_long"})

        with self.connect_client() as connection:
            connection.sendall(b"sta")
            self.publish("busy")
            connection.sendall(b"tus\n")
            connection.shutdown(socket.SHUT_WR)
            self.assertEqual(self.receive_response(connection)["data"]["completed_windows"], 2)
        for partial_request in (b"", b"rep", b"report\n"):
            with self.connect_client() as connection:
                connection.sendall(partial_request)
        self.assertTrue(self.query("status")["ok"])

    def test_slow_clients_do_not_lock_snapshot_publication(self):
        """大快照可被客户端分段读完，慢客户端也不会阻止分析线程发布下一份快照。"""
        self.publish("large")
        with self.connect_client() as connection:
            connection.sendall(b"report\n")
            response = self.receive_response(connection)
            self.assertEqual(len(response["data"]["payload"]), 8 * 1024 * 1024)
        result = run_client("report", "--socket", self.socket_path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), response)

        with self.connect_client() as slow_reader:
            slow_reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            slow_reader.sendall(b"report\n")
            self.assertTrue(slow_reader.recv(1))  # 服务端已取得大快照，正在发送；此时发布新快照仍应立即完成。
            started = time.monotonic()
            self.publish("busy")
            self.publish("idle")
            self.assertLess(time.monotonic() - started, 0.8)
            self.assertEqual(self.query("status")["data"]["completed_windows"], 3)

        with self.connect_client() as idle_client:
            idle_client.sendall(b"sta")
            self.publish("busy")
            self.assertTrue(self.query("status")["ok"])

    def test_path_permissions_collision_and_cleanup(self):
        socket_mode = os.stat(self.socket_path).st_mode
        self.assertTrue(stat.S_ISSOCK(socket_mode))
        self.assertEqual(stat.S_IMODE(socket_mode), 0o600)
        collision = subprocess.run([FIXTURE, self.socket_path], capture_output=True, timeout=3)
        self.assertNotEqual(collision.returncode, 0)
        self.assertTrue(self.query("status")["ok"])

        occupied_path = Path(self.directory.name) / "ordinary-file"
        occupied_path.write_text("keep this file")
        collision = subprocess.run([FIXTURE, str(occupied_path)], capture_output=True, timeout=3)
        self.assertNotEqual(collision.returncode, 0)
        self.assertEqual(occupied_path.read_text(), "keep this file")

        with self.connect_client():
            self.server_process.stdin.write("stop\n")
            self.server_process.stdin.flush()
            self.server_process.wait(timeout=3)
        self.assertEqual(self.server_process.returncode, 0)
        self.assertFalse(Path(self.socket_path).exists())


class ClientErrorTest(unittest.TestCase):
    def test_help_and_invalid_arguments(self):
        """帮助无需建立连接，缺少命令或参数不合法时先报告用法错误。"""
        result = run_client("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertIn("用法：", result.stdout)
        for field in ("kylinrca_client", "status", "top", "report", "--socket", "/run/kylinrca/kylinrca.sock"):
            self.assertIn(field, result.stdout)
        for args in ((), ("unknown",), ("status", "--socket"), ("status", "report")):
            with self.subTest(args=args):
                result = run_client(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("用法：", result.stderr)

    def test_missing_or_unavailable_socket(self):
        """路径不存在或 Socket 没有监听者时，客户端应提示路径和 daemon 状态。"""
        with tempfile.TemporaryDirectory(prefix="kylinrca-client-") as directory:
            path = str(Path(directory) / "daemon.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as inactive_socket:
                missing = run_client("--socket", path, "status")
                inactive_socket.bind(path)
                unavailable = run_client("--socket", path, "status")
            for result in (missing, unavailable):
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn(path, result.stderr)
                self.assertIn("is kylinrcad running?", result.stderr)

    def test_daemon_error_and_incomplete_response(self):
        """用临时 Socket 返回指定字节，检查 daemon 错误、半截响应和错误命令回显。"""
        cases = (
            (b'{"ok":false,"error":"unknown_command"}\n', "unknown_command"),
            (b'{"ok":true,"command":"status","data":{}}', "before sending a complete response"),
            (b'{"ok":true,"command":"top","data":{}}\n', "Unexpected response format"),
        )
        with tempfile.TemporaryDirectory(prefix="kylinrca-client-") as directory:
            path = str(Path(directory) / "daemon.sock")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path)
                listener.listen()
                listener.settimeout(3)
                for response, message in cases:
                    with self.subTest(response=response), subprocess.Popen(
                        [CLIENT, "--socket", path, "status"], text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    ) as client:
                        connection, _ = listener.accept()
                        with connection, connection.makefile("rb") as request:
                            connection.settimeout(3)
                            self.assertEqual(request.readline(), b"status\n")
                            connection.sendall(response)
                        stdout, stderr = client.communicate(timeout=5)
                        self.assertEqual(client.returncode, 1)
                        self.assertEqual(stdout, "")
                        self.assertIn(message, stderr)


def run_config_option(binary, args, success):
    """执行一次参数检查，核对退出状态；失败用例必须在挂载探针前给出配置错误。"""
    result = subprocess.run([binary, *args], text=True, capture_output=True, timeout=5)
    if (result.returncode == 0) != success:
        raise AssertionError(f"unexpected exit: {args}: {result.stderr}")
    if not success and ("[config]" not in result.stderr or "BPF probe attached" in result.stderr):
        raise AssertionError(f"did not fail during config parsing: {args}: {result.stderr}")
    return result



class DaemonPipelineTest(unittest.TestCase):
    def test_queue_windows_final_flush_and_concurrent_snapshots(self):
        result = subprocess.run([FIXTURE, "--self-test"], text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_module_config_options(self):
        binary = DAEMON
        help_text = run_config_option(binary, ["--help"], True).stdout
        for option in ("--config", "--cpu-config", "--lock-config", "--io-config"):
            if option not in help_text:
                raise AssertionError("missing option in help: " + option)
        with tempfile.TemporaryDirectory(prefix="kylinrca-config-options-") as directory:
            root = Path(directory)
            empty = root / "empty.conf"
            empty.write_text("")
            for option in ("--cpu-config", "--lock-config", "--io-config"):
                run_config_option(binary, [option], False)
                run_config_option(binary, [option, str(root / "missing.conf")], False)
                run_config_option(binary, [option, str(empty), option, str(empty)], False)
                invalid = root / "invalid.conf"
                invalid.write_text("window_ms=1000\n")
                run_config_option(binary, [option, str(invalid)], False)
            cpu = root / "cpu.conf"
            cpu.write_text("high_usage_threshold_percent=80.5\nrecovery_threshold_percent=50.25\n")
            lock = root / "lock.conf"
            lock.write_text("recovery_windows=1\n")
            # 最后故意放入未知选项，确保前面全部合法配置被读取，再在挂载前退出。
            result = run_config_option(binary, ["--lock-config", str(lock), "--io-config", str(empty),
                                  "--cpu-config", str(cpu), "--config", str(empty), "--unknown", "x"], False)
            if "unknown or duplicate option: --unknown" not in result.stderr:
                raise AssertionError(result.stderr)
            for field in ("high_usage_threshold_percent", "minimum_wait_us"):
                invalid = root / "public.conf"
                invalid.write_text(field + "=1\n")
                run_config_option(binary, ["--config", str(invalid)], False)


if __name__ == "__main__":
    unittest.main()
