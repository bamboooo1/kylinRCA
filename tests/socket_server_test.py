"""Exercise the real Unix socket with snapshots built from the existing analyzers."""

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


class SocketServerTest(unittest.TestCase):
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
                         {"syscall": 14, "cpu": 0, "lock": 4})
        self.assertEqual(status_response["data"]["modules"],
                         {"syscall": True, "cpu": True, "lock": True, "io": False})

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
        self.assertEqual(report_data["lock"]["diagnosis"]["type"], "LOCK_CONTENTION")

        self.publish("idle")
        idle_top = self.query("top")["data"]
        for module in ("syscall", "cpu", "lock"):
            self.assertEqual(idle_top[module]["items"], [])
            self.assertEqual(idle_top[module]["window_end_ns"], 4_000_000_000)
        self.publish("disabled")
        self.assertIsNone(self.query("report")["data"]["syscall"])
        self.assertIsNone(self.query("top")["data"]["lock"])
        self.publish("missing_cpu_sample")
        self.assertEqual(self.query("status")["data"]["completed_windows"], 1)
        self.assertIsNone(self.query("top")["data"]["cpu"])
        self.assertIsNone(self.query("report")["data"]["cpu"])

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
        self.publish("large")
        with self.connect_client() as connection:
            connection.sendall(b"report\n")
            response = self.receive_response(connection)
            self.assertEqual(len(response["data"]["payload"]), 8 * 1024 * 1024)

        with self.connect_client() as slow_reader:
            slow_reader.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            slow_reader.sendall(b"report\n")
            self.assertTrue(slow_reader.recv(1))  # Server has captured the large snapshot.
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


if __name__ == "__main__":
    unittest.main()
