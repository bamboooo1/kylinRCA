"""使用标准 JSON 解析器验证 C++ Reporter 的实际输出，无需 BPF 权限。"""
import json
import subprocess
import sys
import unittest


class LockJsonReporterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        completed = subprocess.run(
            [sys.argv[1], "--json"], check=True, capture_output=True, text=True,
        )
        cls.reports = [json.loads(line) for line in completed.stdout.splitlines()]

    def test_empty_report(self):
        report = self.reports[0]
        self.assertEqual(report["type"], "lock_summary")
        self.assertEqual(report["diagnosis"]["type"], "NORMAL")
        self.assertEqual(report["processes"], [])
        self.assertEqual(report["received_events"], 0)
        self.assertLess(report["window_start_ns"], report["window_end_ns"])

    def test_contention_evidence(self):
        report = self.reports[1]
        diagnosis = report["diagnosis"]
        self.assertEqual(diagnosis["type"], "LOCK_CONTENTION")
        self.assertEqual(diagnosis["pid"], 101)
        self.assertEqual(diagnosis["lock_addr"], "0xfedcba9876543210")
        self.assertEqual(diagnosis["waiting_threads"], 8)
        self.assertEqual(diagnosis["waiting_tids"], list(range(1001, 1009)))
        self.assertEqual(diagnosis["wait_count"], 8)
        self.assertEqual(diagnosis["avg_wait_ns"], 100_000_000)
        self.assertEqual(diagnosis["max_wait_ns"], 100_000_000)
        self.assertEqual(diagnosis["total_wait_ns"], 800_000_000)
        self.assertEqual(report["received_events"], 10)
        self.assertEqual(report["rejected_events"], 0)
        self.assertEqual(report["late_events"], 0)
        self.assertEqual(report["wait_metric"], "completed_futex_wait_ns")
        self.assertEqual(report["thresholds"]["minimum_waiting_threads"], 2)

    def test_process_and_address_isolation(self):
        processes = self.reports[1]["processes"]
        self.assertEqual([process["pid"] for process in processes], [101, 202])
        first, second = processes
        self.assertEqual([lock["lock_addr"] for lock in first["locks"]],
                         ["0x2000", "0xfedcba9876543210"])
        self.assertEqual(first["locks"][0]["eagain_count"], 1)
        self.assertEqual(first["locks"][0]["waiting_threads"], 0)
        self.assertEqual(second["locks"][0]["waiting_threads"], 1)

    def test_recovery_does_not_relabel_old_evidence(self):
        recovering, recovered = self.reports[2:]
        self.assertEqual(recovering["diagnosis"]["type"], "LOCK_CONTENTION")
        self.assertEqual(recovering["diagnosis"]["recovery_windows"], 1)
        self.assertEqual(recovering["diagnosis"]["evidence_window_end_ns"], 2_000_000_000)
        self.assertEqual(recovering["window_end_ns"], 3_000_000_000)
        self.assertEqual(recovering["processes"], [])
        self.assertEqual(recovered["diagnosis"]["type"], "NORMAL")
        self.assertEqual(recovered["diagnosis"]["pid"], 0)
        self.assertEqual(recovered["diagnosis"]["waiting_tids"], [])
        self.assertEqual(recovered["processes"], [])


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
