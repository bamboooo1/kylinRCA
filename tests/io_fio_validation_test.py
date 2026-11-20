#!/usr/bin/env python3
"""用构造的数据验证验收规则，不需要 root、fio 或真实块设备。"""
import copy
import importlib.util
from pathlib import Path
import unittest
import sys

# 导入被测脚本时不生成 __pycache__，保持工作目录整洁。
sys.dont_write_bytecode = True

# 直接按路径导入验收脚本，调用其中的 validate 函数。
spec = importlib.util.spec_from_file_location("io_check", Path(__file__).resolve().parents[1] / "scripts/check_io_analyzer.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ValidationTest(unittest.TestCase):
    def setUp(self):
        """每个测试开始前，重建一组能够通过验收的基准数据。"""
        # 十个窗口中仅第四个存在负载，其余为空闲；末尾满足恢复要求。
        # deepcopy 让各窗口的数据独立，修改一个窗口不会影响其他窗口。
        empty = {"devices": [], "invalid_events": 0, "capacity_drops": 0, "late_events": 0}
        self.rows = [copy.deepcopy(empty) for _ in range(10)]
        self.rows[3]["devices"] = [{"device": "7:0", "sample_count": 20, "bytes": 40960,
                                    "avg_duration_ns": 150000, "p95_duration_ns": 200000,
                                    "p99_duration_ns": 300000, "diagnosis": "IO_LATENCY"}]
        self.health = "".join(f"STAT {key}=0\n" for key in check.ZERO_STATS)
        self.health += "STAT emitted=20\nSUMMARY received=20 invalid=0 reads=0 writes=20 bytes=40960 pending=0\n"
        self.fio = {"jobs": [{"error": 0, "write": {"io_bytes": 40960}}]}

    def validate(self):
        """统一使用设备 7:0、100 微秒阈值和 10 个样本的门槛。"""
        return check.validate(self.rows, self.health, self.fio, "7:0", 100, 10)

    def test_valid(self):
        """完整且一致的基准数据应通过。"""
        self.assertTrue(self.validate()["passed"])

    def test_probe_failure_or_missing_counter(self):
        """探针出现丢失，或缺少必须的健康计数时，应拒绝通过。"""
        for replacement in ("STAT ringbuf_drop=1", "omitted"):
            with self.subTest(replacement=replacement):
                self.health = self.health.replace("STAT ringbuf_drop=0", replacement)
                with self.assertRaises(ValueError):
                    self.validate()
                self.setUp()  # 恢复基准数据，避免影响下一个子场景。

    def test_missing_summary(self):
        """缺少用户态接收汇总时，无法核对数据完整性。"""
        self.health = self.health.split("SUMMARY")[0]
        with self.assertRaises(ValueError):
            self.validate()

    def test_wrong_device_or_threshold(self):
        """逐项破坏设备归属、延迟门槛、样本门槛或诊断结果。"""
        for key, value in (("device", "8:0"), ("p95_duration_ns", 99999),
                           ("sample_count", 9), ("diagnosis", "NORMAL")):
            with self.subTest(key=key):
                self.rows[3]["devices"][0][key] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.setUp()  # 恢复基准数据，避免影响下一个子场景。

    def test_idle_alert(self):
        """负载结束后仍有设备记录，说明尚未满足空闲恢复要求。"""
        self.rows[-1] = copy.deepcopy(self.rows[3])
        with self.assertRaises(ValueError):
            self.validate()

    def test_analyzer_loss(self):
        """Analyzer 拒绝非法事件或因容量不足丢弃事件时，应失败。"""
        for key in ("invalid_events", "capacity_drops"):
            with self.subTest(key=key):
                self.rows[0][key] = 1
                with self.assertRaises(ValueError):
                    self.validate()
                self.setUp()  # 恢复基准数据，避免影响下一个子场景。

    def test_explicit_late_accounting(self):
        """迟到事件必须能与探针和接收计数对应，不能重复或漏计。"""
        self.rows[4]["late_events"] = 1
        with self.assertRaises(ValueError):
            self.validate()
        # 补齐第 21 条接收事件和对应 bytes 后，一条显式迟到才应被接受。
        self.health = self.health.replace("emitted=20", "emitted=21").replace("received=20", "received=21")
        self.health = self.health.replace("bytes=40960", "bytes=45056")
        self.assertEqual(self.validate()["late_events"], 1)

    def test_consumer_loss_or_pending(self):
        """两侧计数不符、仍有未完成请求或 bytes 不符时，应失败。"""
        for original, replacement in (("emitted=20", "emitted=21"),
                                       ("pending=0", "pending=1"),
                                       ("invalid=0", "invalid=1"),
                                       ("bytes=40960", "bytes=40961")):
            with self.subTest(replacement=replacement):
                self.health = self.health.replace(original, replacement)
                with self.assertRaises(ValueError):
                    self.validate()
                self.setUp()  # 恢复基准数据，避免影响下一个子场景。

    def test_fio_error_or_no_write(self):
        """fio 失败、未写入数据或没有任务结果时，应失败。"""
        for jobs in ([{"error": 1, "write": {"io_bytes": 40960}}],
                     [{"error": 0, "write": {"io_bytes": 0}}], []):
            with self.subTest(jobs=jobs):
                self.fio["jobs"] = jobs
                with self.assertRaises(ValueError):
                    self.validate()


if __name__ == "__main__":
    unittest.main()
