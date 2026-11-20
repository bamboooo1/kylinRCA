"""检查验收脚本会拒绝错误结果，不需要 BPF 权限。"""
import copy
import io
import json
from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_lock_rca import evaluate_case, parse_probe, run_case, main


def stats(tids=(), duration=100_000_000):
    count = len(tids)
    return dict(event_count=count, wait_count=count, waiting_threads=count,
                total_wait_ns=count * duration, avg_wait_ns=duration if count else 0,
                max_wait_ns=duration if count else 0, short_wait_count=0,
                eagain_count=0, timeout_count=0, interrupted_count=0,
                other_error_count=0, waiting_tids=list(tids))


def fixture(scenario="contention", split=False):
    ready = dict(pid="100", threads="8", scenario=scenario, hold_ms="100",
                 mutex_addr="0x1000", mutex_size="40",
                 mutex_count="1" if scenario == "contention" else "8")
    workers, events = [], []
    for index, tid in enumerate(range(101, 109)):
        workers.append(dict(pid="100", tid=str(tid),
                            mutex_addr=hex(0x1000 if scenario == "contention" else 0x1000 + index * 40),
                            mutex_size="40", lock_ret="0", unlock_ret="0",
                            wait_start_ns="1300000000", acquired_ns="2300000000"))
        if scenario == "contention":
            events.append(dict(pid="100", tid=str(tid), lock_addr="0x1004", futex_op="128",
                               duration_ns="100000000", ret="0",
                               timestamp_ns="2100000000" if split and index >= 3 else "1500000000"))
    summary = dict(passed="1", acquisitions="8", counter="8")
    counters = dict(start_update_fail=0, start_miss=0, delete_fail=0,
                    ringbuf_drop=0, bad_timestamp=0, rejected=0,
                    wait_exit=len(events), received=len(events))
    thresholds = dict(window_ns=1_000_000_000, minimum_wait_ns=1_000_000,
                      average_wait_threshold_ns=10_000_000, max_wait_threshold_ns=50_000_000,
                      minimum_waiting_threads=2, recovery_windows=2)
    reports = []
    active = None
    for window in range(1, 5 if split else 4):
        tids = (list(range(101, 104)) if window == 1 else list(range(104, 109))) if split else list(range(101, 109))
        busy = scenario == "contention" and window <= (2 if split else 1)
        current = stats(tids) if busy else None
        if busy:
            active = dict(type="LOCK_CONTENTION", pid=100, lock_addr="0x1004",
                          evidence_window_start_ns=window * 1_000_000_000,
                          evidence_window_end_ns=(window + 1) * 1_000_000_000,
                          recovery_windows=0, **current)
        elif active and active["recovery_windows"] == 0:
            active = dict(active, recovery_windows=1)
        else:
            active = None
        diagnosis = copy.deepcopy(active) if active else dict(
            type="NORMAL", pid=0, lock_addr="0x0", evidence_window_start_ns=0,
            evidence_window_end_ns=0, recovery_windows=0, **stats())
        reports.append(dict(type="lock_summary", wait_metric="completed_futex_wait_ns",
                            window_start_ns=window * 1_000_000_000,
                            window_end_ns=(window + 1) * 1_000_000_000,
                            received_events=len(events), rejected_events=0, late_events=0,
                            thresholds=thresholds.copy(), diagnosis=diagnosis,
                            processes=[dict(pid=100, locks=[dict(lock_addr="0x1004", **current)])]
                            if current else []))
    return [scenario, ready, workers, summary, events, counters, reports]


def line(prefix, values):
    return prefix + " " + " ".join(f"{key}={value}" for key, value in values.items()) + "\n"


def processes(case, target_pid="100"):
    workload = Mock()
    workload.process.pid = 100
    workload.wait_ready.return_value = case[1]
    workload.wait.return_value = 0
    workload.lines = [line("[MUTEX WORKLOAD] ready", case[1])]
    workload.lines += [line("[MUTEX WORKER]", row) for row in case[2]]
    workload.lines.append(line("[MUTEX RESULT]", case[3]))
    probe = Mock()
    probe.wait_ready.return_value = dict(target_pid=target_pid)
    probe.wait.return_value = 0
    probe.finished.wait.return_value = False
    probe.lines = [f"[LOCK PROBE] ready target_pid={target_pid}\n"]
    probe.lines += [line("[LOCK]", row) for row in case[4]]
    probe.lines += [json.dumps(report) + "\n" for report in case[6]]
    probe.lines.append(line("[LOCK PROBE]", case[5]))
    return workload, probe


class LockRcaValidationTest(unittest.TestCase):
    def test_eight_waiters_and_internal_mutex_offset(self):
        result = evaluate_case(*fixture())
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["long_waiters"], 8)
        self.assertEqual(result["alert_windows"][0]["lock_addr"], "0x1004")
        self.assertTrue(result["recovery_observed"])

    def test_waiters_split_across_windows_are_accepted(self):
        result = evaluate_case(*fixture(split=True))
        self.assertTrue(result["passed"], result)
        self.assertEqual([row["waiting_threads"] for row in result["alert_windows"]], [3, 5])
        self.assertEqual(result["long_waiters"], 8)

    def test_empty_control_is_accepted(self):
        result = evaluate_case(*fixture("uncontended"))
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["alert_windows"], [])

    def test_join_wait_stays_out_of_mutex_diagnosis(self):
        case = fixture()
        case[4].append(dict(pid="100", tid="100", lock_addr="0x9000", futex_op="265",
                            timestamp_ns="1500000000", duration_ns="2000000", ret="0"))
        case[5].update(received=9, wait_exit=9)
        for report in case[6]:
            report["received_events"] = 9
        case[6][0]["processes"][0]["locks"].append(dict(lock_addr="0x9000", **stats([100], 2_000_000)))
        result = evaluate_case(*case)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["matched_events"], 8)

    def test_mismatched_metrics_or_thread_identity_fail(self):
        for change in (lambda d: d.update(avg_wait_ns=1),
                       lambda d: d.update(lock_addr="0x9000"),
                       lambda d: d.update(waiting_tids=list(range(201, 209)))):
            with self.subTest(change=change):
                case = fixture()
                change(case[6][0]["diagnosis"])
                self.assertFalse(evaluate_case(*case)["passed"])

    def test_window_statistics_must_match_raw_records(self):
        case = fixture()
        case[6][0]["processes"][0]["locks"][0]["total_wait_ns"] += 1
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_empty_capture_cannot_pass_contention(self):
        case = fixture("uncontended")
        case[0] = case[1]["scenario"] = "contention"
        case[1]["mutex_count"] = "1"
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_missing_waiter_fails(self):
        case = fixture()
        case[4].pop()
        case[5].update(received=7, wait_exit=7)
        for report in case[6]:
            report["received_events"] = 7
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_control_false_alarm_fails(self):
        case = fixture("uncontended")
        case[6][0]["diagnosis"].update(type="LOCK_CONTENTION", pid=100, lock_addr="0x1000")
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_stale_or_relabelled_recovery_evidence_fails(self):
        case = fixture()
        case[6][1]["diagnosis"]["evidence_window_end_ns"] = 3_000_000_000
        self.assertFalse(evaluate_case(*case)["passed"])
        case = fixture()
        case[6][-1]["diagnosis"] = copy.deepcopy(case[6][1]["diagnosis"])
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_no_recovery_report_fails(self):
        case = fixture()
        case[6] = case[6][:1]
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_partial_windows_cannot_prove_recovery(self):
        case = fixture()
        case[6][1]["window_end_ns"] = 2_500_000_000
        case[6][2]["window_start_ns"] = 2_500_000_000
        case[6][2]["window_end_ns"] = 3_500_000_000
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_gaps_and_changed_thresholds_fail(self):
        case = fixture()
        case[6].pop(1)
        with self.assertRaisesRegex(ValueError, "windows"):
            evaluate_case(*case)
        case = fixture()
        case[6][0]["thresholds"]["max_wait_threshold_ns"] = 1
        with self.assertRaisesRegex(ValueError, "thresholds"):
            evaluate_case(*case)

    def test_probe_and_analyzer_errors_fail(self):
        case = fixture()
        case[5]["ringbuf_drop"] = 1
        self.assertFalse(evaluate_case(*case)["passed"])
        case = fixture()
        case[6][-1]["late_events"] = 1
        self.assertFalse(evaluate_case(*case)["passed"])

    def test_bad_or_missing_json_fails(self):
        with self.assertRaises(ValueError):
            parse_probe(["{broken JSON\n"])
        case = fixture()
        case[6] = []
        with self.assertRaisesRegex(ValueError, "No lock_summary"):
            evaluate_case(*case)

    def test_runner_passes_actual_child_pid_and_saves_artifacts(self):
        case = fixture()
        workload, probe = processes(case)
        order = []
        probe.wait_ready.side_effect = lambda: (order.append("probe_ready") or dict(target_pid="100"))
        workload.process.stdin.write.side_effect = lambda _: order.append("release")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "case"
            options = SimpleNamespace(build_dir=Path(directory), threads=8, hold_ms=100)
            with patch("check_lock_rca.CapturedProcess", side_effect=[workload, probe]) as factory:
                result = run_case(options, "contention", output)
            self.assertTrue(result["passed"], result)
            self.assertEqual(order, ["probe_ready", "release"])
            command = factory.call_args_list[1].args[0]
            self.assertEqual(command[command.index("--pid") + 1], "100")
            self.assertIn("--analyze", command)
            probe.finished.wait.assert_called_once_with(4)
            probe.process.send_signal.assert_called_once_with(signal.SIGINT)
            self.assertTrue(json.loads((output / "result.json").read_text())["passed"])
            self.assertEqual(len((output / "reports.jsonl").read_text().splitlines()), 3)
            self.assertTrue((output / "workload.log").exists())
            self.assertTrue((output / "probe.log").exists())
            workload.stop.assert_called_once()
            probe.stop.assert_called_once()

    def test_wrong_target_pid_fails_before_releasing_workers(self):
        workload, probe = processes(fixture(), target_pid="999")
        with tempfile.TemporaryDirectory() as directory:
            options = SimpleNamespace(build_dir=Path(directory), threads=8, hold_ms=100)
            with patch("check_lock_rca.CapturedProcess", side_effect=[workload, probe]):
                result = run_case(options, "contention", Path(directory) / "case")
            self.assertFalse(result["passed"])
            self.assertIn("target PID", result["errors"][0])
            workload.process.stdin.write.assert_not_called()
            workload.stop.assert_called_once()
            probe.stop.assert_called_once()

    def test_probe_failure_is_not_hidden_by_valid_reports(self):
        workload, probe = processes(fixture())
        probe.wait.return_value = 1
        with tempfile.TemporaryDirectory() as directory:
            options = SimpleNamespace(build_dir=Path(directory), threads=8, hold_ms=100)
            with patch("check_lock_rca.CapturedProcess", side_effect=[workload, probe]):
                result = run_case(options, "contention", Path(directory) / "case")
            self.assertFalse(result["passed"])
            self.assertIn("nonzero", result["errors"][-1])

    def test_early_probe_exit_preserves_failure_logs(self):
        workload, probe = processes(fixture())
        probe.finished.wait.return_value = True
        with tempfile.TemporaryDirectory() as directory:
            options = SimpleNamespace(build_dir=Path(directory), threads=8, hold_ms=100)
            with patch("check_lock_rca.CapturedProcess", side_effect=[workload, probe]):
                output = Path(directory) / "case"
                result = run_case(options, "contention", output)
            self.assertFalse(result["passed"])
            self.assertIn("recovery observation", result["errors"][0])
            self.assertTrue((output / "probe.log").exists())

    def test_saved_manual_captures(self):
        path = Path(__file__).resolve().parents[1] / "docs" / "lock_rca_validation_results.json"
        record = json.loads(path.read_text())
        self.assertEqual(record["validation_kind"], "historical_capture_replay")
        self.assertFalse(record["fresh_bpf_capture"])
        for case in record["cases"]:
            with self.subTest(scenario=case["input"]["scenario"]):
                result = evaluate_case(**case["input"])
                self.assertTrue(result["passed"], result)
                self.assertEqual(result, case["result"])

    def test_main_preserves_previous_runs_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("kylinrca_lock_test", "kylinrca_lock_probe_smoke", "lock.bpf.o"):
                (root / name).touch()
            argv = ["check_lock_rca.py", "--rounds", "1", "--build-dir", directory,
                    "--output-dir", str(root / "results")]
            for _ in range(2):
                with patch.object(sys, "argv", argv), patch("check_lock_rca.run_case") as run:
                    run.return_value = dict(passed=False, errors=["test failure"])
                    with patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
                        self.assertEqual(main(), 1)
                    self.assertEqual(run.call_count, 2)
            self.assertEqual(len(list((root / "results").glob("run-*/results.json"))), 2)


if __name__ == "__main__":
    unittest.main()
