import copy
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_mutex_probe import evaluate


def fixture(scenario="contention"):
    ready = {"pid": "100", "threads": "2", "scenario": scenario, "hold_ms": "100",
             "mutex_addr": "0x1000", "mutex_size": "40",
             "mutex_count": "1" if scenario == "contention" else "2"}
    workers = []
    events = []
    for index, tid in enumerate((101, 102)):
        address = 0x1000 if scenario == "contention" else 0x1000 + index * 40
        workers.append({"pid": "100", "tid": str(tid), "mutex_addr": hex(address),
                        "mutex_size": "40", "lock_ret": "0", "unlock_ret": "0",
                        "wait_start_ns": "100000000", "acquired_ns": "300000000"})
        if scenario == "contention":
            events.append({"pid": "100", "tid": str(tid), "lock_addr": "0x1004",
                           "timestamp_ns": "200000000", "duration_ns": "100000000",
                           "futex_op": "128", "ret": "0"})
    summary = {"passed": "1", "acquisitions": "2", "counter": "2"}
    counters = {key: 0 for key in ("start_update_fail", "start_miss", "delete_fail",
                                   "ringbuf_drop", "bad_timestamp", "rejected")}
    counters.update(wait_exit=len(events), received=len(events))
    return [scenario, ready, workers, summary, events, counters]


class MutexProbeValidationTest(unittest.TestCase):
    def test_mutex_internal_offset_is_accepted(self):
        report = evaluate(*fixture())
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["futex_addresses"], ["0x1004"])
        self.assertEqual(report["long_waiters"], 2)

    def test_join_wait_does_not_count_as_mutex_contention(self):
        case = fixture()
        event = copy.copy(case[4][0])
        event.update(tid="100", lock_addr="0x9000", futex_op="265")
        case[4].append(event)
        case[5].update(wait_exit=3, received=3)
        report = evaluate(*case)
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["matched_events"], 2)

    def test_missing_waiter_fails_even_when_counters_match(self):
        case = fixture()
        case[4].pop()
        case[5].update(wait_exit=1, received=1)
        self.assertFalse(evaluate(*case)["passed"])

    def test_event_outside_lock_interval_fails(self):
        case = fixture()
        case[4][0]["timestamp_ns"] = "400000000"
        self.assertFalse(evaluate(*case)["passed"])

    def test_control_rejects_mutex_wait(self):
        case = fixture("uncontended")
        self.assertTrue(evaluate(*case)["passed"])
        case[4].append(fixture()[4][0])
        case[5].update(wait_exit=1, received=1)
        self.assertFalse(evaluate(*case)["passed"])

    def test_probe_errors_fail_validation(self):
        case = fixture()
        case[5]["ringbuf_drop"] = 1
        self.assertFalse(evaluate(*case)["passed"])


if __name__ == "__main__":
    unittest.main()
