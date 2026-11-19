#!/usr/bin/env python3
"""Run fio only on a newly created temporary loop device; verify windowed RCA."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

def run(args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()

def main():
    if os.geteuid() != 0:
        raise SystemExit("requires root for BPF and temporary loop device")
    if not shutil.which("fio"):
        raise SystemExit("install fio first")
    output=Path("build/io-analyzer-validation")
    output.mkdir(parents=True, exist_ok=True)
    monitor=str(Path("build/kylinrca_io_rca_smoke").resolve())
    with tempfile.TemporaryDirectory(prefix="kylinrca-io-analyzer-") as tmp:
        image=Path(tmp)/"disk.img"
        with image.open("wb") as f: f.truncate(128*1024*1024)
        loop=run(["losetup","--find","--show",str(image)])
        if not re.fullmatch(r"/dev/loop[0-9]+",loop):
            raise RuntimeError("unexpected loop path")
        p=None
        try:
            if shutil.which("udevadm"): run(["udevadm","settle","--timeout=10"])
            info=os.stat(loop)
            device=f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
            with (output/"reports.jsonl").open("w") as reports, (output/"probe.log").open("w") as log:
                # 100us is an explicit sensitivity setting for this virtual loop test.
                p=subprocess.Popen([monitor,"--seconds","12","--device",device,
                    "--threshold-us","100","--min-samples","10"],stdout=reports,stderr=log)
                for _ in range(100):
                    if "READY" in (output/"probe.log").read_text(): break
                    if p.poll() is not None: raise RuntimeError("monitor failed to start")
                    time.sleep(.05)
                else: raise RuntimeError("monitor readiness timeout")
                time.sleep(2)
                fio=subprocess.run(["fio","--name=rca","--filename="+loop,
                    "--rw=randwrite","--bs=128k","--size=128m","--direct=1",
                    "--ioengine=libaio","--iodepth=64","--runtime=4","--time_based",
                    "--output-format=json"],check=True,text=True,capture_output=True,timeout=30)
                (output/"fio.json").write_text(fio.stdout)
                if p.wait(timeout=20): raise RuntimeError("monitor failed")
            rows=[json.loads(x) for x in (output/"reports.jsonl").read_text().splitlines()]
            alerts=[d for r in rows for d in r['devices'] if d['diagnosis']=='IO_LATENCY']
            assert alerts, "fio must trigger IO_LATENCY"
            assert all(d['device']==device and d['sample_count']>=10 and d['bytes']>0
                       and d['avg_duration_ns']>0 and d['p99_duration_ns']>=d['p95_duration_ns']>=100000 for d in alerts)
            assert len(rows)>=8 and all(not r['devices'] for r in rows[-3:]), "idle windows retain old alerts"
            assert all(r['invalid_events']==0 and r['capacity_drops']==0 for r in rows)
            health=(output/'probe.log').read_text()
            assert 'STAT ringbuf_drop=0' in health and 'STAT map_update_fail=0' in health
            summary={'device':device,'windows':len(rows),'alert_device_windows':len(alerts),
                     'threshold_ns':100000,'idle_tail_windows':3,'passed':True}
            (output/"results.json").write_text(json.dumps(summary,indent=2))
            print(json.dumps(summary))
        finally:
            if p is not None and p.poll() is None:
                p.terminate()
                try: p.wait(timeout=5)
                except subprocess.TimeoutExpired: p.kill(); p.wait()
            run(["losetup","--detach",loop])

if __name__=='__main__': main()
