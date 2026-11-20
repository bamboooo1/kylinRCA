# W3 B 第三个任务：fio 场景与 I/O 测试

任务：[#26](https://github.com/bamboooo1/kylinRCA/issues/26)  
日期：2026-11-19（Asia/Shanghai）  
分支：`feat/io-fio-scenario`，基于包含 #25 的 `feat/io-analyzer`（`7d94b22`）。#25 的 PR #32 尚未合入，后续合并需保留该依赖。

## 复现

```bash
sudo apt install fio util-linux
cmake -S . -B build
cmake --build build -j8
ctest --test-dir build --output-on-failure
sudo python3 scripts/check_io_analyzer.py
```

`scenarios/io_latency.fio` 固定负载；脚本定位相对于自身路径的仓库，自动创建镜像、分配设备、启动监控、运行 fio、核对结果和清理。仅写本轮新建镜像对应的 loop，不接受外部磁盘参数。默认重复三轮，每轮约 12 秒另加少量启动/清理时间。

默认输出为 `build/io-fio-时间戳`；指定目录必须尚不存在，防止混入旧的成功证据：

```bash
sudo python3 scripts/check_io_analyzer.py --repeat 3 --output build/my-io-validation
sudo python3 scripts/check_io_analyzer.py --repeat 1 --threshold-us 100 --min-samples 10
```

| 项目 | 参数 |
| --- | --- |
| 测试文件 | `/tmp/kylinrca-fio-随机串/disk.img`，128 MiB 稀疏镜像 |
| 设备 | `losetup --find --show` 新分配的 loop，记录 major:minor |
| fio | libaio、direct=1、randwrite、128 KiB、iodepth=64、numjobs=1、运行 4 秒 |
| 采集 | 目标设备过滤、约 1 秒窗口、采集 12 秒；READY 后空闲约 2 秒再启动 fio |
| 诊断门槛 | P95 >= 100 µs 且窗口样本数 >= 10 |
| 对照 | 首个窗口为空，负载后末尾连续 3 个窗口为空 |

100 µs 是虚拟 loop 验收的显式灵敏度设置，产品默认阈值仍为 10 ms。该场景验证真实块层事件和诊断链路，不代表物理磁盘故障；宿主缓存可能影响结果，不能用 loop 测量物理磁盘性能，也不保证默认 10 ms 在任意设备触发。

## 判定及证据

每轮检查目标设备真实事件、正样本数/bytes/延迟、有效 P95/P99，以及满足配置门槛的 IO_LATENCY。fio 所有 job 必须成功并写入数据。以下条件也必须成立：

- RingBuffer 丢失、Map 更新/删除失败、时间错误、读取错误均为 0，缺失计数也失败。
- Probe emitted 等于 Consumer received；invalid=0、pending=0。
- Analyzer 非法事件和容量丢弃为 0。
- 已聚合样本数 + 显式 late_events = received。迟到事件沿用 #25 的拒绝语义，单独记录。无迟到时精确核对 bytes；有迟到时聚合 bytes 为正且不超过接收 bytes。
- 空闲基线和末尾三窗口无残留设备或告警。

unmatched 保留原计数语义，含挂载前完成及过滤范围外事件，不直接视为丢失。requeue、partial、释放清理分支是否触发以实测计数为准，不声称本任务覆盖了所有分支。

输出包含 `environment.json`（系统、内核、架构、fio/util-linux 版本、Git 基线及工作区状态）和 `results.json`（总结果）。每轮 `run-NN` 包含：

- `metadata.json`：镜像、设备、完整命令 argv、fio 配置快照、阈值、结果及清理状态，失败也记录错误。
- `reports.jsonl`、`probe.log`：窗口报告、Probe 计数及 Consumer 汇总。
- `fio.json`、`fio.stderr`：负载输出。
- `results.json`：该轮通过且清理成功后生成的完整结果。

失败/中断返回非零，总结果 passed=false。判定回归测试含 9 个测试方法及多个子场景，覆盖健康计数错误/缺失、错误设备、未触发、空闲残留、Analyzer 拒绝、Consumer 差异、迟到核对及 fio 失败，纳入 CTest。

## 清理

正常、异常、Ctrl+C、SIGTERM 均进入 finally：停止监控、detach 本轮 loop、确认镜像无设备关联，再删除本轮临时目录。若清理失败则保留 backing file，在 metadata 记录 cleanup_error，防止删除仍使用中的镜像。

SIGKILL 或断电无法运行 finally。恢复时从 metadata.json 读取 image 和 loop，先用 `sudo losetup --associated /tmp/kylinrca-fio-实际目录/disk.img` 核对归属，再 detach 对应设备；确认无关联后删除该镜像及专用临时目录。实际路径以 metadata 为准，只清理本次创建的资源。

## 本机验收

Ubuntu 26.04 LTS / WSL2、x86_64、内核 `6.18.33.2-microsoft-standard-WSL2`、fio 3.41、util-linux 2.41.3。

执行 `sudo python3 scripts/check_io_analyzer.py --repeat 3 --output build/io-fio-final`（本次通过 WSL root 身份运行，等价于 sudo）。连续三轮全部通过，每轮 12 个窗口、5 个诊断窗口，末尾连续 3 窗口为空。设备均为本轮新分配的 7:0，轮次间已 detach，编号可复用。

| 轮次 | received | 已聚合样本 | 显式迟到 | Consumer bytes | 诊断窗口 | 清理 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 84550 | 84549 | 1 | 11072462848 | 5 | 完成 |
| 2 | 86338 | 86335 | 3 | 11306819584 | 5 | 完成 |
| 3 | 79862 | 79862 | 0 | 10457997312 | 5 | 完成 |

三轮 RingBuffer/Map 更新/删除、时间及读取错误均为 0，Consumer invalid/pending 和 Analyzer invalid/capacity_drops 均为 0。Probe emitted 与 received 相同，迟到事件如实记录。

实测 SIGTERM：监控 READY 后发送信号，入口非零退出、总结果 passed=false，metadata.cleanup_complete=true，确认 loop 已 detach 且镜像已删除，记录在 `build/io-fio-interrupt/check.json`。开发首轮因将迟到误当作丢失而失败，其 finally 清理也完成，失败证据保留在 `build/io-fio-acceptance-3runs`。

构建、CTest 13/13 和 git diff --check 全部通过。最终原始产物：`build/io-fio-final/{environment.json,results.json,run-01/,run-02/,run-03/}`，build 被 Git 忽略。

满足 #26 的重复运行、真实 block I/O、稳定触发及环境/阈值/清理记录要求。未验证物理 SSD、ARM64 或长期运行；没有修改其他 W3 任务或 GitHub 状态。
