# W3 B 第三个任务：fio 场景与 I/O 测试

任务：[#26](https://github.com/bamboooo1/kylinRCA/issues/26)  
日期：2026-11-19（Asia/Shanghai）  
历史开发基线：`feat/io-fio-scenario`，基于包含 #25 的 `feat/io-analyzer`（`7d94b22`）。编写初始报告时 PR #32 尚未合入。
PR #32 和 #34 现已合入 `main`；2026-11-21 的四模块回归、最新结果与构建步骤见
[W3 四模块整合验收](w3_integration_validation.md)。下文保留 #26 开发期间的验收记录。

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
| 诊断门槛 | 连续 3 个完整窗口 P95 >= 100 µs 且窗口样本数 >= 10；连续 3 个非异常窗口恢复 |
| 对照 | 首个窗口为空，负载后末尾连续 3 个窗口为空 |

100 µs 是虚拟 loop 验收的显式灵敏度设置，产品默认阈值仍为 10 ms。该场景验证真实块层事件和诊断链路，不代表物理磁盘故障；宿主缓存可能影响结果，不能用 loop 测量物理磁盘性能，也不保证默认 10 ms 在任意设备触发。

## 判定及证据

每轮检查目标设备真实事件、正样本数/bytes/延迟、有效 P95/P99，并独立重放连续三次触发与三次恢复的状态序列。首次触发必须有三个连续异常窗口；恢复观察期间的持续告警不要求当前窗口仍达到 P95 门槛。fio 所有 job 必须成功并写入数据。以下条件也必须成立：

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

失败/中断返回非零，总结果 passed=false。判定回归测试含 10 个测试方法及多个子场景，覆盖健康计数错误/缺失、错误设备、未触发、空闲残留、Analyzer 拒绝、Consumer 差异、迟到核对及 fio 失败，纳入 CTest。

## 清理

正常、异常、Ctrl+C、SIGTERM 均进入 finally：停止监控、detach 本轮 loop、确认镜像无设备关联，再删除本轮临时目录。若清理失败则保留 backing file，在 metadata 记录 cleanup_error，防止删除仍使用中的镜像。

SIGKILL 或断电无法运行 finally。恢复时从 metadata.json 读取 image 和 loop，先用 `sudo losetup --associated /tmp/kylinrca-fio-实际目录/disk.img` 核对归属，再 detach 对应设备；确认无关联后删除该镜像及专用临时目录。实际路径以 metadata 为准，只清理本次创建的资源。

## 初始单窗口版本的历史验收

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

## 2026-11-20：三窗口状态机更新

默认规则已改为按设备连续三次异常触发、三次正常或空窗口恢复，且恢复期再次异常重新计数。JSON 用 devices 表示当前样本、diagnoses 表示仍在告警的设备。最后不足整窗报告 window_complete=false，不参与状态推进。前面的历史数据不能替代本次状态机验收。

脚本逐窗独立计算期望状态并核对 JSON，覆盖前两次不告警、第三次触发、空窗口保留告警、第三次正常解除，以及末尾无告警。合成回归另覆盖交替异常、设备隔离、恢复中断、正常有样本的恢复、配置校验、容量释放及部分窗口。运行命令与负载参数保持不变。

构建及 CTest 16/16、git diff --check 全部通过。连续三轮真实 fio/BPF 验收通过，每轮均验证第三个异常窗口才触发、恢复期前两次保留告警、第三次正常恢复，末尾无样本且无持续告警。每轮 3 个有样本的已确认告警窗口，另有 2 个空窗口处于恢复观察期。

| 轮次 | 接收事件 | 显式迟到 | 有样本的告警窗口 | 含恢复期的告警窗口 | 清理 |
| --- | ---: | ---: | ---: | ---: | --- |
| run-01 | 78053 | 0 | 3 | 5 | 完成 |
| run-02 | 74960 | 0 | 3 | 5 | 完成 |
| run-03 | 75946 | 1 | 3 | 5 | 完成 |

原始产物：`build/io-fio-20261120-191313-964914`。Probe 和 Analyzer 健康计数由脚本核对通过，三轮临时 loop 和镜像均已清理。

