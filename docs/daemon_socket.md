# daemon 统一快照与 Socket 查询（Issue #38）

`kylinrcad` 统一采集 Syscall、CPU、Lock、I/O。另一个程序通过 Unix Domain Socket
查询状态、热点和已有报告。正式 `kylinrca status/top/report` CLI 属于 Issue #39，
本轮使用 README 中的 Python 查询示例和统一 daemon 验收入口。

## 职责与数据流

| 位置 | 职责 |
| --- | --- |
| `src/kylinrcad.cpp` | 配置、探针、采集、CPU/内核健康采样、定时与停止通知 |
| `src/daemon_analysis.cpp` | 分析线程独占四个 Analyzer，处理队列、结算窗口、输出报告、制作快照 |
| `IoSnapshot` | I/O 启用状态、累计计数、最近窗口、探针健康数据的值副本 |
| `DaemonSnapshot` | 同批生成的 status/top/report JSON 和退出所需的 I/O 最终状态 |
| `SnapshotStore` | 唯一共享仓库，在锁外准备快照，仅在交换或读取共享指针时加锁 |
| `src/unix_socket_server.cpp` | 独立线程接收请求，读取只读快照，在锁外发送答案 |

原来的 IoSnapshotStore 已合入统一发布机制。模块负责分析，快照负责保存结果，
Socket 负责通信；查询不重新分析，也不直接访问 Analyzer。

主线程把事件和 AnalysisTick 放进 EventQueue。事件用于累计统计，只有分析线程处理
tick 时才结算并发布快照。Lock 和 I/O 按完成时间判断归属，跨到下一窗口的记录先暂存，
等 tick 打开相应窗口后再加入统计。恰好在结束边界的记录，Lock 计入下一窗，
I/O 计入当前窗。

如果一条 tick 跨过多个完整窗口，分析线程逐窗结算 Lock 和 I/O，每份结果在被替换前
先发布，CPU 和 Syscall 沿用这条 tick 的同一份结果。SnapshotStore 对新查询提供最新
快照，已经开始的查询可继续持有旧快照，直到使用完毕。
排序、JSON 生成和 Socket 收发都不持仓库锁，采集线程也不使用这把锁。

停止时先结束 Socket 接待，再解除四种探针、消费尾部，投递 final tick。
分析线程结算 Lock/I/O 尾窗并更新统一快照，队列关闭排空后退出。
主线程读取最终 IoSnapshot，输出原有 io_status。final tick 不增加完整窗口计数。

## 最小协议

- AF_UNIX、SOCK_STREAM，一次连接发送一个请求并读取一个响应，随后服务端关闭连接。
- 请求区分大小写，以一个 LF（`\n`）结束：`status\n`、`top\n`、`report\n`。
  不接受参数、空格或 CRLF；最多 64 字节，包含 LF。只处理第一行，其后内容忽略。
- 请求可以分多次发送；响应也可能分多次收到，不能把一次 recv 当成消息边界。
- 响应是 UTF-8 单行 JSON，以 LF 结束；客户端读取到 LF 即取得完整响应。
- 成功：`{"ok":true,"command":"status","data":{...}}`。
- 空命令或未知命令：`{"ok":false,"error":"unknown_command"}`。
- 超长命令：`{"ok":false,"error":"request_too_long"}`。
- 不完整请求在断开或收发等待约 1 秒没有进展时关闭。发送使用 MSG_NOSIGNAL，
  对方提前断开不会因 SIGPIPE 终止 daemon。

服务端一个线程依次处理客户端，监听等待队列设置为 8。慢客户端可能使其他查询排队，
不阻止分析线程发布新快照。协议没有订阅和长连接。

## status

| 字段 | 含义 |
| --- | --- |
| `state` | 服务可查询期间为 running；启动失败不提供查询服务 |
| `pid` | daemon 自身 PID |
| `started_ns` | 本次开始初始化采集时的单调时钟时间 |
| `updated_ns` | 当前快照对应的 tick 时间，首次为 started_ns |
| `completed_windows` | 已处理的普通 tick 数，启动时为 0，不包含最终尾窗消息 |
| `window_ms` | 公共采样周期 |
| `modules` | syscall/cpu/lock/io 的实际启用状态 |
| `processed_events` | 分析线程自启动以来消费的四类事件数量，不包含 tick |

消费计数包含随后被分析器拒绝的事件，并非 BPF 内核总数。I/O 的 invalid、late、
capacity_drops、字节数和探针健康数据保留在 report.io，Lock 细分计数保留在 report.lock。
所有时间戳和耗时以纳秒计；时间戳使用 CLOCK_MONOTONIC，不是日历时间。

## top

外层含 updated_ns、limit=10 和四个模块，每个模块有 window_start_ns、window_end_ns、
sort_by、items。未启用或没有已结算结果时为 null，有窗口但没有热点时 items 为 []。

| 模块 | 责任对象 | 主排序字段 |
| --- | --- | --- |
| syscall | PID + 系统调用编号 | total_duration_ns 降序 |
| cpu | PID + TID | usage_percent 降序 |
| lock | PID + futex 地址 | total_wait_ns 降序 |
| io | 设备主/次编号 | p95_duration_ns 降序 |

主指标相同，按 PID/调用编号、PID/TID、PID/锁地址或设备主/次编号升序；每模块最多 10 项。
CPU 百分比保留可回读精度。锁地址使用十六进制字符串，避免浮点数转换损失。

Syscall 按两次 tick 之间消费的已完成调用统计，发布后清空本轮记录；它的 tick 区间
与事件真实时间可能因队列和缓冲区排空略有偏差，累计结果另存于 report。
CPU 使用 /proc 和 BPF runtime 的真实采样窗口，runtime_valid=false 表示读数不可用，
不能解释成零运行时间；本轮未取得 CPU 观测时为 null。
Lock 读取最近结算窗口，仅排名 wait_count>0 的对象。I/O 仅排名有样本设备，
没有样本但仍处于恢复观察的告警保留在 report，不作为本轮热点。

四个模块窗口不强行对齐，各自保留时间边界。I/O 还含 window_complete，
最终不足整窗的结果为 false，尾窗不改变连续异常/恢复次数。

## report

外层含 updated_ns 和四个模块；禁用模块为 null。

- syscall：since_ns、until_ns、summary，summary 保留原 syscall_summary 格式。
  累计表仍清理已退出且超过 60 秒无事件的进程，不是永久历史档案。
- cpu：原 cpu_summary，保留诊断、责任/受害线程、runtime、窗口和实际配置 thresholds。
  没有有效采样窗口时为 null；最终消息不把最近 CPU 结果误标成零时间窗口。
- lock：原 lock_summary，含逐锁统计、阈值和诊断；恢复期间保留的触发证据使用
  独立 evidence_window_*，不标成当前窗口。
- io：原 io_status，包含 enabled、累计计数、probe 和最近 report。
  已启用但还没有窗口时，io_status.report 为 null；诊断、拒收原因和健康字段不丢失。

Socket 会移除原 Reporter 用于排版的换行，仅在完整响应末尾添加 LF。
daemon 标准输出仍保留连续 JSON 文档格式，Syscall 总结可能跨行。

## 路径与权限

默认 /run/kylinrca/kylinrca.sock，可由公共 socket_path 修改；自动创建缺失父目录，
目录权限遵循 umask，Socket 在监听前设为 0600。root 启动的 daemon 使用 sudo 查询。
路径已存在时启动失败，不覆盖其他 daemon 或普通文件。
正常退出或绑定后启动失败时，删除本进程创建的 Socket，保留父目录。
SIGKILL 无法执行清理，确认旧进程退出后再手动删除残留路径。

## 双方测试如何合并

| 原测试 | 原覆盖重点 | 当前归属 |
| --- | --- | --- |
| event_queue_test.cpp | 长度/类型、副本、关闭排空和等待唤醒 | daemon_fixture.cpp 的队列检查 |
| io_daemon_test.cpp | 四类型分发、I/O 边界、迟到、恢复、尾窗、并发快照 | 同一 fixture 的 I/O 边界检查 |
| socket_server_fixture.cpp / socket_server_test.py | 三个查询、排序、断开、慢客户端、路径权限 | daemon_fixture.cpp / daemon_test.py，增加 I/O |
| daemon_config_options_test.py | 模块参数错误和读取顺序 | daemon_test.py 的配置用例 |
| check_daemon_socket.py | 三模块热点身份、runtime、协议、两种停止信号和重启 | check_daemon.py 的 socket 场景 |
| check_daemon_io.py | 临时 loop、fio、四模块重叠、告警恢复和计数闭环 | 统一入口的 io/modes 场景，增加连续 Socket 查询 |
| check_daemon_module_config.py | CPU/Lock 阈值触发与对照 | 统一入口的 config 场景，同时核对 Socket 阈值 |

无特权回归由一个 daemon_integration 用例运行，fixture 使用与真实 daemon 相同的
analyze_events，避免另写一套分析流程。I/O 专用算法和配置的独立单测继续保留。
check_daemon.py 包含完整实采验收：运行入口、Socket 场景、CPU/Lock 配置测试、
I/O 共存与开关模式，以及共用的查询、连续 JSON 解析和采样记录。

## 提交前完整验证

1. 编译和无特权回归：

   ```bash
   cmake -S . -B build
   cmake --build build -j4
   ctest --test-dir build --output-on-failure
   git diff --check
   ```

   daemon_integration 覆盖四模块查询、窗口与累计区分、告警恢复、尾窗、健康计数、
   模块禁用、配置生效、非法/分段请求、提前断开、8MiB 响应、慢客户端发布与路径清理。
   合成事件不代表真实 BPF 实采已通过。

2. 完整实采，默认包括三轮隔离 fio：

   ```bash
   sudo python3 scripts/check_daemon.py
   ```

   默认记录在 /tmp/kylinrca-daemon-validation/run-*，末尾打印实际位置。
   results.json 的 passed 必须为 true；各场景记录查询原文、配置、命令与清理结果。
   fio 只写本轮新建的 128MiB loop 镜像，100μs 是验收阈值，产品默认仍为 10ms。
   CPU 热点身份检查需要测试线程进入前 10；繁忙机器需结合记录排查排名和 runtime。
   Socket 场景持续六秒制造锁竞争，分别核对各测试进程的 PID 和锁地址，避免一次短负载
   落在两次定时快照发布之间而未被查询观察到。查询只返回最近快照，不保存所有历史窗口。

3. 可分场景定位失败，不必重复全部负载：

   ```bash
   sudo python3 scripts/check_daemon.py --suite socket
   sudo python3 scripts/check_daemon.py --suite config
   sudo python3 scripts/check_daemon.py --suite io --repeat 1
   sudo python3 scripts/check_daemon.py --suite modes
   ```

4. 手动双终端：终端 1 运行 sudo ./build/kylinrcad，终端 2 按 README 示例分别发
   status/top/report。三个响应均为 ok=true；终端 1 Ctrl+C 后确认 Socket 路径消失，
   再次启动后能继续查询。

5. PR 分别记录合成事件回归和实采的真实结果。B 拉取分支复测并 Review，作为合并验收。
   2026-11-26 的历史实采记录保留在原报告中，不能代替本次统一快照改动的验收。
