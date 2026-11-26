# daemon Socket 查询（Issue #38）

`kylinrcad` 负责采集、分析和保存结果；另一个程序通过本机 Unix Domain Socket
查询结果。当前接入 Syscall、CPU、Lock。`kylinrca status/top/report` 正式 CLI
属于 Issue #39，本轮可以用 README 中的 Python 请求示例验证。

## 数据怎么传递

1. 采集线程把事件和定时 `AnalysisTick` 放入 `EventQueue`。
2. 分析线程独自使用 Analyzer。每次处理完 tick，就准备一份新的 `DaemonSnapshot`。
3. `SnapshotStore::publish()` 在锁外准备新快照，加锁交换指针，随即解锁。
4. Socket 线程加锁取得一个只读快照的共享指针，随即解锁，再整理响应并发送。

旧快照会保留到读者用完。即使客户端读取缓慢，分析线程仍可以发布新快照。
JSON 构造、排序和网络收发均不占用快照锁，采集线程不使用这把锁。
查询只读取已有结果，不重新运行诊断。

快照按 `window_ms` 更新，并非逐事件更新。不同请求可能读到不同版本，
可以比较 `updated_ns` 判断。停止时先停止 Socket 服务，再解除探针并排空分析队列。

## 最小协议

- 地址类型为 `AF_UNIX`，连接类型为 `SOCK_STREAM`。
- 一次连接发送一个请求，取得一个响应。需要再次查询时建立新连接。
- 请求为区分大小写的 ASCII 命令，以一个 LF（`\n`）结束：
  `status\n`、`top\n` 或 `report\n`。不接受参数、空格或 CRLF。
- 请求最多 64 字节，包含末尾 LF。按第一个 LF 分帧；其后内容不处理。
  请求可以分多次发送，不能依靠一次 `recv()` 就收到完整请求。
- 响应为 UTF-8 单行 JSON，以 LF 结束。客户端应读取到 LF，不依赖一次
  `recv()` 或连接断开来判断响应结束。服务端发完响应后关闭连接。
- 成功：`{"ok":true,"command":"status","data":{...}}`。
- 未知或空命令：`{"ok":false,"error":"unknown_command"}`。
- 超长请求：`{"ok":false,"error":"request_too_long"}`。
- 客户端提前断开，或收发连续约 1 秒没有进展时，服务端关闭该连接。
  不完整请求直接关闭。发送时使用 `MSG_NOSIGNAL`，断开不会触发 SIGPIPE 终止 daemon。

服务端使用一个独立线程依次处理客户端，等待队列长度为 8。慢客户端可能让其他
查询短暂排队；收发超时使空闲客户端释放连接，采集和快照发布继续工作。
这是一套供本机 CLI 使用的最小协议，没有订阅、长连接或自定义排序。

## status 字段

`data` 含有以下字段：

| 字段 | 含义 |
| --- | --- |
| `state` | 服务可查询期间为 `running`；启动失败不提供查询服务 |
| `pid` | daemon 自身的进程号 |
| `started_ns` | 本次 daemon 开始采集初始化时的单调时钟时间 |
| `updated_ns` | 当前快照对应的 tick 时间；第一份为 `started_ns` |
| `completed_windows` | 已完成并保存的 tick 数；启动时为 0 |
| `window_ms` | 配置的采样周期，单位毫秒 |
| `modules` | `syscall/cpu/lock/io` 实际接入状态；当前 `io` 固定为 `false` |
| `processed_events` | 分析线程自启动以来消费的 `syscall/cpu/lock` 事件数量 |

事件计数不包含 tick，不是 BPF 内核侧总事件数；Lock 的拒绝或迟到事件也算已消费，
其细分计数保留在 `report.lock`。配置中的 `enable_io` 尚未接入统一 daemon，
因此不会据此声称 I/O 正在采集。

所有 `*_ns` 时间戳来自 `CLOCK_MONOTONIC`，单位为纳秒，不能当作日历时间。
耗时也使用纳秒。CPU 使用率以一个逻辑核心为 100%；进程使用率可能超过 100%。

## top 字段和窗口

`data` 含 `updated_ns`、`limit=10`，以及 `syscall/cpu/lock` 三个模块。
模块未启用或没有第一个已完成窗口时，模块为 `null`。
已有窗口但没有热点时，返回带窗口时间的 `items: []`，不会沿用上一轮热点。

每个模块包含 `window_start_ns`、`window_end_ns`、`sort_by` 和 `items`。
返回的是查询时最近一次保存的已完成窗口。

| 模块 | 对象与主要指标 | 排序依据 |
| --- | --- | --- |
| `syscall` | PID、syscall ID/名称、次数、累计/最大耗时、错误次数 | `total_duration_ns_desc` |
| `cpu` | PID、TID、线程使用率、runtime 及其有效性与误差 | `usage_percent_desc` |
| `lock` | PID、futex 地址、成功明显等待次数、累计/最大等待、等待线程数 | `total_wait_ns_desc` |

主指标从大到小排序；相同时按 PID，再按 syscall ID、TID 或锁地址从小到大排序。
每模块最多 10 项。锁地址使用十六进制字符串，以免 JSON 客户端转换浮点数损失精度。

- Syscall 按分析线程两次 tick 之间消费的已完成调用统计，发布后清空窗口统计。
  窗口起止表示 tick 区间；队列调度和 ring buffer 排空可能让事件时间与此区间略有偏差。
  `report` 保留累计数据，`top` 不使用累计数据排序。
- CPU 使用已有 `/proc` 与 BPF runtime 采样窗口，按线程真实使用率排序。
  `runtime_valid=false` 表示缺少可信 BPF runtime 依据，不能解释为线程没有运行。
- Lock 使用 Analyzer 最近结算的固定窗口，沿用已完成 futex 等待的口径。
  只列出 `wait_count > 0` 的对象，失败和过短的等待仍可在 `report` 中查看。

三个模块的窗口边界未必完全一致，因此各自返回时间；不要把外层更新时间当作
每个模块的窗口边界。

## report 字段

`data` 含 `updated_ns` 和 `syscall/cpu/lock`。未启用模块返回 `null`；
CPU、Lock 在没有已完成窗口时也返回 `null`。
CPU 本轮未得到有效使用率采样时返回 `null`，不会把旧诊断配上零时间戳。

- `syscall`：`since_ns`、`until_ns` 和现有 `syscall_summary` 格式的 `summary`。
  表示从启动到快照时保留的累计统计；沿用原分析器清理规则，已退出且超过 60 秒
  没有事件的进程可以被移除，因此不是永久历史档案。
- `cpu`：现有 `cpu_summary`，含诊断、责任进程/线程、runtime 有效性、受害线程及窗口。
- `lock`：现有 `lock_summary`，含逐锁统计、阈值和竞争诊断。
  恢复观察期间保留的触发证据使用独立的 `evidence_window_*`，不伪装成本轮数据。

Socket 响应会去掉原 Reporter 的排版换行，JSON 字段和分析口径保持原样。
原有标准输出报告继续保留。

## 路径、权限和退出

默认地址是 `/run/kylinrca/kylinrca.sock`，可用配置 `socket_path` 修改。
缺失的父目录会被创建，目录权限遵循运行用户的 umask；Socket 在监听前设为 `0600`。
通常用 root 运行 daemon，因此查询示例也使用 `sudo`。

地址已存在时启动失败，不删除其他 daemon 的 Socket 或普通文件。
正常 SIGINT/SIGTERM 退出以及绑定后的启动失败会清理本进程创建的 Socket；
父目录保留。SIGKILL 或系统崩溃不能执行清理；确认旧 daemon 已退出后，
手动删除残留 Socket，再启动。不要删除仍在运行的 daemon 的地址。

## 验证

```bash
cmake -S . -B build
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

`daemon_socket` 不加载 BPF，使用现有 Analyzer 处理合成事件后通过真实 Socket 查询。
覆盖窗口/累计区分、排序和条数、CPU runtime 依据、Lock 诊断、空窗口、禁用模块、
分段请求、非法命令、长响应、提前断开、慢客户端期间继续发布、路径占用与权限清理。
运行环境需要允许绑定本机 Unix Socket。

### 提交 PR 前的完整验证流程

在仓库根目录执行以下命令。编译和自动回归可直接运行；实采步骤需要本地 root 权限。

1. 编译和自动回归：

   ```bash
   cmake -S . -B build
   cmake --build build -j4
   ctest --test-dir build --output-on-failure
   git diff --check
   ```

   当前应为 22/22 通过。这里的 Socket 测试使用合成事件，不加载 BPF。

2. 运行真实 BPF 验证：

   ```bash
   sudo python3 scripts/check_daemon_socket.py
   ```

   脚本使用独立 Socket 路径，自动启动并清理自己创建的 daemon 和负载。
   大约需要十几秒，过程中会执行：

   - 挂载 Syscall、CPU、Lock，检查真实 PID、模块开关和 Socket 权限 0600。
   - 创建已知 PID 的 Syscall 写入负载、CPU 计算负载、8 线程 mutex 竞争负载。
   - 连续请求 status/top/report，核对 Syscall PID、CPU PID/TID/runtime、Lock PID/地址。
   - 检查热点排序与最多 10 项，确认窗口和事件计数在查询期间继续增长。
   - 验证非法命令、超长命令、分段发送和提前断开之后仍能正常查询。
   - 用 SIGINT 退出并检查 Socket 清理；关闭 CPU 模块后重启，核对禁用结果。
   - 用 SIGTERM 退出并再次检查 Socket 清理。

   每轮记录保存到 `/tmp/kylinrca-issue38/run-*`，末尾会打印实际目录。
   `summary.json` 的 `passed` 应为 `true`，所有检查应为 PASS。
   `queries.jsonl` 保存三种查询的原始响应，`lock-workload.txt` 保存真实锁地址，
   `daemon.log`、`restart.log` 保存启动日志，两个 `.json` 文件保存 daemon 原有输出。

   若失败，查看 `summary.json` 和对应日志。CPU 检查要求测试线程至少一次进入前 10，
   且有有效 runtime；繁忙机器上的排名或采样问题需要结合原始响应排查。
   本脚本不要求全系统诊断一定恢复为 NORMAL，其他后台进程仍可能产生告警。

3. 手动确认两个终端的查询方式：

   终端 1 启动 daemon，保持运行：

   ```bash
   sudo ./build/kylinrcad > /tmp/kylinrcad-38-manual.json
   ```

   等到 `[daemon] Ready` 后，终端 2 执行：

   ```bash
   sudo python3 - <<'PY'
   import json, socket
   for command in ('status', 'top', 'report'):
       with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
           connection.settimeout(3)
           connection.connect('/run/kylinrca/kylinrca.sock')
           connection.sendall((command + '\n').encode())
           with connection.makefile('rb') as response:
               print(command, json.dumps(json.loads(response.readline()), indent=2))
   PY
   ```

   三个响应应均为 `ok: true`。终端 1 按 Ctrl+C 后，终端 2 确认路径消失：

   ```bash
   python3 - <<'PY'
   from pathlib import Path
   assert not Path('/run/kylinrca/kylinrca.sock').exists()
   print('PASS: 手动退出后 Socket 已清理')
   PY
   ```

4. PR 中分别记录自动回归、实采脚本和手动查询的真实结果，并附实采输出目录或摘要。
   B 拉取分支后重复这些命令并完成 Review，作为合并验收。

B 的本地联调步骤：

1. 用 README 的命令启动 daemon，等到 `[daemon] Ready`。
2. 在另一个终端发送三个请求，确认 `status.modules` 和配置一致。
3. 运行 README 中的 Syscall、CPU、Lock 真实负载，重复查询 `top/report`，核对负载 PID、
   TID、锁地址和指标；确认 `status.completed_windows` 及事件计数继续增长。
4. 负载结束后检查热点和诊断恢复；向 Socket 发送非法命令并提前断开一次，再正常查询。
5. 按 Ctrl+C 退出 daemon，确认 Socket 路径消失；重新启动后能继续查询。
6. Review 请求接收、快照发布、查询响应三段代码，并记录实际联调结果。

合成事件测试不代替真实 BPF 验证，也不代替 B 的 Review。
