# Syscall PID 命名空间修复与验证

## 问题与修改

同一进程的 `getpid()` 返回 `793858`，旧探针事件却输出 `21722`。这两个编号分别来自采集程序所在的 PID 命名空间和内核的初始 PID 命名空间，不能直接比较。旧的 tracer 自过滤和用户态进程存活检查也会因此受到影响。

用户态现在通过 `/proc/self/ns/pid` 获取当前命名空间的 inode，并在挂载前写入 `namespace_config[0]`。BPF 通过任务的 PID 信息查找该命名空间里的 PID、TID，进入调用时一起保存，退出时写入事件。对采集程序不可见的任务不输出事件；配置缺失时也不退回输出内核编号。部署时 `/proc` 必须与采集程序所在的 PID 命名空间匹配。

`config_map[0]` 仍保存用户态 `getpid()` 的结果，自过滤改用转换后的进程 PID 比较，因此整个采集进程的线程都会被排除。`start_map` 内部仍使用原始内核 `pid_tgid` 配对。共享事件结构和 JSON 格式保持不变。`SyscallAnalyzer` 无须转换编号，直接使用事件 PID 做统计和 `kill(pid, 0)` 存活检查。

## 构建及非特权检查

在工程根目录执行：

```bash
cmake -S . -B build
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

`syscall_analyzer` 检查统计结果，并验证真实存活进程被保留、已退出子进程被清理。CTest 不加载 BPF，不能替代下面的实采验证。

## PID、TID 和自过滤实采

```bash
sudo ./build/kylinrca_syscall_pid_test
```

测试使用与 loader 相同的 `syscall.bpf.o` 和命名空间配置函数，需要 BPF 加载权限。第一阶段临时允许采集自身，由工作线程各调用三次 `getpid` 和 `gettid`，依据返回值及调用时间范围找到对应事件，核对事件 PID、TID。第二阶段排除自身，确认六次工作线程调用均不出现，同时另一个进程的两次调用仍能正常采到。

成功时打印：

```text
[SYSCALL PID] identity=PASS matched_calls=6
[SYSCALL PID] self_filter=PASS excluded_calls=6 child_calls=2
```

任何编号不符、预期事件缺失、自过滤失败或子进程未被采集，都会以非零状态退出。不要继续使用旧的 `/tmp/kylinrca-syscall-idcheck` 二进制：它没有配置新增的命名空间 Map。

## 原 loader 的端到端复核

终端一在工程根目录启动：

```bash
sudo ./build/bpf_loader | tee -i /tmp/kylinrca-syscall-fixed.log
```

`tee -i` 忽略 Ctrl+C，让 loader 收到停止信号后仍能把最终 JSON 写入日志。普通 `tee` 可能与 loader 同时退出，造成日志只有启动信息、缺少最终报告。

等出现 `Collecting syscall events...` 后，在终端二执行：

```bash
python3 -c '
import os

read_fd, write_fd = os.pipe()
print("测试进程 PID：", os.getpid(), flush=True)
data = b"x" * 64
for _ in range(100):
    os.write(write_fd, data)
    assert os.read(read_fd, 64) == data
os.close(read_fd)
os.close(write_fd)
input("100 次读写完成；请先在终端一按 Ctrl+C，再回这里按回车退出。")
'
```

这里使用 `python3 -c` 传入代码，让标准输入继续连接终端，`input()` 才能等待回车。使用 `python3 - <<'PY'` 时，标准输入用于读取代码，读完后 `input()` 会遇到 EOF 并报错。

保持测试进程存活，先在终端一按 Ctrl+C 生成 JSON。找到与终端二打印 PID 相同的统计，`read`、`write` 的 `count` 应各不少于 100，且二者 `error_count` 为 0。Python 启动、输出及等待输入可能增加调用数，因此不要求恰好 100。loader 启动时打印的 `Tracer PID configured` 不应出现在 JSON 的进程统计中。

可以用下面的命令提取指定 PID 的统计，把 `801463` 替换成本轮测试打印的 PID。日志包含启动文字，不能直接把整个文件当成纯 JSON 读取。

```bash
python3 - 801463 <<'PY'
import json
from pathlib import Path
import sys

pid = int(sys.argv[1])
text = Path("/tmp/kylinrca-syscall-fixed.log").read_text()
marker = text.find('"type": "syscall_summary"')
if marker < 0:
    raise SystemExit("日志中没有最终 JSON，请检查 loader 是否已正常停止，以及 tee 是否保留了报告。")
start = text.rfind("{", 0, marker)
report, _ = json.JSONDecoder().raw_decode(text[start:])
found = next((p for p in report["processes"] if p["pid"] == pid), None)
print(json.dumps(found, ensure_ascii=False, indent=2) if found else f"未找到 PID {pid} 的统计")
PY
```

最后再让终端二退出。只有编译、CTest 和实采验证均通过后，才能确认该环境中的修复完成。
