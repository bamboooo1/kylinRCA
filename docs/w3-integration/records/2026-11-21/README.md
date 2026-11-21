# 2026-11-21 W3 四模块实采记录

对应 [Issue #28 验收文档](../../../w3_integration_validation.md)，基线
`e694090a30b2d51e357651ff255708259cec837e`，分支 `feat/w3-integration`。
用户执行构建和实采；归档时重新核对保存的日志，没有重新启动负载或采集程序。

- [summary.json](summary.json)：本轮综合结果、基线、四类模块指标、范围和待人工确认项。
- [manifest.json](manifest.json)：64 个原始文件的源路径、归档路径、字节数及 SHA-256。
- [ctest.txt](ctest.txt)、[build.txt](build.txt)、[configure.txt](configure.txt)：18 项测试与构建日志。
- [syscall-pid.txt](syscall-pid.txt)、[syscall-check.json](syscall-check.json)：身份、自过滤及目标读写提取结果。
- [syscall.txt.gz](syscall.txt.gz)：完整 loader 日志，无损 gzip 压缩。
- [cpu/](cpu/)：两类 CPU 原始诊断、计数及结果 JSON。
- [lock/run-zuyudpoe/](lock/run-zuyudpoe/)：三轮竞争和对照、原始等待事件、窗口 JSON、进程退出码。
- [io/](io/)：环境、三轮窗口 JSON、Probe 计数、fio 输出、命令和清理记录。
- [reviews.json](reviews.json)：GitHub PR #34、#35 的双向 Approved 元数据及链接。
- [terminal-excerpt.txt](terminal-excerpt.txt)：用户提供的终端节选，保留手工输入的测试 PID。

原始目录为 `/tmp/kylinrca-w3-nYsGQb`。为避免仓库忽略 `*.log`，归档把后缀改为 `.txt`，
内容保持原始字节；完整 Syscall 日志单独压缩。原始 JSON 内的绝对路径保持原样，
文件对应关系查 manifest 中的 `source` 与 `archive`，无需依赖原机器的 `/tmp`。
`summary.json` 和 `syscall-check.json` 为从原始记录提取的汇总，不是新的实采。

在仓库根目录验证全部原始文件的归档内容：

```bash
python3 - <<'PY'
import gzip
import hashlib
import json
from pathlib import Path

root = Path('docs/w3-integration/records/2026-11-21')
entries = json.loads((root / 'manifest.json').read_text())
for entry in entries:
    archived = (root / entry['archive']).read_bytes()
    assert hashlib.sha256(archived).hexdigest() == entry['archive_sha256']
    original = gzip.decompress(archived) if entry['encoding'] == 'gzip' else archived
    assert len(original) == entry['source_bytes']
    assert hashlib.sha256(original).hexdigest() == entry['source_sha256']
print(f'归档校验通过：{len(entries)} 个原始文件')
PY
```

查看压缩的完整 Syscall 日志：

```bash
gzip -dc docs/w3-integration/records/2026-11-21/syscall.txt.gz | less
```

归档核对还使用现有 `check_lock_rca.evaluate_case()`、`check_io_analyzer.validate()`
重新计算六例 Lock 与三轮 I/O 的判断结果，并核对 CPU 原始采样、热点身份、窗口证据和计数。
第二轮 I/O 的 1 条迟到按原规则保留；未重写原始结果或伪造命令退出码。
