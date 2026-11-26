# CPU、Lock、I/O 模块配置

daemon 统一读取配置，但模块专用规则不进入 AppConfig。
公共配置管理日志、Socket、模块开关和 window_ms；
CpuConfig、LockConfig、IoConfig 分别把文件转换成对应的 AnalyzerConfig。
Syscall 当前只做统计，没有新增专用配置文件。

## 启动

~~~bash
cmake -S . -B build/w4-module-config -DCMAKE_BUILD_TYPE=Debug
cmake --build build/w4-module-config -j 4
ctest --test-dir build/w4-module-config --output-on-failure
sudo ./build/w4-module-config/kylinrcad --config config/kylinrca.conf.example --cpu-config config/cpu.conf.example --lock-config config/lock.conf.example --io-config config/io.conf.example
~~~

四个配置选项可任意顺序传入，模块文件可独立省略。
不传文件或省略字段时保留原有默认值；显式文件缺失、重复选项、重复键、
未知字段和非法参数都会在挂载 BPF 前明确失败。
读取错误包含文件路径，字段错误带行号；跨字段关系错误指明涉及的字段。
显式配置即使对应模块关闭也会校验，不把错误配置静默藏起来。

模块文件采用一行一个键值，支持空行、整行注释、首尾空白和 CRLF。
不支持行尾注释、分节、环境变量展开和带单位的数值字符串。
所有数字字段必须完整解析，不接受符号、溢出或多余字符。

## CPU 参数

| 字段 | 默认 | 规则 |
| --- | --- | --- |
| high_usage_threshold_percent | 80 | 有限十进制百分比，可含小数，最大 100 |
| recovery_threshold_percent | 50 | 0..100，必须严格低于告警阈值 |
| runqueue_delay_threshold_us | 10000 | 正 uint32 微秒，读取后转成纳秒，默认 10ms |
| alert_consecutive_samples | 3 | 正 uint32 连续异常样本数 |
| recovery_consecutive_samples | 3 | 正 uint32 连续恢复样本数 |

百分比不接受 NaN、无穷大和指数形式。只修改告警阈值时，
也要确保它与仍使用默认值的恢复阈值关系合法。
CpuAnalyzer 的既有诊断算法不变；外部配置先严格校验，避免依赖构造函数的旧有修正逻辑。

daemon 的 cpu_summary 增加 thresholds，记录分析器实际采用的五项参数；
排队延迟在报告中使用纳秒。小数阈值保留可回读精度，便于核对生效情况。

## Lock 参数

| 字段 | 默认 | 规则 |
| --- | --- | --- |
| minimum_wait_us | 1000 | 正 uint32，低于此值的成功等待归入短等待 |
| average_wait_threshold_us | 10000 | 正 uint32，平均明显等待阈值 |
| max_wait_threshold_us | 50000 | 正 uint32，最大明显等待阈值 |
| minimum_waiting_threads | 2 | uint32，至少 2 个不同等待线程 |
| recovery_windows | 2 | 正 uint32，连续正常或空窗口达到此数后恢复 |

要求 minimum_wait_us <= average_wait_threshold_us <= max_wait_threshold_us。
三个时间值读取后转换为纳秒；Lock 原有诊断和聚合口径不变。
lock_summary 已包含 thresholds，能够直接核对实际配置。

## 公共窗口和 I/O

公共 window_ms 仍同时控制 CPU 采样间隔、Lock 和 I/O 窗口长度。
模块文件不接受 window_ms，避免同一参数在多处相互覆盖。
I/O 保留 latency_threshold_us、min_samples 和 device，
默认 10ms、最低 10 样本、全部设备。旧公共 I/O 字段仍不接受。

CPU、Lock、I/O 共用 module_config_reader 的基础文本、数字和文件读取，
各模块解析器只识别自己的字段并检查自己的规则。
分析器不读取文件；主线程把解析结果传入分析线程，再分别构造各分析器。

## 验证

~~~bash
sudo python3 scripts/check_daemon_module_config.py --build build/w4-module-config --output build/module-config-real
sudo python3 scripts/check_daemon_io.py --build build/w4-module-config --repeat 1 --cpu-config config/cpu.conf.example --lock-config config/lock.conf.example --output build/module-config-four-probes
~~~

复跑使用新的输出目录。第一个脚本分别对 CPU、Lock 执行低阈值触发与高阈值对照，
核对 JSON 中实际阈值、真实事件及诊断状态。测试参数只写入本轮输出目录，不改产品默认值。
CPU 运行两线程压力；Lock 运行 8 线程竞争，核对目标 PID，并观察低阈值告警后的恢复。
CPU 恢复逻辑由确定性观测回归验证，实采是否恢复还取决于背景使用率。

第二个脚本在同一 daemon 中传入三份模块配置，先确认目标设备已经产生真实 I/O，
再启动 CPU、Lock 和 Syscall 负载，仍独立核对报告窗口重叠；
I/O 使用新建的临时 loop 镜像，核对三窗告警与恢复、字节与事件闭环，以及模块时间重叠。

2026-11-26，Ubuntu 26.04 / x86_64 / WSL2：
干净 Debug 构建通过，CTest 25/25。
CPU 触发与对照、Lock 触发与对照四个实采用例均通过；
三份模块配置同时输入时的四模块并发及 I/O 告警恢复通过。

[本次环境、配置、原始报告与汇总](module-config/records/2026-11-26/summary.json)单独归档，
不覆盖此前 I/O 重构证据。结果基于未提交工作树，汇总中的源码哈希标识版本。
Socket/CLI 查询入口和队友人工 Review 仍是独立待办。
