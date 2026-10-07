# Bounded ground resource capture contract

Source, binary, observer and controller commitments must be selected independently and recorded locally. Resource observations cannot extend consensus or qualification deadlines.

## 当前采集实现

`tools/regional_ground_resources.py` 是单独运行的只读工具，也提供 `Process`、`Storage`、
`Recorder` 接口供后续冻结控制器显式接入。它不启动或停止节点、不加载私钥，不调用
Runtime、Native 开启/恢复/签署、Mesh 锁或钱包，不采用任何调用者头。

进程观察只针对调用者显式选择的 PID。首次记录的启动时间和命令摘要必须继续匹配；
后续不匹配、退出或读取失败返回未知，绝不填零。输出不含 PID、命令、私有路径或凭据。
CPU 为进程累计时间及相邻有效观察的单核百分比，RSS 为观察时驻留字节。
短命子进程未自动覆盖；秒级 `ps` 启动时间/命令摘要不是独立进程身份或保管证明。

可选 `--exited-child-cpu` / `Recorder(..., exited_child_cpu=True)` 使用独立 V2 日志，
头部绑定 `regional_ground_child_cpu.py` 的精确字节；默认模式仍只观察主进程 CPU/RSS。
macOS SDK rusage V1/Mach timebase 返回主进程及已退出子进程的累计 CPU，
不需捕捉每个短命子进程的 PID。每个观察器保留原 PID/命令/启动锚及首个有效内核启动值；
后续内核启动改变、退出、读取失败或 CPU 计数回退返回未知，间隔百分比重置。
初次非原子身份观察仍不是独立身份保证；不能接纳另一个锚替代原标签。
最多保留 32 个进程观察器，动态注册同样受上限约束；输出仍无 argv、PID 或私有路径。
V2 日志核验逐项重算百分比与未知/采样最大值，不相加可能重叠的父子累计量。
活跃子进程 CPU/RSS、Native 命令普查、系统总 CPU 和实际 fsync 成本仍未覆盖。
旧 V1 日志和已冻结控制器保持原字节，绝不回填子进程 CPU 或改变旧失败判定。

存储仅遍历显式目录的元数据，逐路径计数完整文件的逻辑长度；不读节点/钱包内容。
扫描拒绝符号链接、特殊文件、目录替换和超过 4,096 个目录项的观察；失败项全部为未知。
这是采集器工作预算，不改变任何 Native/档案容量。活跃写入可能使样本不一致；
`atomic_snapshot: false` 保留该边界。逻辑长度不是实际物理占用、fsync 时间或全节点总存储。

采集间隔 1–60 秒、至多 32 个显式进程及 32 个目录、4,096 条记录、单条 64 KiB、
日志 32 MiB。独立 CLI 时长最多 3,600 秒，仅限制采集器；不修改控制器阶段时间。
每条记录带前条完整字节摘要、单调时钟开始/结束、采集耗时、缺采间隔和超间隔标记。
所有资源最大值必须称为“采样最大值”；采样不能排除间隙峰值。

日志须在所有观察目录外，以 0600 独占新建，每条 flush/fsync；不覆盖、合并或恢复旧日志。
写入/容量错误保留部分日志并拒绝成功返回，缺少终止记录代表采集未完成。
摘要链和文件同步仅保护记录关联，不能提供 Native、签署、独立新鲜度或防回滚权利。
日志默认私有，公开前单独审阅与脱敏；不公开生成的私有目录或证据载荷。

## 已接入的控制器观察与仍未实现的测量

当前输出显式将 `native_value_observation` 保留为 null，`native_value`、`wire_bytes`、
`fsync_latency`、`child_process_tree`、`continuous_peaks` 和 `qualification` 均为 false。
CLI 正常终止仅表示观察循环完成，`campaign_passed` 为 null。
没有把外部任意金额、文件数量、遥测高度或摘要接受为 Native 价值认证。

后续补充已实现 `regional_ground_value.py`：有限故障控制器原有的十二次 `status` 与
三次 `proof` 调用保持不变，仍经过精确 Native 的完整重放。观察同时绑定货币、地区、
高度、块和状态根；领先副本中的已确认扣除必须计入，等高不兼容状态拒绝。
完整响应以规范字节摘要和每次调用区间绑定，保留选中检查点与十二高度。
永久导入必须对应观察到的唯一来源出口和目标地区，received 计数必须相符；
未交付毛额包括目的手续费，净额单独记录。缺失、锁拒绝、混合的不兼容观察直接拒绝，
不重用旧成功值、不猜测零、不生成签署/入账或当前可花费权利。
模块本身不运行 Native；只有执行控制器的正常 Native 回调可提供这些结果。
普通 `status` 并非一般性的无恢复入口，不能绕过原停止检查或 pending-incident 限制。

`regional_ground_relay.py` 提供显式 IPv4 loopback 加密流计量。控制器的
`--meter-contacts` 只在全新私有范围中为原配置的每个方向加入独立转发端点；
邻居身份和证书 SHA-256 固定值仍由原配置核对，不能从广告学习地址或 pins。
每个 relay 沿用两个 worker、四秒转发期限和每连接 64 MiB；所有真实发送返回的字节，
包括发生错误前的部分发送，都计入各方向。已读取但未转发的字节单独保留，活跃时不是丢包证明。
计数溢出/线程启动失败返回未知并拒绝度量成功；停止须加入全部实际线程。
不终止 TLS、不解码/保留载荷、不创建目的收件或账本回执；Socket 转发成功仍不是保管证明。
这些是 TCP 中的加密流字节，包含重传应用承载/握手，但不覆盖 TCP/IP 头或物理链路字节。
