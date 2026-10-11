# Bounded contact trace interface

## 实现与保管语义

`RLD_GROUND_CONTACT_TRACE=1` 显式开启进程内私有元数据环，默认关闭。
最多 128 行、每行 1,024 字节、快照 192 KiB；仅保存包/帧/完整信封摘要、
固定邻居、尝试序号、请求 nonce、单调时刻和有界拒绝类别。
不保存负载、密钥或 Native 账本；不输出到伴随进程 stdout。
TCP 的每次已打开 Mesh 操作使用同一个显式开启的观察器，使既有的
准备选择、完整交换保留和目录收发边界可在实际运输路径记录。
选择事件不代表交换已保留；保留事件不代表连接成功、对端保管或 Native 接收。
默认关闭及观察拒绝均保持正常准备、认证与保管要求；缺失事件仍为未知。
`mesh_lease_cost` 将既有的固定角色/阶段墙钟时长、成功标志和该类调用数
投影到同一有界环，时长使用整数微秒。`acquire` 包含打开，`open` 包含完整
验证，`hold` 包含打开和关闭；`hold` 的成功只表示关闭成功。它们不能相加
作为互不重叠的 CPU 时长。进程内 `worker_id` 仅供关联，同一标签可能被复用，
不是操作身份或保管证明。`outbound_peer_started/finished` 标记同一尝试的完整
发送轮次边界；完成包括拒绝路径，不代表连接、认证或保管成功。丢失、拒绝、
未配对或跨进程记录保持未知，不得据此归因，也不改变等待期限或调度。
在完整追踪模式中，`RLD_GROUND_TRACE_WATCH_ENVELOPE` 可显式指定一个完整
BFT 信封的32字节十六进制摘要。`native_selection_watch` 每次仅记录一次选择的
匹配摘要数、目的/回执/已接收/已尝试/合资格数量、原剩余槽位、两类数量、
原轮转次序中的首个匹配名次，以及实际检查和选中数量。名次从1开始，0表示
该类没有匹配项；它不是 Native 认证、签署许可或最新状态证明。
观察器不读取包、调用分类器或 Native，也不更新轮转次序；它仅观察原选择
输入和结果。拒绝或丢失记录仍为未知，不改变四项限制、两类公平份额或重试规则。
普通入队、准备交换、请求发送、对端认证保管、实际本地保管、目标回执和
Native 完整信封接收分别记录。Native 接收事件只在正常完整认证、依赖同步和
保留成功之后产生。目标运输回执不代表 Native 接收或可花费。

`inbound_refused.failure_stage` records the local execution boundary:
`mesh_open`, `custody_receive`, `custody_observe` or `reply_prepare_or_close`.
The last boundary includes context-manager close; it does not assert that reply
construction was the unique cause. The bounded exception class is retained
alongside it. These private observations distinguish a pre-open lock refusal,
a receive/publication failure and refusal after durable receipt retention without
changing the signed `CONTACT_REJECTED` reply or granting custody. A sender's
generic refusal alone cannot identify the receiver's cause. Missing or evicted
events remain unknown; the exact earlier failure cannot be reconstructed from
a later run.

所有 Native 验证、TLS pin、挑战/精确交换绑定、fsync、签署头、四项接收槽、
票数、成熟高度、期限和容量保持原要求。追踪需要额外散列和状态字节，可能改变时序；
它是明确开启的观察候选，不能替代关闭追踪的既有资格，也不提供账本授权。

独立采集器固定拥有的进程身份及预先给定 network/node 绑定，读取私有状态环；
原生状态等其他字段即刻丢弃。事件丢失、拒绝、身份变化和格式不符明确记录。
PID/进程命令关联是观察边界，不是独立最新状态保护。写入失败保留部分日志并向观察者
抛出，不能重启节点、恢复签署、采纳调用者头或使协议跳过同步。

Trace coverage is an observation property. Missing events, rejected identities and
unpublished tails remain unknown; they cannot prove absent custody, ledger
acceptance, spendability or the unique cause of a stalled payment. Traces and
source/binary/controller binding records are retained locally.
