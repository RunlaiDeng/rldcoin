# Bounded contact trace interface

## 实现与保管语义

`RLD_GROUND_CONTACT_TRACE=1` 显式开启进程内私有元数据环，默认关闭。
最多 128 行、每行 1,024 字节、快照 192 KiB；仅保存包/帧/完整信封摘要、
固定邻居、尝试序号、请求 nonce、单调时刻和有界拒绝类别。
不保存负载、密钥或 Native 账本；不输出到伴随进程 stdout。
普通入队、准备交换、请求发送、对端认证保管、实际本地保管、目标回执和
Native 完整信封接收分别记录。Native 接收事件只在正常完整认证、依赖同步和
保留成功之后产生。目标运输回执不代表 Native 接收或可花费。

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
