# Joint 普通循环中的单次原生签名头观测候选

2026-10-04。仅适用于显式 `RLD-REGIONAL-BFT-NODE-JOINT-V1` 地面配置。
Native/Core、原生签名检查、共识与运输格式、私有磁盘格式均未改变。

## 实测依据

384 文件版本的全新故障范围仍失败于原 600 秒恢复接触后的新增出口导入与成熟门槛。
严格停止核验认证了十二份 Native 前缀、2,105 个完整 BFT 信封、4,727 条运输归档和四组
分离的 caller 保管记录，全部私有字节与权限保持不变。比邻星实际于高度 12 导入，
成熟高度 14，停止高度 13；三个原始所有者请求已入账、预留为零。失败不可通过恢复续跑改写。

[真实进程的现有有界观测](evidence/regional-frame-stream-live-fault-cost-observation-retry1-20261004.json)
与[停止后的分项测量](evidence/regional-frame-stream-stopped-bft-components-20261004.json)
是不同范围。后者的地球新 voter 只读头查询三次平均为 0.425672 秒；context 查询平均
0.048166 秒，原 voter 0.087694 秒，candidate 0.046356 秒。
地球约 2.82 MiB 状态的完整 pack/两次 canonical 编码与 body 扫描，各样本共约 0.042 秒。
这些非并发测量未计磁盘 fsync、锁竞争及真实进程负载，不能确定唯一失败原因。

## 实现边界

`JointEpoch.advance` 仍执行原有当前 Native membership、初始化/恢复、outbox 和新 voter
完整原生签名头检查。普通循环只把刚完成的这一次检查，以不可变完整 canonical 字节，
交给同一 `Runtime._tick` 的局部操作对象。直接 `tick`、startup、incoming activation、
角色 handoff 及其他调用仍走原有接口；没有跨循环缓存、持久化或恢复该观测。

观测同时绑定 Runtime 对象、该次私有操作对象、完整 signing binding 和完整 caller head。
两份字节合计上限仍为 8 MiB。其他 Runtime/操作、caller pending/outbox/初始化或 binding
变化、限额收紧及超容量均回到原来的完整新查询；没有未核验数据的签名回退。
无 Native journal 的 keyless Python 状态不产生这种观测。

每次 `sign` 仍先执行原有新 Native signer/head 查询，并在 Native 原子签名路径中检查
exact expected head、当前会员、时代、锁、完整 owner/value/evidence。观测只用于本轮
调度和本地诊断，绝不授权签名、同步、证书、账本或 caller-head 采用。每个 incoming 完整
信封仍先通过原有 Native 认证；未更改 dedup 或 receipt/custody 规则。

## 资格状态

实际 Native fixture 回归覆盖每轮仅一次 active-head 查询且下一轮重新查询、scope/head
变化、收紧限额/超容量、实际 Native signer 头提前变化时拒绝 first-sign，以及真实 Runtime
cold reopen。新默认 driver 的精确重建、完整过程检查及全新普通循环/故障/cold 资格仍待
分别完成；这些局部回归不能代替它们。新 Python 运行时需要全新私有无价值范围。
旧失败源、报告和私有现场保持；不迁移 value/custody，不放宽期限、容量、成熟或票数。
I1–I12、独立保管、长期历史和真实星际物理链路仍未完成。
