# RLDCOIN 当前交付状态

更新：2026-10-04。仅全新无价值地面测试候选；退役主网、旧余额和失败保管不迁移。
总目标：[I1–I12 完整主计划](RLDCOIN_MASTER_PLAN.md)；
默认网络：[N1–N10 接触中继要求](research/INTERSTELLAR_NODE_MESH_REQUIREMENTS.md)。均未全部完成。

## 当前唯一近期交付

**同一冻结实现：普通三地区付款返程、原定完整有限故障范围、严格停止冷核验全部通过。**
保持原成熟高度、票数、容量、24 高度上限、600 秒阶段窗口和实际 60 秒轮超时。
组件速度、运输收件和测试数量均不替代付款资格。

## 已有资格与失败原件

运行来源 `7c5b78c85d1b50640ce2d783fd752d7c818387e9be4ddcae3bb208003d4c4c61`，
387 份完整清单；Native/core 与此前已核验源码逐字节相同，默认启动程序精确重建。
运输修复及六项冷启动/锁回归已按明确清单合入 `06660aa`，未发布。

| 检查 | 实际结果 | 判定 |
| --- | --- | --- |
| 冻结回归 | 486 过程检查、3 实际 Runtime 保管阶段通过；184 Native/strict 引用相同 Native/core 的既有证据 | 回归通过 |
| 普通三地区返程 | 743.120 秒；12 原生、12 收款、4 时代保管、1,728 档案冷核验；issued/liquid 300、in_transit 0 | 同机有限循环通过 |
| 原定完整有限故障范围 | 912.029 秒；缺席 leader、隔离当地付款、追赶通过；恢复后新出口未在 600 秒内导入成熟 | **整个范围失败，原件保留** |
| 失败范围严格停止核验 | E14/P12/A16；12 原生、1,989 完整 BFT 信封、4,369 档案、4 时代保管通过，私有字节/权限不变 | 核验失败状态，不替代资格 |
| 三份原始 owner 请求 | INCLUDED_IN_LOCAL_LEDGER、预留零；各自独立最新头及签署高度重放匹配 | 不替换，不退款 |

四个 Proxima 收款检查均为 VERIFIED_EVIDENCE_PENDING_IMPORT，未导入、成熟或可花费。
兼容前缀守恒 issued 300 / liquid 290 / pending_exports 10；Native 候选试算不足半秒。

## 当前阻塞与本轮结论

已认证外层请求仍会在打开本地存储前耗尽原 0.2 秒锁等待；外层认证不代表完整
运输或原生认证。实际 OS 锁记录、多跳有限压力及失败状态均保留，不改时限或资格。

本轮真实双进程对照确认两处局部问题：

- 对称区分接收/发送意图：旧候选的发送轮询可消耗已失败接收意图；新候选拒绝抢先
  轮询，实际接收复核和完整 Native 认证通过。保留实际 TLS、锁及 0.35 秒诊断 CPU 条件。
- 延迟输入占满原两入站槽会关闭第三次 TLS 连接；候选将延迟输入限制为其中一个槽，
  第三次请求完成真实挑战/签名拒收认证。两者都不确认保管，发送原包完整保留，
  实际延迟落盘/Native 检查通过。总容量仍为两槽，已持久化签名证据完整保留。
- 新组合的实际双进程发送意图回归通过：抢先接收拒绝、实际排入及 Native 认证通过。

三个相同四进程压力范围都失败：同一观察工具、40 种完整 Native 证据、每节点 40 输入，
所有进程正常停止；原 60 秒轮和 120 秒诊断观察不变。非对称候选最近目标 80.136 秒，
对称候选 8.303 秒，预留接入槽候选 43.427 秒完成 Native 认证；各自两个远端均未在
普通运行观察中完成。这些同机样本不是可外推的性能基准或完整付款故障资格。

预留槽候选减少了实际 TLS 接入失败，但原发送方仍有 8 次关键签名拒收，中继只有
2 次关键批次转送。中继向下一跳的两次关键请求均外层认证后在打开存储前耗尽等待，
下一跳队列当时是否可保留它们尚未记录，不推断。需检查实际延迟输入准入、重试和
普通/发送/接收轮转；单个修复不合入、不发布，也不启动完整资格范围。

12 份停止运输存储通过完整 Mesh 检查，其中关键完整信封通过 Native 检查；
私有字节/权限不变。只核验关键 Native 信封，未声称所有 BFT 或完整故障冷核验通过。
所有失败原件保留；排队、签名拒收、下一跳保管、目的回执及限时 Native 接收分开记录。

## 证据与发布边界

主资格证据：`operations/evidence/regional-fair-carriage-source-inventory-20261004.json`、
`regional-qualified-fair-carriage-frozen-checks-20261004.json`、
`regional-fair-carriage-three-region-cycle-20261004.json`、`regional-fair-carriage-three-region-cold-20261004.json`、
`regional-fair-carriage-joint-fault-fresh-20261004.json`、`regional-fair-carriage-joint-fault-failed-cold-observations-20261004.json`、
`regional-fair-carriage-joint-fault-owner-head-observations-20261004.json`。
本轮：`operations/evidence/regional-open-inbound-slot-diagnostic-summary-20261004.json`、
`regional-open-inbound-slot-stopped-review-20261004.json`。
此前诊断和来源：[原样保留状态](operations/history/PLAN_STATUS_before_open_inbound_slot_20261004_f28669c4f4a8.md)。

公开仓库仍为已验证 v55；v56 材料完整延后保存。不发布微优化或失败变体。
失败状态、签署证据及私有头不改变；不恢复失败范围为通过、不迁移价值、不提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。
