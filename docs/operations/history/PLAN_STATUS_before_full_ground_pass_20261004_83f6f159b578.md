# RLDCOIN 当前交付状态

更新：2026-10-04。仅全新无价值地面测试候选；退役主网、旧余额和失败保管不迁移。
总目标：[I1–I12 完整主计划](RLDCOIN_MASTER_PLAN.md)；
默认网络：[N1–N10 接触中继要求](research/INTERSTELLAR_NODE_MESH_REQUIREMENTS.md)。均未全部完成。

## 当前唯一近期交付

**同一冻结实现：普通三地区付款返程、原定完整有限故障范围、严格停止冷核验全部通过。**
保持原成熟高度、票数、容量、24 高度上限、600 秒阶段窗口和实际 60 秒轮超时。
组件速度、运输收件和测试数量均不替代付款资格。

## 已有资格基线与失败原件

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

## 当前实现与正在验证的范围

当前候选运行来源 `8831a6348cbb08772d09f302ea2620a595b0b97b13d9d6e90fc0c3e90c140199`，
388 份完整冻结清单，Native/core 逐字节未变；默认启动程序精确重建，构建 37.96 秒。
已通过并按明确文件清单合入主目录以供审阅，未发布：

- 真实 Runtime 双进程对照：旧候选重复广播重新占锁并拒收入站；新候选在所有完整
  原生信封/收件方副本已持久化后避开空读取，入站落盘、目的回执及 Native 认证通过。
  实际构造全新 Native Runtime，签署头不变、记录零；未调用共识 tick 或首次签署。
- 完全相同且已确认完整排入的原生信封/收件方清单可暂缓空读取；只有进程内有界
  调度提示。变化、容量、失败、重启、四秒或十六次定期复查均走完整 Mesh 路径。
  每份后来接收的完整证据、依赖/时代同步及新鲜 Native 头/签署检查继续强制执行。
- 真实启动失败过程对照：旧消费者在构造失败后仍存活；新候选停止并加入实际启动
  的线程。接收/发送意图区分、原两槽内至多一个未确认延迟输入及活消费者重试一并保留。
- 五项针对性检查以及 **491 项完整过程回归、三个实际 Runtime 保管阶段全部通过**。
  Native 的 184 项测试/strict 检查引用相同 Native/core 的既有证据，本轮明确未重跑。

全新普通三地区付款返程 **673.309 秒通过**，干净停止与严格冷核验 **60.350 秒通过**。
E11/P4/A4 四副本一致；12 原生重放、12 收款、4 时代保管、788 完整 BFT 信封及
1,744 档案核验通过。兼容前缀守恒 issued/liquid 300、in_transit 0，私有字节/权限不变。
已从这份成功停止样本开启同一源码的原定完整有限故障范围；故障终止及冷资格仍未证明。
旧失败目录、支付、保管和证据均未改写或迁移；没有恢复旧失败范围或计作通过。

此前运输四进程诊断本身未调用本次修改的 `Runtime.broadcast`，仍保留原失败判定，
没有补记为压力通过；不靠改写该模型证明修复。当前资格取决于完整真实 Runtime
回归及新普通/故障范围，不提高原成熟高度、票数、容量、24 高度上限或 600/60 秒窗口。

## 证据与发布边界

主资格证据：`operations/evidence/regional-fair-carriage-source-inventory-20261004.json`、
`regional-qualified-fair-carriage-frozen-checks-20261004.json`、
`regional-fair-carriage-three-region-cycle-20261004.json`、`regional-fair-carriage-three-region-cold-20261004.json`、
`regional-fair-carriage-joint-fault-fresh-20261004.json`、`regional-fair-carriage-joint-fault-failed-cold-observations-20261004.json`、
`regional-fair-carriage-joint-fault-owner-head-observations-20261004.json`。
本轮：`operations/evidence/regional-qualified-quiet-broadcast-component-summary-20261004.json`、
`regional-qualified-quiet-broadcast-frozen-checks-20261004.json`、`regional-qualified-quiet-broadcast-source-inventory-20261004.json`。
普通范围：`regional-quiet-broadcast-three-region-cycle-20261004.json`、
`regional-quiet-broadcast-three-region-cold-20261004.json`。
此前诊断和来源：[原样保留状态](operations/history/PLAN_STATUS_before_qualified_quiet_broadcast_20261004_1a0a9f7774e5.md)。

公开仓库仍为已验证 v55；v56 材料完整延后保存。不发布微优化或失败变体。
失败状态、签署证据及私有头不改变；不恢复失败范围为通过、不迁移价值、不提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。
