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

关键包实际选入发送批次仍遭拒收。已认证外层请求会在打开本地存储前，因普通或发送
线程占用、保留调度意图而耗尽原 0.2 秒等待；外层认证不代表完整运输或原生认证。
分层轮转、重试、CPU/socket 边界、活线程准入及观察轮询的有限诊断均独立保留。
局部检查通过不算完整压力或故障通过；未合入这些候选，也未启动新的完整资格范围。

新增四进程实际锁记录确认：普通、发送、接收的锁占用多为 0.4–0.7 秒；
13 个关键拒收等待中，8 个完整等待窗可直接匹配实际 OS 锁占用。记录上限 128，
已明确披露逐进程淘汰数量；未知区间不推断，嵌套组件耗时不可相加。

两项真实双进程对照已通过，但组合仍未通过压力门槛：
- 原始锁争用下，两次真实 TLS 请求都明确拒收；异步候选约 0.623 秒后真实落盘及原生认证，
  发送方保留原包且没有本地回包保管或目的回执。内存输入共用原两入站槽，排队不确认保管。
- 原已失败发送的意图被下轮接收轮询消耗；区分意图的候选拒绝抢先轮询，并完成实际排入、
  停止运输及完整原生认证。真实 TCP 等待者和 0.35 秒诊断 CPU 边界明确记录，不是完整故障资格。

相同四进程、40 种完整证据、每节点 40 输入压力仍失败：异步候选最近目标 102.549 秒
完成原生认证、两远端未完成；组合候选三个目标均未在普通运行观察中完成。所有输入
排入、进程正常停止。停止后八份存储和其中关键完整原生证据检查通过，私有字节/权限
不变；两远端仍无目的回执。停止时最近目标的有效收件不能补记为限时普通接收通过。

候选不合入、不发布。需继续检查两类调度意图是否都能获得机会，以及新接收队列占槽
后请求在哪个 socket 阶段失去回包；没有认证回包本身不能定位 TLS/请求/回包故障。
异步长期消费者的旧诊断线程字段可能残留，未用于精确拒收归因；实际收件字节和独立
发送阶段记录分开核验。不提高时限、容量、票数或成熟高度，不剪除签署证据。

## 证据与发布边界

主资格证据：`operations/evidence/regional-fair-carriage-source-inventory-20261004.json`、
`regional-qualified-fair-carriage-frozen-checks-20261004.json`、
`regional-fair-carriage-three-region-cycle-20261004.json`、`regional-fair-carriage-three-region-cold-20261004.json`、
`regional-fair-carriage-joint-fault-fresh-20261004.json`、`regional-fair-carriage-joint-fault-failed-cold-observations-20261004.json`、
`regional-fair-carriage-joint-fault-owner-head-observations-20261004.json`。
本轮：`operations/evidence/regional-lock-section-timeline-summary-20261004.json`、
`regional-deferred-carriage-diagnostic-summary-20261004.json`、`regional-deferred-carriage-stopped-review-20261004.json`。
此前诊断和来源：[原样保留状态](operations/history/PLAN_STATUS_before_deferred_carriage_20261004_5fb9b0653c54.md)。

公开仓库仍为已验证 v55；v56 材料完整延后保存。不发布微优化或失败变体。
失败状态、签署证据及私有头不改变；不恢复失败范围为通过、不迁移价值、不提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。
