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
运输或 Native 认证。对称接收/发送意图、保留一个接入槽的局部双进程对照均通过，
组合仍未通过原 60 秒多跳压力门槛。既有失败原件与原定付款资格保持不变。

本轮补充实际排队记录，读取真实追加、选取和 handler 终止结果，未改变运行实现：
三个目标 Native 认证为 63.211 / 61.979 / 5.896 秒。所有每节点 40 输入完成，进程
正常停止，但仍超过原 60 秒门槛。节点 2 的三个关键拒收对应另一个非关键完整输入
占着唯一延迟槽；后续关键请求成功排队或直接落盘。完整记录均低于原 512 事件界限。

随后真实双进程原始锁/重试对照确认：延迟消费者耗尽锁等待后丢失需求，普通线程
可以抢先重新占锁，导致原输入再次拒收。候选仅为实际存活、仍持有原始未确认输入
的消费者保留需求；普通线程先行尝试拒绝，实际接收落盘、目的回执及完整 Native
认证通过。诊断屏障仅放在原有有界拒收之后，不是完整故障或独立资格。发送方仍保留
原包、没有采纳回包保管或目的回执；输入终止及实际停机清除需求，未提高容量或时限。

相同四进程/40 种完整证据/每节点 40 输入的候选压力仍失败：最近目标约 4.798 秒
完成 Native 认证，两远端未完成；全部进程正常退出。下一跳关键请求未排队或落盘时，
确有一个其他完整输入在延迟槽中；候选增加了该消费者获得机会，未解决完整多跳门槛。
不将旧候选这次约 63 秒的全到达或本次局部修复补算为 60 秒、付款或完整故障通过。

八份停止运输存储通过完整 Mesh 检查，其中关键完整信封通过 Native 检查；私有
字节/权限不变。仅核验关键 Native 信封，未声称所有 BFT 或完整故障冷核验通过。
候选未合入、未发布，未开启新的完整资格范围。下一步需验证普通循环中已无待发项的
重复存储复核是否仍占用接收所需锁；`Runtime.broadcast` 当前先打开完整 Mesh 再判断
无待发项。应以真实过程对照证明变化，保持完整证据认证及重启/故障保管要求。

## 证据与发布边界

主资格证据：`operations/evidence/regional-fair-carriage-source-inventory-20261004.json`、
`regional-qualified-fair-carriage-frozen-checks-20261004.json`、
`regional-fair-carriage-three-region-cycle-20261004.json`、`regional-fair-carriage-three-region-cold-20261004.json`、
`regional-fair-carriage-joint-fault-fresh-20261004.json`、`regional-fair-carriage-joint-fault-failed-cold-observations-20261004.json`、
`regional-fair-carriage-joint-fault-owner-head-observations-20261004.json`。
本轮：`operations/evidence/regional-retained-input-demand-diagnostic-summary-20261004.json`、
`regional-retained-input-demand-stopped-review-20261004.json`。
此前诊断和来源：[原样保留状态](operations/history/PLAN_STATUS_before_retained_input_demand_20261004_c6dc8278ebc6.md)。

公开仓库仍为已验证 v55；v56 材料完整延后保存。不发布微优化或失败变体。
失败状态、签署证据及私有头不改变；不恢复失败范围为通过、不迁移价值、不提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。
