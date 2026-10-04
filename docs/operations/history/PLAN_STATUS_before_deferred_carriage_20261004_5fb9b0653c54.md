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

本轮原生空闲窗口候选在同一精确包、两个真实进程中复现旧失败/新通过：接收一份完整
请求后实际落盘及原生认证，第二份拒绝，普通线程随后正常继续。发送端只核验回包，
没有本地回包保管或目的回执，原包保留。socket 3 秒、锁等待 0.2 秒不变。
相同 40 种完整证据、四进程压力对照仍失败：旧版三个目标均未完成；候选最近目标
69.303 秒完成原生认证，另两目标未完成。双方每节点 40 输入全部排入、进程正常停止。
停止核验八份运输存储通过；完整关键原生信封核验通过，所有私有字节/权限不变。
源和最近中继仍保留发往两个远端的原包，两个远端均没有目的回执。
候选不合入、不发布。实际 Node 打开采样显示热态成本主要在活动图解码/展开和完整
传输身份检查；采样含额外开销，不当成实时延迟或吞吐证明。下一步量出实际
普通/发送/接收操作的锁持有区间，先证明对应真实输入旧失败/新通过，再完整资格。

## 证据与发布边界

主资格证据：`operations/evidence/regional-fair-carriage-source-inventory-20261004.json`、
`regional-qualified-fair-carriage-frozen-checks-20261004.json`、
`regional-fair-carriage-three-region-cycle-20261004.json`、`regional-fair-carriage-three-region-cold-20261004.json`、
`regional-fair-carriage-joint-fault-fresh-20261004.json`、`regional-fair-carriage-joint-fault-failed-cold-observations-20261004.json`、
`regional-fair-carriage-joint-fault-owner-head-observations-20261004.json`。
本轮：`operations/evidence/regional-native-idle-admission-summary-20261004.json`、
`regional-native-idle-admission-stopped-review-20261004.json`、`regional-native-idle-stopped-mesh-open-cost-20261004.json`。
此前诊断和来源：[原样保留状态](operations/history/PLAN_STATUS_before_native_idle_result_20261004_fd5fa9f7b1a2.md)。

公开仓库仍为已验证 v55；v56 材料完整延后保存。不发布微优化或失败变体。
失败状态、签署证据及私有头不改变；不恢复失败范围为通过、不迁移价值、不提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。
