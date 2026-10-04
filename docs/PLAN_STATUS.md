# RLDCOIN 当前交付状态

更新：2026-10-04。仅全新无价值地面测试候选；退役主网、旧余额和失败保管不迁移。
总目标：[I1–I12 完整主计划](RLDCOIN_MASTER_PLAN.md)；
默认网络：[N1–N10 接触中继要求](research/INTERSTELLAR_NODE_MESH_REQUIREMENTS.md)。均未全部完成。

## 当前唯一近期交付

**同一冻结实现：普通三地区付款返程、原定完整有限故障范围、严格停止冷核验全部通过。**
保持原成熟高度、票数、容量、24 高度上限、600 秒阶段窗口和实际 60 秒轮超时。
组件速度、运输收件和测试数量均不替代付款资格。

## 当前证据与阻塞

冻结来源 `7c5b78c85d1b50640ce2d783fd752d7c818387e9be4ddcae3bb208003d4c4c61`，
387 份完整清单。Native/core 与先前已核验源码逐字节相同；默认启动程序精确重建。
运输修复及六项冷启动/锁回归已按明确清单合入主仓库 `06660aa`；未发布。

| 检查 | 实际结果 | 判定 |
| --- | --- | --- |
| 固定排队输入、四真实进程 | 旧实现 120 秒未交付；候选全部 40 输入/节点完成排入，控制标记至三个目标原生认证最多 31.367 秒 | 最小运输修复通过，非完整故障资格 |
| 最终冻结回归 | 486 过程检查及 3 实际 Runtime 保管阶段通过；184 Native/strict 明确引用相同 Native/core 的先前证据 | 回归通过 |
| 同来源普通三地区返程 | 743.120 秒；地球离线期间 onward/返程；12 原生、12 收款、4 时代保管及 1,728 档案冷核验通过；issued/liquid 300、in_transit 0 | 同机有限普通循环通过 |
| 原定完整有限故障范围 | 912.029 秒；缺席 leader、隔离当地付款、离线追赶通过；接触恢复后新出口未在 600 秒内导入成熟 | **整个范围失败，原件保留，不恢复为通过** |
| 失败范围严格停止核验 | 高度 Earth 14/Proxima 12/Andromeda 16；12 原生、1,989 完整 BFT 信封、4,369 档案、4 时代保管通过；私有字节/权限不变 | 核验失败状态，不替代资格 |
| 原始 owner 请求 | 三份均 INCLUDED_IN_LOCAL_LEDGER、预留零；各自最新独立头及签署高度重放匹配 | 不替换，不退款 |

当前四个 Proxima 收款检查均为 VERIFIED_EVIDENCE_PENDING_IMPORT，未导入、未成熟、
不可花费。最高兼容前缀守恒 issued 300 / liquid 290 / pending_exports 10。
Native 候选试算总耗时不足半秒，不据此猜测修补试算速度。

当前父级 12 的 11 份本地签署信封、33 个目的副本中，24 份已完整交付。
Proxima-2 的 Commit 在发送端有 132 秒日志观测，仍未交付 Proxima-0/1；
同一 Prepare 的远端副本经 Proxima-1 到达 Proxima-0，发给 Proxima-1 自身的副本却未到。
源/目的日志并非同时采样，负时差不能解释为逆因果，也不能把短观测窗当永久停滞。
多种完整原生证据的四真实进程压力对照均失败：原版、分层目的地轮转、
新旧帧交替以及本地 CPU 时限修复均未在原 60 秒内完成所有目标，未启动新的完整资格范围。
这些试验和私有现场独立保留；分层轮转的单项通过不计为实际转发通过。

另外，两独立进程用同一个精确包复现了已收到的认证请求在完整本地验证超过 socket
时限后被拒绝落盘。局部候选移除验证完成后的 socket 时限检查，并在每次锁尝试前
拒绝过期准入；旧版无保管，新版 3.434 秒后真实落盘及原生认证。3 秒 socket、
0.2 秒锁等待不变；发送端超时、无回执、原包保留。三项专项回归旧版两项失败、新版
全部通过。这是注入时序边界的有限对照，候选未合入主运行代码，不能宣称已解决完整阻塞。
提前登记仍活着的入站线程调度需求也通过相同精确包的双进程边界对照：旧版重复
普通处理后拒绝入站；新版 0.367 秒完成实际落盘、原生认证及发送端持久回执。
29 项现有 TCP 回归通过；原多证据压力对照仍失败，候选未合入。
诊断脚本曾在接收争用后跳过后续发送，真实服务却继续原生与发送阶段；已保留原结果，
新对照按真实服务分离阶段，并保留接收争用的原调度意图。先验证这个修正模型，
再定位未交付路径；相同输入实际旧失败/新通过之后才能进入完整回归与资格。

## 开发与发布边界

公开仓库仍为已验证 v55；v56 材料完整延后保存，当前不发布微优化或失败变体。
失败状态、旧冻结包、所有签署证据和私有头原样保留。无 Runtime 重启失败账本、
无恢复首次签署、替换原始付款、退款、迁移价值、提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。

完整当前证据：`docs/operations/evidence/regional-fair-carriage-source-inventory-20261004.json`、
`regional-qualified-fair-carriage-frozen-checks-20261004.json`、
`regional-fair-carriage-three-region-cycle-20261004.json`、
`regional-fair-carriage-three-region-cold-20261004.json`、
`regional-fair-carriage-joint-fault-fresh-20261004.json`、
`regional-fair-carriage-joint-fault-failed-cold-observations-20261004.json`、
`regional-fair-carriage-joint-fault-owner-head-observations-20261004.json`、
`regional-fair-carriage-fault-current-proxima-path-observations-20261004.json`、
`regional-fair-carriage-fault-log-timeline-20261004.json`。

此前详史：[原样历史记录](operations/history/PLAN_STATUS_before_delivery_focus_20261004_8403d16a68dc.md)。
本轮诊断详史：[此前状态原文](operations/history/PLAN_STATUS_before_fair_carriage_fault_result_20261004_2fb5b6d7e1ec.md)。
原失败 f49 来源及更早失败均独立保留，不混计为本次样本。
新增诊断汇总：`operations/evidence/regional-carriage-late-custody-and-diverse-pressure-summary-20261004.json`。

入站边界与模型校核：`operations/evidence/regional-live-inbound-demand-boundary-summary-20261004.json`。
