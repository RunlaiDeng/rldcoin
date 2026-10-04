# RLDCOIN 当前交付状态

更新：2026-10-04。仅全新无价值地面测试候选；退役主网、旧余额和失败保管不迁移。
总目标：[I1–I12 完整主计划](RLDCOIN_MASTER_PLAN.md)；
默认网络：[N1–N10 接触中继要求](research/INTERSTELLAR_NODE_MESH_REQUIREMENTS.md)。均未全部完成。

## 已完成的近期交付

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

## 当前通过实现与验证范围

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
原定完整有限故障范围 **881.112 秒通过**，严格停止冷核验 **240.974 秒通过**。
缺席 leader、隔离当地付款、追赶、新出口唯一导入成熟及暂停签署排空均通过。
E13/P15/A14 四副本一致；12 原生、4 新收款、4 时代保管、1,934 完整 BFT 信封、
4,268 档案通过，守恒 300/300/0，私有文件不变。**本轮唯一近期交付已经完成。**
旧失败目录、支付、保管和证据均未改写或迁移；没有恢复旧失败范围或计作通过。
后续按 [资源预算与剩余门槛](operations/GROUND_RESOURCE_AND_GATE_MATRIX.md) 推进；
一次有限故障成功不资格持续负载、长期历史、独立/跨设备保管或物理路线。

此前运输四进程诊断本身未调用本次修改的 `Runtime.broadcast`，仍保留原失败判定，
没有补记为压力通过；不靠改写该模型证明修复。当前资格取决于完整真实 Runtime
回归及新普通/故障范围，不提高原成熟高度、票数、容量、24 高度上限或 600/60 秒窗口。

白皮书已按用户要求完成本地 **1.12** 修订，网页/PDF 标签同步；23 页 PDF 逐页版面、
现有网站测试、类型检查、生产构建及本地桌面/移动显示通过。主计划对应版本同步，
没有发布、部署或改写任何冻结运行来源；文档对齐不提供 I1–I12 的完整资格。

第 1 个后续门槛已有[资源采集契约](operations/GROUND_RESOURCE_CAPTURE_CONTRACT.md)与
独立只读采集工具；15 项检查及 2.275 秒实际 CLI 诊断通过，完整来源/二进制字节绑定，
三个进程/存储样本、私有日志关联和原目录 7,219 份文件元数据不变均已核验。
诊断进程是本次拥有的短命 sleep 子进程，存储为一个停止的通过样本目录；
没有启动节点或 Native，没有新增持续负载资格。原生价值、每跳字节和完整短命子进程
覆盖仍待接入；明确保留未知和采样间隙，不将样本最大值当作持续峰值。

随后接入有限故障控制器的原生价值审计（原十二 status/三 proof 调用不增加）：
完整认证响应与兼容检查点关联，分别记录未交付毛额/净额，拒绝重复或不匹配导入。
原生/流/资源 29 项、相关控制器 23 项、度量绑定 6 项检查通过；真实停止样本的
15 次原生读取通过，300/300/0 与全部 7,219 份私有文件字节/权限不变。
显式全跳计量使用独立冻结控制器来源 `20d5427a2547fdb699cca679aec152136b3e2a756f044a082a0347a21891e2a7`，
节点来源/二进制未变。新增 22 配置方向有限故障**失败**：净额 9 已在 P13 导入，
停止 P14 未达到成熟 P15，原 600 秒内未成熟。严格停止检查 240.425 秒通过，
覆盖 12 原生、4 收款、4 时代保管、1,990 完整信封及 4,317 档案，私有字节/权限不变。
92 个十秒资源样本与全部 22 方向累计流计量已关联；单进程 RSS 采样最大约 786.7 MiB，
主进程 CPU/存储观察不覆盖完整 Native 子进程或全节点成本。
后续采集器 V2 可显式观察主进程加已退出子进程 CPU，真实父进程和 47 项组件/日志
检查通过；尚未接入旧运行，也不覆盖完整活跃子进程 CPU/RSS 或持续负载。
停止 Native/薄路径同步/分配探针已经完成，否定完整帧 witness 的高 RSS 猜测；
下一活动假设、单次新范围预算与退出分支见
[成本判别](operations/GROUND_RESOURCE_COST_DECISION_20261004.md)，先补实时普通承载链。
原范围与旧失败保持原判定；见[实际度量与剩余缺口](operations/GROUND_RESOURCE_METRICS_FINDINGS_20261004.md)。

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
故障范围：`regional-quiet-broadcast-joint-fault-fresh-20261004.json`、
`regional-quiet-broadcast-joint-fault-cold-20261004.json`；资源：`regional-quiet-broadcast-ground-resource-baseline-20261004.json`。
资源采集组件：`regional-ground-resource-capture-checks-20261004.json`，不替代新增负载范围。
原生/流接入组件：`regional-ground-value-stream-components-20261004.json`；
冻结控制器清单：`regional-ground-metered-controller-source-20261004.json`。
新增计量失败范围、资源、严格停止检查及来源关联见
[度量发现与完整证据清单](operations/GROUND_RESOURCE_METRICS_FINDINGS_20261004.md)。
此前诊断和来源：[原样保留状态](operations/history/PLAN_STATUS_before_qualified_quiet_broadcast_20261004_1a0a9f7774e5.md)。

公开仓库仍为已验证 v55；v56 材料完整延后保存。不发布微优化或失败变体。
失败状态、签署证据及私有头不改变；不恢复失败范围为通过、不迁移价值、不提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。
