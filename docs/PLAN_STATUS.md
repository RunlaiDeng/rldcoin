# RLDCOIN 当前交付状态

更新：2026-10-04。当前只开发全新签署的无价值地面测试候选；退役主网及旧测试余额不迁移。
项目总目标与 I1–I12 保持：[完整主计划](RLDCOIN_MASTER_PLAN.md)；默认节点网络 N1–N10：
[接触中继要求](research/INTERSTELLAR_NODE_MESH_REQUIREMENTS.md)。这些条件尚未全部完成。

## 当前唯一近期交付

同一冻结实现的普通三地区付款返程、原定完整有限故障范围、严格停止后冷核验全部通过。
保持既有阶段时限、成熟高度、法定票数和容量。测试数量、组件查询速度和运输回执不替代付款资格。

当前运行的是新 Native 同次持锁状态观测候选，源码集合
`f49c183bb61a4a0a8871c81e9707b1a7830cb803fa4905f1d63d03e7d7989feb`，
使用全新 genesis/货币。当前普通三地区返程已实际通过，用时 916.479 秒；严格停止
冷核验用时 69.903 秒，12 Native/12 收款/4 时代保管及 1,760 运输档案完整核验通过，
私有字节/权限保持。原定完整有限故障范围实际用时 895.062 秒，接触恢复后的付款导入与成熟关卡再次失败。
原定 24 高度、每阶段 600 秒和实际 60 秒轮超时保持；所有节点停止，失败状态保留。
严格停止核验已认证 12 Native、1,838 完整 BFT 信封、4,117 运输档案及 4 时代保管，
所有私有字节/权限不变；三份原始 owner 请求均已包含，预留为零，没有替换或退款。

## 已确认的证据与当前阻塞

| 范围 | 实际结果 | 判定 |
| --- | --- | --- |
| 前一冻结实现普通三地区返程 | 12 个节点；地球停机时继续 onward；原始扣款保留；停止冷核验、12 接收检查及 4 时代保管检查通过 | 同机有限地面样本通过 |
| 前一实现完整有限故障范围 | 缺失 leader、隔离期间当地付款、离线节点恢复通过；接触恢复后比邻星新出口未导入 | **整个故障范围失败，原件保留** |
| 失败范围停止核验 | 12 Native 完整重放、1,996 完整 BFT 信封、4,424 档案及 4 时代保管检查；私有字节/权限不变 | 确认失败状态，不能改计通过 |
| 当前实现普通返程与严格冷核验 | 12 节点/12 收款/4 时代保管、全部运输档案认证及守恒通过 | 同机有限样本通过；完整故障范围失败 |
| 当前 Native 候选检查 | 精确重建、strict、184 Native、完整 480 过程与 3 真实 Runtime 保管检查实际通过 | 组件及回归通过；完整交付待验证 |

当前单一阻塞是故障恢复后的比邻星支付进展：这次四份原生账本均停在高度 10，
新出口证据已认证，尚未导入；原始 owner 请求已包含。当前父级 16 份本地签署消息中，
一份进入下一轮所需的超时消息只留在发送者，三个目的节点都无完整消息及目的收件。
其余 15 份已完整交付。前一实现停在高度 12 的失败仍独立保留，不混计为同一次样本。

当前实验：四个真实进程、全新 mesh/TLS 目录，用原有认证消息构造历史运输负载，
检查这份关键超时消息交付及原生认证。原失败账本只用于只读认证，绝不启动 Runtime、
恢复响应、首次签署、安装账本或迁移价值。若运输试验通过，则该负载假设被削弱，
继续定位普通运行中的具体延迟；若失败，先证明最小修复在同一复现中通过，再运行完整资格。
当前进程仅 6 次候选试算、总耗时约 0.34 秒，不支持历史提交试算是主要瓶颈；不据此补丁。

冻结清单沿用了错误的 20 秒轮超时描述，12 份实际配置与普通报告均为 60 秒。
[精确配置哈希说明](operations/evidence/regional-current-round-timeout-metadata-20261004.json)
保留冻结清单原字节；这项元数据错误不改变实际运行规则或授予任何资格。

## 开发与发布边界

审阅过的稳定源码基线及当前 Native 修复已分别提交到主开发仓库。明确文件清单排除
临时实验、构建输出、生成密钥、钱包、节点、签署人、caller-head、运输及 TLS 私有状态。
当前运行实验使用冻结目录，不受主仓库整理影响。公开仓库仍停在已验证的 v55；
待发布 v56 材料已逐字节保存为本地延后材料，不发布每个微优化或失败变体。
完成当前交付后，整理一次有完整证据的稳定成果，再推进其余工程与外部资格门槛。

完整证据保存在 `docs/operations/evidence/`：
`regional-joint-loop-retry1-three-region-cycle-20261004.json`、
`regional-joint-loop-retry1-three-region-cold-20261004.json`、
`regional-joint-loop-retry1-joint-fault-fresh-20261004.json`、
`regional-joint-loop-retry1-joint-fault-failed-cold-observations-20261004.json`、
`regional-joint-loop-retry1-fault-current-proxima-path-observations-20261004.json`、
`regional-bft-open-status-frozen-checks-20261004.json`、
`regional-bft-open-status-three-region-cycle-20261004.json`、
`regional-bft-open-status-three-region-cold-20261004.json`、
`regional-bft-open-status-joint-fault-fresh-20261004.json`、
`regional-bft-open-status-joint-fault-failed-cold-observations-20261004.json`、
`regional-bft-open-status-joint-fault-owner-head-observations-20261004.json`、
`regional-bft-open-status-fault-current-proxima-path-observations-20261004.json`。

此前详细历史已原样归档：[历史状态记录](operations/history/PLAN_STATUS_before_delivery_focus_20261004_8403d16a68dc.md)。
归档 SHA-256：`8403d16a68dc6adbd2be3afdfd1afda843ac1cfd0e1a6e114912457465db203c`。所有历史失败、签署证据及私有目录继续保留。
