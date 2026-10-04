# RLDCOIN 当前交付状态

更新：2026-10-04。当前只开发全新签署的无价值地面测试候选；退役主网及旧测试余额不迁移。
项目总目标与 I1–I12 保持：[完整主计划](RLDCOIN_MASTER_PLAN.md)；默认节点网络 N1–N10：
[接触中继要求](research/INTERSTELLAR_NODE_MESH_REQUIREMENTS.md)。这些条件尚未全部完成。

## 当前唯一近期交付

同一冻结实现的普通三地区付款返程、原定完整有限故障范围、严格停止后冷核验全部通过。
保持既有阶段时限、成熟高度、法定票数和容量。测试数量、组件查询速度和运输回执不替代付款资格。

当前运行的是新 Native 同次持锁状态观测候选，源码集合
`f49c183bb61a4a0a8871c81e9707b1a7830cb803fa4905f1d63d03e7d7989feb`，
使用全新 genesis/货币。普通三地区实验已推进地球与比邻星出口、地球停机后的 onward，
正在运行仙女座付款与返程。先完成该实验及严格冷核验，成功后才启动同一冻结实现的
原定完整有限故障范围。全过程不再并行运行重型测量或重复实验。

## 已确认的证据与当前阻塞

| 范围 | 实际结果 | 判定 |
| --- | --- | --- |
| 前一冻结实现普通三地区返程 | 12 个节点；地球停机时继续 onward；原始扣款保留；停止冷核验、12 接收检查及 4 时代保管检查通过 | 同机有限地面样本通过 |
| 前一实现完整有限故障范围 | 缺失 leader、隔离期间当地付款、离线节点恢复通过；接触恢复后比邻星新出口未导入 | **整个故障范围失败，原件保留** |
| 失败范围停止核验 | 12 Native 完整重放、1,996 完整 BFT 信封、4,424 档案及 4 时代保管检查；私有字节/权限不变 | 确认失败状态，不能改计通过 |
| 当前 Native 候选检查 | 精确重建、strict、184 Native、完整 480 过程与 3 真实 Runtime 保管检查实际通过 | 组件及回归通过；完整交付待验证 |

当前单一阻塞是完整故障范围中的比邻星支付进展：停止时高度 12，原始 owner 请求已包含；
当前父级 P0 Proposal 与 P0/P1 Prepare 在 P0/P1 已认证保留，P2/P3 缺少完整对应消息及目的收件。
这定位了停滞路径，尚未证明唯一原因。已发现的候选路线不等于实际交付、账本包含或成熟。

下一实验：保留当前普通实验的准确源码与状态；通过后执行原定故障范围与严格停止核验。
若仍失败，先沿该消息路径提出可证伪假设，建立最小真实进程复现，证明旧实现失败及修复通过，
再做下一次完整资格运行。不靠微优化组件耗时推断原因，不提高门槛，不重发或退款已包含请求。

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
`regional-bft-open-status-frozen-checks-20261004.json`。

此前详细历史已原样归档：[历史状态记录](operations/history/PLAN_STATUS_before_delivery_focus_20261004_8403d16a68dc.md)。
归档 SHA-256：`8403d16a68dc6adbd2be3afdfd1afda843ac1cfd0e1a6e114912457465db203c`。所有历史失败、签署证据及私有目录继续保留。
