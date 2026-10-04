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

四个真实进程的静态档案实验已通过：441 条历史运输记录下，关键完整消息最终交付、
原生认证及超时证书组合成功。其约 82 秒还包含历史认证队列，不能视为单纯网络延迟。
进一步控制了已认证历史队列：无持续流量时三个目的节点在 8.521 秒内完成认证；
每节点最多 40 个有效历史重发时，一个目的节点在预定 120 秒观察窗内仍未收到消息，
另外两个分别约 3 秒和 33 秒收到。四个真实进程正常退出，原失败账本及成功运输基线逐字节不变。
这是可反驳的运输压力失败复现，尚未证明原完整范围只有这一根因，也不是完整故障通过。
已保留固定输入及候选分解对照：公平锁入口单独仍失败；帧/目的地轮转单独完整压力
用时 60.456 秒，超过原 60 秒判定；组合曾在约 8 秒完成关键认证，但未完成全部历史包排入。
修复新锁入口错误清理等待意图后，改用旧/新实现相同的独立排队、最多四条批次驱动：
旧实现三个目的节点在 120 秒内均无关键消息；组合候选从控制标记至全部目的节点原生认证
最多 25.456 秒，全部四节点 40 个预定历史包排入，原失败账本与运输基线保持不变。
该冻结候选的 480 过程回归及 3 个实际 Runtime 保管阶段通过；Native/core 源码未变，
原生启动程序已为其默认入口重建，184 Native 与 strict 检查明确引用完全相同的先前源码证据。

补充冷启动/无提示检查发现 41 个待发包只轮转到 12 个，故该候选尚不能合入。
冷缺失改回持久游标轮转后，6 个针对性检查覆盖禁用、紧容量、每次驱逐、出版失败、
坏签名和真实锁拒绝意图保持，全部通过；但该版实际运输最慢约 71 秒，仍超过原判定。
当前只在真正冷缺失时回到原游标，新帧组首次出现初始化独立位置；6 检查已通过，
四真实进程运输确认已通过：每节点全部 40 个输入排入；从控制标记至原生认证最多 31.367 秒。
最终冻结来源的 486 项过程检查与 3 个实际 Runtime 保管阶段已通过；默认启动程序已精确重建。
四份运输实现及六项冷启动/锁回归已按明确清单合入主仓库。普通三地区及原定完整故障资格即将依次运行；未发布。
所有相反结果、源码冻结包、原失败状态及私有头保持；不放宽原阶段时限、轮次、成熟或容量。

原失败日志显示当前提案目的节点首次观测相差 79–95 秒，晚于部分节点的下一轮。
最后缺失的超时消息只在发送端有约 6 秒观测窗，不能仅凭它断言运输永久停滞。
当前进程仅 6 次候选试算、总耗时约 0.34 秒，不支持历史提交试算是主要瓶颈；不据此补丁。
所有实验保持原失败账本只读，不启动其 Runtime、恢复响应、首次签署、安装账本或迁移价值。
静态实验使用新 mesh/TLS；后续控制试验仅复制成功运输诊断的同格式私有测试目录，
保留全部签署档案及测试密钥，不代表新保管或独立运营资格。

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
`regional-bft-open-status-fault-current-proxima-path-observations-20261004.json`、
`regional-bft-open-status-fault-log-timeline-20261004.json`、
`regional-timeout-carriage-four-process-ablation-20261004.json`、
`regional-dynamic-carriage-four-process-ablation-20261004.json`、
`regional-dynamic-carriage-four-process-traced-20261004.json`、
`regional-dynamic-carriage-scheduling-observations-20261004.json`、
`regional-fixed-carriage-four-process-20261004.json`、
`regional-coordinated-enqueue-four-process-20261004.json`。

此前详细历史已原样归档：[历史状态记录](operations/history/PLAN_STATUS_before_delivery_focus_20261004_8403d16a68dc.md)。
归档 SHA-256：`8403d16a68dc6adbd2be3afdfd1afda843ac1cfd0e1a6e114912457465db203c`。所有历史失败、签署证据及私有目录继续保留。
