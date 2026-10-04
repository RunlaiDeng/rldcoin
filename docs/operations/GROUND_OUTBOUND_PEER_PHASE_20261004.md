# 普通出站邻居尝试位置：反例、修复及有限资格

2026-10-04；全新无价值地面运输候选。冻结白皮书内容不变，全部实施验收仍适用。

当前失败范围在 Proxima 高度 12 导入、13 未成熟。已经完整认证的停止档案与四个
Proxima 实时链显示：一份 Prepare 在来源入队到首次准备之间等待约 40.180 秒；
同一目标的 20 次尝试在准备阶段因本地争用拒绝，仅有 2 次准备成功。目标处于
四个固定邻居排序中的第 2 个位置。旧运行每轮最多四邻居，完整处理后起点增加
四再取模四，因而每轮位置相同。元数据不能重建未发布尾部或证明唯一故障根因。

先做的大证据实际 TLS 窄判别测得最长本地租约 0.964 秒，其中线程 CPU 0.952 秒；
3 次原 0.2 秒普通尝试完全落在此租约内，随后 carriage 因待重试目的不同拒绝。
同时普通 receive 已成功准入 15 次，所以不据此改变准入、租约或所有权规则。
观察是实际运输工作与控制的锁外暂停；没有执行或测量 Native CPU。

## 可复现周期争用反例

一个实际出站 owner、四个固定 pinned-TLS 邻居，四轮。每轮竞争者先持有真实 TCP
Mesh Node 租约，在第二次实际有界拒绝后解除控制屏障；剩余位置执行正常认证、
持久收件及回复本地保管。竞争屏障不是 Native CPU，不放大任何等待或入站槽。
旧代码约 2.123 秒完成，顺序四次均为 0/1/2/3，前两个位置均失败、后两个均成功，
只有 2/4 邻居保留双端精确匹配收据。私有 fixture 留存，不发布密钥、TLS 或状态。

修复让每批起点按不小于批宽、且与固定邻居数互素的最小步长前进。原四邻居
顺序变成 0/1/2/3、1/2/3/0、2/3/0/1、3/0/1/2。新目录、同一控制屏障，约
2.134 秒完成，4/4 邻居保留双端精确匹配收据。没有变更发现/端点权限、TLS/
挑战绑定、证据验证、fsync、退款、成熟、票数、四项每轮上限或 0.2/3 秒尝试。
出站成功仍在完整本地回复保管之后才抑制重发，停止/取消语义和游标推进时点不变。

对固定 1–16 邻居，实际拒绝调度入口的检查证明：至多邻居数个完整 tick 内每个
邻居都取得每个现有尝试位置；邻居变化只使用当前配置的固定端点。它不是相应
规模的 TLS 负载。全部位置都不可服务、tick 未完成、频繁重启或动态邻居下的
送达期限未资格。相位轮转不预抢现有租约，也不提供无条件活性或账本授权。

## 精确来源与后续门槛

新 397 文件来源 `7e729cd692769b9bdafc40171ab423306ab4ed5da098e7302e7f2ae186e99a3c`。
只改变 `interstellar_tcp.py` 并新增位置覆盖检查，Native/core 字节相同；精确
默认驱动重建为 `e5f72ec41f2801c4fca20d85f7e067a1c73cbd3a67548bfcd3694c3f8e0c9c77`。
组件通过不继承旧普通、完整故障、持续负载、独立保管或物理路线资格。

冻结来源 531 项完整过程回归 282.264 秒通过；三个实际 Runtime 保管边界通过，
各自独立 caller head 与保留签署响应核验，源码/驱动字节未变。184 Native 与 strict
检查复用相同 Native/core 字节的有效证据，未重复运行；这些检查仍非普通付款资格。

节点检查已结束，单次新普通范围及严格停止核验已通过。该范围绑定精确来源、
实际默认驱动与独立 controller，使用全新无价值目录并保留原窗口/成熟/票数/容量。
独立 controller `50259ae2...` 的原清单节点绑定仅为历史；实际导入路径与运行节点
绑定本次 `7e729cd6...`。尝试预算一、已用一；阶段 600 秒、轮 60 秒、24 高度不变。
普通循环 759.140 秒、严格停止核验 63.086 秒通过：E11/P4/A4、12 Native、
12 收款、4 保管头、784 完整信封、1,824 接触档案；300/300/0，私有字节/权限未变。
没有与旧普通构成受控速度比较，也不证明旧故障的唯一原因。

随后只启动一次新隔离的原定有限故障范围：从本次停止合格普通范围复制，
不启动旧失败源；Node/驱动同上，独立 fault controller `20d5427a...`、
停止 verifier `4bb57a09...`。假设是新尝试位置在原故障条件下允许唯一导入、
成熟及无钥证书排空。阶段仍 600 秒、轮 60 秒、上限 24 高度，预算一、已用一。
当前未终态，普通成功没有授予其资格。失败保存原件，不同条件不能误称
原失败恢复通过，也不原样重复或替换付款；停止后才进行对应严格核验。

证据：`regional-ordinary-lease-overlap-component-20261004.json`、
`regional-outbound-peer-phase-window-observations-20261004.json`、
`regional-outbound-peer-phase-baseline-component-20261004.json`、
`regional-outbound-peer-phase-candidate-component-20261004.json`、
`regional-outbound-peer-phase-source-inventory-20261004.json`、
`regional-outbound-peer-phase-stage-decision-20261004.json`、
`regional-outbound-peer-phase-frozen-checks-20261004.json`、
`regional-outbound-peer-phase-runtime-custody-20261004.json`、
`regional-outbound-peer-phase-ordinary-stage-decision-20261004.json`、
`regional-outbound-peer-phase-ordinary-stage-outcome-20261004.json`、
`regional-outbound-peer-phase-three-region-cycle-20261004.json`、
`regional-outbound-peer-phase-three-region-cold-20261004.json`、
`regional-outbound-peer-phase-joint-fault-stage-decision-20261004.json`（均在本目录 evidence 内）。
