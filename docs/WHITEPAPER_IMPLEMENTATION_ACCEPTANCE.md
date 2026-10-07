# 冻结白皮书实施验收

采用[冻结记录](WHITEPAPER_FREEZE_RECEIPT.json)的正文/PDF准确哈希，全部S1–S18/R1–R24/I1–I12/A–G/N1–N10/P1–P8必须完成。表中“有限证据”只指准确来源/故障/资源/期限内的行为；实现、模型、独立复核、采用和物理运行分别验收。未知或失败保持未知或失败，所有历史原件保留；记录精简不改变门槛。

| 条款 | 已实现/有限证据 | 实现缺口与待证明假设 | 必须验收 |
| --- | --- | --- | --- |
| I1 / S1–S2 / R3 | 已有无价值signed-genesis/admission身份检查及精确fixture根。 | 完整CurrencyRoot/RegionAdmission治理配置、独立批准权/控制披露；发现不授予权威。 | A、N1/N8；错根/自签地区/缺权限拒绝，独立采用复核。 |
| I2 / S3 / R1–R2 | 精确同机三地区循环及有界隔离当地付款有样本。 | 长断联独立地域启动/恢复/本地进度；quorum/suite条件与远程新证据边界。 | C/E/F，移除所有Earth端点后实际付款，不以cache UI通过。 |
| I3 / S5/S8 / R14 | 候选整数量账、重复进口拒绝和当地守恒检查。 | §6精确递推/向量与checked arithmetic实施；互斥U/E/T跨任意拓扑证明。 | A/B/F，每transition及恢复守恒，跨平台整数向量和overflow拒绝。 |
| I4 / S6 / R4 | 同机Native普通三地区付款返程完成。 | 完整公开canonical语义、并发/重启原子唯一进口；独立多源通用互通。 | F，错目的/错域/篡改/duplicate均不credit，来源扣除先终局。 |
| I5 / S7–S9 / R4–R5 | Native onward与return在有限普通scope通过。 | 根化良基DAG资源上限、混合/拆分/合并谱系、复合终局证明。 | F，拒自证环，任意多源重放与故障、污染descendant隔离。 |
| I6 / S6–S8 / R1/R4 | Earth→Proxima→Andromeda→Earth在精确同机scope净返程。 | 独立保管返程、永久ID去重/升级连续；不能释放初始扣款。 | F，掉回执/重启/退休epoch/返程并发，原debit不退款。 |
| I7 / S3–S4/S9–S10 / R2/R6/R23 | 三取四prepare/commit及durable lock有无价值候选。 | 共识/view-change/reconfiguration完整profile与独立fault/custody；全descendant冲突隔离、预定事故权限。 | A/D/F/G，故障界内无冲突final，缺quorum停止；独立与更广故障资格必须分别完成。 |
| I8 / S13–S14 / R12/R16 | 固定TLS ordinary startup、多跳、持久收件、默认中继地面样本。 | N1–N10完整native与实际长延迟adapter、合法custody删除、独立资源/替代物理接触。 | C/F/G及全部N1–N10；receipt不是ledger credit。 |
| I9 / S18 / R20 | Native/wallet区分queued/verified/import/maturity/owner heads有候选。 | 完整状态、污染余额、独立验证、过期显示与真实consumer flow。 | E/F，每stage端到端，stale/伪receipt/credit claim不当native money。 |
| I10 / S11/S16 / R10/R11/R22 | 已有严格停止重放，私有字节不变及外部caller-head样本。 | 总本地回滚独立见证、跨设备、>200000历史/实际scale、灾难全恢复与费用。 | D/G，旧全文件backup/clone/见证丢失拒签/拒支出，不恢复已消费ID。 |
| I11 / §11–12 / R7/R8/R21 | 现有ledger仍Ed25519/SHA256/TLS1.3；新增Core候选AND双签、四签续证及有界公开入口，15个NIST external SigVer子集和两不同实现互通通过。无实际PQ交易/共识/运输或独立审查资格。 | 认证suite/parameter/era，reviewed PQ授权/KEM、反降级、迁移/退休、可信原始证据续证。 | D/F/G，标准向量/全proof成本、迟到撤销、broken旧钥伪migration、休眠余额/旧视图、反回滚。 |
| I12 / S12/S14–S17 / R9/R13/R17–R19/R24 | 有限同控制者普通scope/组件证据，现无mainnet。 | 独立运营/控制/保管/两独立验证实现，费用/储存/负载/钱包/供应链/隐私审查与维护。 | 全A–G与I1–I12/N1–N10；P1–P8明确采用；真实route另证。 |

## 实现与采用边界

[实现边界](PLAN_STATUS.md)区分候选能力与采用条件。Core混合双签、quorum、
四签续证和有限归档是verification-only接口；已有Native账本继续使用其签署采用的
经典规则。候选验证、编译、另一个参考实现或运输收据均不能替代完整价值、独立
安全/保管、历史恢复和采用验收。内部阶段结果、源码/二进制绑定、预算与失败记录
在本地保留，不按运行轮次更新公开条款映射。

S1–S18按实现集成、R1–R24按反例/模型和独立复核逐项验收；对应算法块、图示及39条参考文献不改变。A–G全部基础验收、全部I1–I12、N1–N10和独立采用P1–P8共同构成完成条件，表的组合映射不省略未显式列出的编号。

P1共识/时代与独立验证者准入；P2治理/继任/事故/分叉权限；P3密码suite及有限旅程重叠/退役/续证；P4直接钥/监护恢复、watcher与独立单调见证；P5资源保留、档案资金及赤字；P6规范交易/谱系/永久消费根与任意地区组合证明；P7独立发布/保管/安全审查和排除测试资产的新零初始分配签名采用；P8具体物理路线/隐私/服务期限。每项需要认证profile和相应证据，缺决定或失败禁止受影响的真实资产操作。

每条验收记录必须保留owner、source/profile/artifact、假设、故障/规模/期限、可证伪检查、实际结果、失败原件、风险、停止及续资格点。[主计划](RLDCOIN_MASTER_PLAN.md)保留完整目标矩阵；[验证入口](operations/VERIFICATION.md)不授予独立审查或部署资格。新缺陷进入动态风险记录，冻结正文/PDF不得自行修改。
