# 按最终白皮书完成项目：实施与验收映射

**已采用的实施验收记录：** 最终白皮书审计提交 `5bf11e4b3637cd99b3a6ebbb8e9e90f7e3edd402`；正文 `2ba62421583c60d0d35d295ff859eef558f2d372ea191d2a2dc828bb3e0b477b`；PDF `c59f9fe8e09e972b25c88626a1468298d9a16fc2343387412973df1829447e14`。文档目标已对齐，全部目标的协议资格仍未完成。

准确任务：`01a100ac-5340-7b13-b661-eedc397b003a`。本文件是可更新的实施/风险记录，不能自行修改冻结白皮书或降低其目标。[冻结receipt](WHITEPAPER_FREEZE_RECEIPT.json)已绑定正文/PDF内容哈希与审计提交，无白皮书展示版本号。已签fixture/旧profile不因文档改变获得新权限。

最终目标：按白皮书§16–21全部强制义务完成守恒、当地自治、任意授权地区可付款/继续转出/返程、正常启动默认中继、独立长期安全与资格的项目。一亿年是跨代连续性目标，不能称一次测试或固定算法已证明一亿年安全。项目完成和某条物理星际路线实际运营须分别验证。

判定词：**已实现/有限证据**仅说明下表所列精确行为；**实现缺口**待开发；**假设待证明**须模型/独立审查；**安全门槛**未通过禁止实际资产采用。不把文档、活动日志、测试数量、未成熟进口或最新提交当作完成。

| 条款 | 已实现/有限证据 | 实现缺口与待证明假设 | 必须验收 |
| --- | --- | --- | --- |
| I1 / S1–S2 / R3 | 已有无价值signed-genesis/admission身份检查及精确fixture根。 | 完整CurrencyRoot/RegionAdmission治理配置、独立批准权/控制披露；发现不授予权威。 | A、N1/N8；错根/自签地区/缺权限拒绝，独立采用复核。 |
| I2 / S3 / R1–R2 | 精确同机三地区循环及有界隔离当地付款有样本。 | 长断联独立地域启动/恢复/本地进度；quorum/suite条件与远程新证据边界。 | C/E/F，移除所有Earth端点后实际付款，不以cache UI通过。 |
| I3 / S5/S8 / R14 | 核验fixture兼容前缀300发行、重复进口和当地守恒。 | §6精确递推/向量与checked arithmetic实施；互斥U/E/T跨任意拓扑证明。 | A/B/F，每transition及恢复守恒，跨平台整数向量和overflow拒绝。 |
| I4 / S6 / R4 | 同机Native普通三地区付款返程完成。 | 完整公开canonical语义、并发/重启原子唯一进口；独立多源通用互通。 | F，错目的/错域/篡改/duplicate均不credit，来源扣除先终局。 |
| I5 / S7–S9 / R4–R5 | Native onward与return在有限普通scope通过。 | 根化良基DAG资源上限、混合/拆分/合并谱系、复合终局证明。 | F，拒自证环，任意多源重放与故障、污染descendant隔离。 |
| I6 / S6–S8 / R1/R4 | Earth→Proxima→Andromeda→Earth在精确同机scope净返程。 | 独立保管返程、永久ID去重/升级连续；不能释放初始扣款。 | F，掉回执/重启/退休epoch/返程并发，原debit不退款。 |
| I7 / S3–S4/S9–S10 / R2/R6/R23 | 三取四prepare/commit及durable lock有无价值候选。 | 共识/view-change/reconfiguration完整profile与独立fault/custody；全descendant冲突隔离、预定事故权限。 | A/D/F/G，故障界内无冲突final，缺quorum停止；现最新故障scope失败保留。 |
| I8 / S13–S14 / R12/R16 | 固定TLS ordinary startup、多跳、持久收件、默认中继地面样本。 | N1–N10完整native与实际长延迟adapter、合法custody删除、独立资源/替代物理接触。 | C/F/G及全部N1–N10；receipt不是ledger credit。 |
| I9 / S18 / R20 | Native/wallet区分queued/verified/import/maturity/owner heads有候选。 | 完整状态、污染余额、独立验证、过期显示与真实consumer flow。 | E/F，每stage端到端，stale/伪receipt/credit claim不当native money。 |
| I10 / S11/S16 / R10/R11/R22 | 已有严格停止重放，私有字节不变及外部caller-head样本。 | 总本地回滚独立见证、跨设备、>200000历史/实际scale、灾难全恢复与费用。 | D/G，旧全文件backup/clone/见证丢失拒签/拒支出，不恢复已消费ID。 |
| I11 / §11–12 / R7/R8/R21 | 当前Ed25519/SHA256/TLS1.3；无PQ交易/共识实现。 | 认证suite/parameter/era，reviewed PQ授权/KEM、反降级、迁移/退休、可信原始证据续证。 | D/F/G，标准向量/全proof成本、迟到撤销、broken旧钥伪migration、休眠余额/旧视图、反回滚。 |
| I12 / S12/S14–S17 / R9/R13/R17–R19/R24 | 有限同控制者普通scope/组件证据，现无mainnet。 | 独立运营/控制/保管/两独立验证实现，费用/储存/负载/钱包/供应链/隐私审查与维护。 | 全A–G与I1–I12/N1–N10；P1–P8明确采用；真实route另证。 |

## 保留的 traced 基线与当前关键路径

节点冻结来源396文件 `2309a18199c5e7714017b56780001cbdf2527c57b574cc759d09d83ebc9f4c57`，二进制 `a4f5e23204f1a8d7d76545d95f88bd556a4ba7e8f5905b77c52529b02d4cb979`。

普通三地区cycle报告 `regional-contact-trace-three-region-cycle-20261004.json` 及cold报告同来源通过。527 process回归和3 Runtime custody组件通过；184 Native/strict引用逐字节未变旧证据，未重复运行。这些只能提供相应有限行为，不资格全部目标。

最新完整有限故障 `regional-contact-traced-joint-fault-fresh-20261004.json` 于15:41:51 UTC失败：E13/P11/A12，四recipient均 VERIFIED_EVIDENCE_PENDING_IMPORT，未导入/未成熟/不可花。600秒stage、60秒轮、24高度上限未增加。300发行、290 liquid、10 gross pending守恒不等于付款通过。失败范围停止cold、原owner heads和档案未变；不会恢复/重签/退款。

15:49/15:55 live path/wait reconciliation提供实际普通准备等待和拒收记录（例如P1→P2 Timeout入队到首次prepare约88.318秒；已实际认证请求被拒），但完整尾部/部分启动观察未知，**H-service仍不是已证唯一根因**。后续已有最小普通Runtime反例及窄修复（见下一节），不能将其推广为旧完整故障的唯一根因；没有新因果证据不重跑完整campaign。不修改/打开原停止fixture，不绕过读取限制或读取私钥。

## 2026-10-04 16:35 UTC 当前开发检查点

原任务正在实际开发。提交 `f7b21e9` 保留 traced 失败并隔离空闲ordinary intent占用；`935e7e8` 实施有界重试优先；`bd64666` 修复可空观察和独立controller绑定。新Node来源 `67ad71f18be1578005caab76689297d7b12f8ba1d46c9e804bc72ced6fd2d858`、binary `3019b6d9072673c0c05c99bc8d4f43bcd5998bda0a53e98c7c9d1e919be4f713`：旧反例复现、新有界等待后两端实际TLS持久保管及原owner/purpose重试完成，528过程回归与3 Runtime custody组件通过；184 Native/strict引用未变来源而未重复运行。这是针对已测阻塞的实质行为修复，**不是完整资格或无条件starvation freedom**。

第一新ordinary cycle 346.082秒因可空观察的 `TypeError: 'NoneType' object is not subscriptable` 失败并停止于E8/P4/A0；31.436秒严格停止核验12 Native/492信封/1088档案通过，原失败和私有字节保留。最小真实停止状态反例证明旧谓词抛错、新谓词保留unknown；controller修复没有改变Node。新独立controller来源 `50259ae2b36b96272e8676f7a0630fc314d7b34d1a25891b6a7f9e2f707640d2`，相关8+16与独立绑定18+45检查通过（首次环境不足失败日志保留）。

准确一次新普通三地区范围于 **16:35:15 UTC** 启动，追踪默认关闭、Node/二进制不变，budget1；截至此检查点未完成。原600秒阶段/60秒轮/成熟/容量/票数保持，完整故障budget当前0。通过分支须完整实际返程及严格停止cold后才决定一次新fault；失败保留原件、cold后换最小判别，不能原样重复或退款/重签。证据：`operations/evidence/regional-bounded-ordinary-preference-stage-decision-20261004.json`、`regional-bounded-ordinary-preference-three-region-cycle-20261004.json`、`regional-pending-observation-stage-decision-20261004.json`、`regional-pending-observation-three-region-scope-binding-20261004.json`。下一合理检查点：新普通范围的实际阶段/终态或预算边界，以源绑定行为证明推进，不以活动日志判断。

## 独立未通过待办：旧价值库严格静态检查（VALUE-STRICT-01）

**OPEN / 未通过**。原两处基线告警及120秒预算耗尽不能由地区账本库通过替代。
[准确触发条件、影响范围、单次预算与完成标准](operations/RLD_VALUE_SUCCESSOR_STRICT_ACCEPTANCE_TODO.md)
已纳入验收；当前通道范围已终止，本次没有启动检查或增加生产豁免。

## 实施顺序和单一负责人

1. 保留本轮失败原件，补齐H-service最小反例，修复已测普通路径；按改变范围复用仍有效精确证据，必要时一次新的隔离无价值验证，不提高门槛。
2. 形成§20 immutable complete protocol profile与模型：所有身份/权限、canonical、finality/epoch、根化谱系、互斥守恒与冲突隔离先定义，审核后开发；缺字段failclosed。
3. 实施S5–S12原子账本/谱系/恢复、跨升级永久ID与独立见证；组件反例后实际三地区多源/混合/循环/冲突故障验收。
4. native relay/wallet按S13–S18、N1–N10集成，扩大历史与资源、明确service/archive funding；独立测试/实现/安全审查。
5. 完成PQC/crypto-renewal/governance succession与全部A–G/I1–I12有限资格；P1–P8未作决定或证据失败不得上线真实资产。实际physical route另行逐条资格。

原任务保持实现和fixture的唯一负责人；本次只更新规范计划文件，不覆盖活动实现。独立审查、文档、只读证据分析可在不覆盖源码/保管范围进行；不得并发复制签署或重复长测试。本文件不授权部署协议、启动主网、操作资金、改变账户/权限或外部联系。

## 完成和冻结后记录

每个S/I/N/A–G/R条款的实施行须记录：owner、精确source/profile/artifact、实现/缺口、assumptions、fault/scale/horizon、可证伪验收、结果/失败原件、剩余风险、stop与requalification checkpoint。白皮书正文冻结后新缺陷记录在独立risk/implementation档案并报告owner，不能自行改正文、删gate或称“所有风险已经消失”。支持任务消息接口不可用时，AGENTS/计划文件的存在不代表原任务已收到；须如实记录传达和receipt状态。


**目标传达状态：** 权威文件已更新供原任务下次读取。检查本机当前支持工具未发现任务/线程read/send或桌面应用接口，不能确认原线程已收到或加载；不直接编辑任务数据库、读取凭证或绕过限制。文件更新与消息receipt分别记录。

**用户授权的正文编辑修订（2026-10-04）：** 白皮书写需要实现的能力，开发和发布状态移至独立记录；全部 I/S/R/A–G/N/P 验收要求保持。此次编辑不授予协议、物理路线或主网资格，不因正文编辑重跑已有有效证据或打断当前故障范围。旧冻结记录由官网 Git 前驱及新记录内 predecessor 哈希保留。

## 2026-10-05 新目录继续转出验收检查点

原线程goal已恢复active，项目命令显式新workdir；持久cwd仍旧。新驱动
`d8c2af0d...` 默认入口实际执行当前companion，Native87/Python153/Core来源未改。
一次180秒/1次的全新范围在136.378秒完整通过：Native准备E4/P3；普通P
使用原99输入在4认证gross98出口、5停止；四新A在4进口net97、6成熟可花。
494完整信封逐份Native检查、独立caller/owner头及9个正常退出核验；
I=U=10^30、E=T=0。[准确终态/源绑定/下一返程](operations/evidence/regional-native-paged-onward-fresh-outcome-20261005.json)。
这证明当前来源的有限继续转出行为；初始E到P仍为controller准备，完整ordinary
循环/返程/完整fault/2016/long-history/独立保管/PQ/physical仍OPEN。旧180.529秒
失败原件保留且未打开；旧价值strict仍独立OPEN，不由本范围替代。
下一一次300秒/1次验证原A97→return96→原E净95、真实导入成熟和全cold，保留
原E100扣款及全部负债；起源实际发行/不同高度兼容前缀须按完整Native重放计数。
旧goal正文前继哈希已在本原线程报告；实施按当前AGENTS/冻结receipt，不自主改
goal目标正文、白皮书/PDF/官网。
