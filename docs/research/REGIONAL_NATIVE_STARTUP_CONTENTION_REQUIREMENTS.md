# 原生启动观察的有界锁竞争等待

状态：同机无价值候选的明确启动缺陷已修复；S17 / I8–I9 的有限工程证据，
不构成完整协议、独立保管、全故障或物理路线资格。正文/PDF不改。

## 实际反例和来源

旧Node/原生 `c2b5e8bc...` 的ordinary TLS首样本42.973秒启动失败保留。
未把控制器过早读取推为其唯一原因。独立全新V8 signed zero-allocation目录，
仅持有真实 `LOCK` OS锁，`startup_config` 精确拒绝，且没有transport/custody
创建；放锁后同一native contact观察、startup配置读取和pinned全重放成功，
native文件字节/库存/模式/大小/mtime不变。该因果反例0.170秒，预算一次120秒。
原生源码与binary没有改变，未打开旧失败fixture或重排其状态。

## 修复边界

`tools/regional_native_startup.py` 的 `Inspection` 只用于构造阶段，允许固定
观察集合 `contact-status`、`bft-context/status/retained-messages`、`proof`、
`bft-network-pack/check/check-batch` 和 `bft-installed-epochs`。每次仍调用
完整原生程序；只对本机已验证的完整精确错误
`native rejected: regional candidate rejected: lock acquisition failed because the operation would block`
等待。不同/附加错误、无效currency、签名、RESTORING、IO/timeout均原样拒绝。

每个Inspection共享最多3秒的失败锁尝试及延迟，最多128次锁拒绝，25ms步长。
完整成功原生重放保留原30秒每调用/输出限制；3秒不是整个startup、重放CPU
或socket尝试上限。默认startup配置及Service首观察各有一个Inspection，
Runtime构造的所有观察共享一个Inspection；不改变native历史/金额/成熟、
quorum、capacity或已配置block/round/deadline。

所有未列明命令直接单次转交，包括sign、recover-only、sync、init、finalize、
epoch/custody恢复。不能补签、清除native reservation、自动领受caller head、
返回伪观察或从Python缓存初始化权威。原有native/current proof和完整caller
约束仍执行。Runtime构造完成/异常退出后恢复原native对象；普通tick/receive
仍使用原有lock refusal及unknown观察策略，没有新增live等待或延长共识轮。

## 验证及未通过原件

首fix检查五项逻辑通过、八项Native setup报untrusted currency，0.255秒终态
未通过：fixture生成器仍为旧二进制 `f687855b...`，Native main `838873ba...`
与源c2保持准确。仅重建该helper，1.48秒退出0，新helper `7c588b9d...`；
原件与失败目录保留，换全新fixture重测，不重签旧请求或修改生产lint策略。

当前准确Node源上13项于7.652秒通过：精确readonly重试、其他错误立即拒绝、
mutation/recovery单次、不前进时钟下的尝试上限、共享预算、真实Native持锁
释放/持续超时、Service/Runtime构造、原生无钥旧响应恢复不首次签署，以及
invalid authority和既有identity恢复。持续持锁拒绝后未创建运输状态；
Runtime实际构造没有改变独立caller head，普通native/live观察恢复立即拒绝。

另一个全新V8准入样本1.374秒通过：真正的Native入口在临时OS锁下启用
isolated relay并干净停机，genesis head未变；另一个V8 BFT构造无key文件，
真实锁释放后完整认证/观察成功，native head/caller head不变、records0。
没有首次投票、长网络campaign或全fault；两阶段预算各一次180/120秒。

既有native69文件/binary、core171和冻结正文/PDF/receipt准确字节未变。
Native.call/apply、Service.tick/receive scheduler、Runtime live `_tick`、
candidate/receive/sign/reconcile/retain/broadcast及cold/live/retention/TCP/mesh
准确方法/文件字节与已通过TLS来源相同。只复用这些原范围行为的证据；
已有TLS通过属于其原Node来源，不能称为新Node full TLS/fault通过。

完整绑定及终态：
[启动修复结果](../operations/evidence/regional-native-startup-inspection-outcome-20261005.json)。
VALUE-STRICT-01仍OPEN，地区/启动通过不替代旧价值库严格检查。

## 下一行为门槛

全新一地区V8普通Native/TLS fixture，按实际height6/有序admission导出缺席
leader，不启动其进程；三健康voter须有事前明确pin的连通邻居路径。
只启停/原生观察，禁止控制器构造或搬运协议消息。必须实际观测Native
认证的后续round及三取四prepare/commit、自动最高q2和一次fee debit，
停机后完整native/envelope/caller核验；缺席signer/caller head字节不变。

准备180/live600/cold180秒，各一次；原60秒轮、24高度、2016窗口/成熟/票数/
容量不变，full fault campaign预算0。拒绝、原阶段边界或实际终态即退出，
保留反证，不原样重跑。这个有限缺席leader观察仍不替代完整fault、真实
2016窗口、跨设备/独立保管、长历史、PQC/续证及物理route资格。
