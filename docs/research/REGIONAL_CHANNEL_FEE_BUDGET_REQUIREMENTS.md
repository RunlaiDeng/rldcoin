# 通道挑战累计费用预算：V8 地面候选

规范依据是最新冻结白皮书 §7 / S6–S11/R10–R13。正文 SHA-256
`2ba62421583c60d0d35d295ff859eef558f2d372ea191d2a2dc828bb3e0b477b`、PDF
`c59f9fe8e09e972b25c88626a1468298d9a16fc2343387412973df1829447e14`保持；全部
S1–S18/R1–R24/I1–I12/A–G/N1–N10/P1–P8仍必须验收。新授权仅在全新签署
零分配、无价值V8 source/currency/profile中实施，不解释或迁移旧授权/余额/目录。

## 失败与模型判别

V7 R-CH-FEE-01原生失败仍失败：合法Challenge(q1)可以消费q2所选one-use
reserve，包括将其未付费用的余额作为普通找零离开E。普通watcher不能凭空
替q2构造资金。原生反例、原report/source/fixture保持。

独立费用模型先用354个有限状态/576条边检查覆盖/守恒/窗口/顺序与拒绝，
随后补齐可执行旧selector：相同pot会被q1消费；仅另选pot也未解决，通道级
q1授权仍能指定q2的pot。第一模型版本与检查原件保留，不能把初版的distinct
标记当完整执行证据；后继模型才真实执行两个selector。模型的authentication、
finality/maturity是明确理想前提，不是native验签或独立证明。

## 新授权和完整原生执行

`ReserveBudget { channel, input, fee_limit, max_fee }`由准确成熟input的实际
owner签署；owner仍须是通道party，原input/通道/网络/地区/目的/声明/前驱
及所有完整proof/signatures原生验证。`max_fee`是明确累计授权，不从旧
`Reserve`的一次授权推断；旧Reserve仍一次性，不能支撑新可靠fast receipt。

`RLD-NATIVE-CHANNEL-FEE-BUDGET-V1`保留original_amount、max_fee、spent与
准确原始签署authorization、原input root、当前完整coin/provenance。每次
Challenge仅按原per-fee ceiling支出准确fee，spent在原生全重放下累加，并须
不超过max_fee；original_amount = remaining protected amount + spent。
剩余金额继续在E，原授权/root不改、不新增签署权限，不向普通余额返找零。
即使累计授权耗尽或余额为0，保留有界记录直到合法settlement；不通过删
记录复活预算。费用已进入原beneficiary输出，不能退款或重花。

完整input资金只能由原生genesis/历史执行建立；serialized FeeBudget、map
leaf、head或原始授权摘要本身不能初始化账本或保管。所有后继保留当前完整
checkpoint/channel provenance并集；事故仍阻止相关新动作。原生组装在副本
上执行所有fallible检查，预算超限/坏签/错格式/旧头不改变actual native state。
Settlement仍h>c+2016，一次返还准确剩余预算；0余额不生成非法零输出。

## 费用覆盖量及条件

接收新可靠receipt时，选定一笔准确成熟、未消费的Budget，其当前余额与
剩余累计授权都至少为 `fee_limit * WINDOW * MAX_COMMANDS`。按原WINDOW=2016、
原native MAX_COMMANDS=16，per-fee ceiling=3时为96768 runlai。全部乘法/cap
检查整数溢出。不能用companion的四proposal slots代替原生16命令界限。

这是一笔预算的最坏金额覆盖，不是16笔储备的最低数量或新增reserve容量。
每fee/fee floor、发行/供应、成熟、quorums、owner/witness/history/archive/
wire bounds及原deadline不改。max_fee可小于input amount；不同owner明示的
额外pots只授予各自准确权限。过小/旧one-use/不成熟/已耗尽授权拒绝新receipt。
保持普通receipt高度selected/Open、双方/见证完整授权和原生最新caller-head规则；
已经accepted的历史重试不成为新预算授权或新ledger credit。

理由：任何选定高度最多原生16个命令；所有挑战在c+1..c+2016且每笔fee不超过
其fee_limit。因此某个pot的累计授权支出上界为2016*16*fee_limit。每次只支出
fee并保留剩余授权，任何仍有eligible native slot的前缀都有对应费用余量。
序号必须严格增加、同序冲突需隔离；不能用该算术宣称数据可用、独立新鲜度、
quorum、敌对审查、最后一块后的响应、费用规则变化或physical liveness已解决。
本条件是新候选的保守接受策略，不是对冻结白皮书的修改或所有充分策略的唯一性证明。

## 真实检查、失败与证据复用

最终native来源 `c2b5e8bccd707e8f6d74193d488d24dace8453a3339e0c2a09c6db89d8b808a3`，
binary `838873ba542703392db98d3fa411bd2f4a9f43837c9493073bc6fdcd6ed5fb3a`。
36 focused native/build/unsuppressed all-targets strict一次180秒范围，在79.902秒
终止通过。真实原生cases包括q1旧挑战后q2预算仍足够、exact root/累计fee/
金额守恒、全cold、双通道普通BFT候选/full three prepare/commit/finalize，
旧one-use和small max_fee拒绝、overflow、授权篡改、累计耗尽、零余额及d/d+1
settlement。2021/2022 case是原生component高度边界，不是2016普通区块运行。

首CLI因控制器保留fixture witness key供q2新签，却仍复制q1“钥已删除”断言，
47步/10.578秒失败停止。原生准确recover-seal成功且完整body相同，错误断言/
失败controller/report及private fixture保留。修正后只新建目录，不改native或
复跑36/strict。完整两次新owner请求和witness seal/receipt后删三角色钥文件，
执行无钥q1再q2挑战、原预算保留、4累计费与普通mine/cold。重建公开fixture
seed文件仅为同一当前owner journal签署新q2请求；不是旧fixture恢复、复制钥
并发或独立密钥销毁资格。无人把报告失败改成通过。

V7来源 `4110ffc4...` 上184其余native检查已经通过。当前execution/wallet/
wallet-agent/storage/BFT/epoch/joint/contacts/history/index/proof实现逐字节未变，
本次7处改变仅在显式channel profile、receipt、kernel与对应tests/docs。
36已验证新channel/value/provenance/cold/legacy拒绝；复用其余未变分支的旧
证据，不再执行已有长检查，不声称220项全部在最终身份重跑。
复用不替代后续实际新行为的必要验证或独立qualification。

## 尚未通过与下一条可证伪主线

旧V3–V7 R-CH-FEE-01保持失败；V8有限native路径已修复，整项独立/full-window/
fault验收仍OPEN。持续2016窗口/200000历史、真实Runtime/TLS无钥最高状态
可用性/对抗调度、实际process/power interruption与独立custody/全回滚、
费用峰值/新fee规则/跨设备、PQ/crypto、物理与全部协议目标仍需完成。
旧价值库VALUE-STRICT-01未通过，地区strict不替代，源码未改，不加豁免。

### 普通领导者自动提案：最小实际范围已通过

2026-10-05，native来源 `c2b5e8bc...` / binary `838873ba...` 未变。
首个全新BFT样本41.693秒在Runtime配置读入拒绝：controller用了native-style
非排序JSON，严格mesh配置要求canonical JSON。原配置/来源/失败目录保留，
独立字节比对确认schema值相同；只在新目录改用现有 `mesh.atomic` 写配置。
这不是协议反例，也没有完成普通启动。

第二个新样本三个Runtime分别于62.476、83.044、102.151秒完成原有完整冷认证；
controller先搬运其历史完整信封，120.017秒预算耗尽，未观察到最高状态提案。
此范围仍未通过。未提高预算重跑同一历史搬运方法，也未取消native冷认证。

判别改为一个当前合法leader、全新四副本/原生投票目录准备、普通启动和真实
时钟的tick。一次120秒范围在70.186秒通过：冷启动61.362秒，三次普通tick
于69.204秒自动提出高度7、q2、费用3的Challenge；controller没有调用Runtime
candidate/sign/quorum、没有注入Challenge，owner/W钥文件已不存在。
提案保留实际完整q2 witness/state与原储备，原生ledger仍高度6、q0、spent0；
c=6、deadline2022不变，最终exact latest head完整冷重放通过。
这证明普通自动提案，**不是三取四纳入、TLS/full fault/full window通过**。
setup六个旧块/Close由controller真实3/4认证，不能冒充Runtime自动认证。
同源码36项/strict/build与旧准确分支证据继续复用，没有再做已通过长测。

### 三取四自动认证/最终纳入：有限控制器搬运范围已通过

下一步已按当时记录的一次180秒独立预算执行；全新私有目录及签署无价值
BFT/通道fixture，native与Node代码未变，不重复strict或旧长测试。
移除controller对历史信封的重复搬运，每个Runtime仍在普通startup全量冷
认证其保留历史，收到的每个新信封仍走原receive/native认证和依赖同步。
没有重设时钟、caller head或prepare lock；没有controller注入Challenge/
Propose/Prepare/Commit/quorum/certificate；原60秒轮、24高度、2016窗口不变。

该范围在179.233秒正常终态通过：三份冷启动63.229/83.658/102.723秒，
合法leader于114.434秒自动提出q2；三个Runtime产生三份不同有序prepare和
commit，认证同一个高度7块。原budget仅扣fee3，剩余+spent=original；
c=6、deadline2022保留，三个独立新native进程pinned全历史冷重放通过。
controller仅经普通receive搬运16个完整当前context信封。所有owner/W钥
文件在Runtime阶段已不存在。setup中的旧六块及Close仍由controller认证；
这个有限范围不资格ordinary TLS/contact scheduler、完整fault或2016窗口。
前41.693秒配置拒绝和120.017秒预算耗尽仍未通过，不由此结果改写。
完整来源/终态：实际自动认证（历史证据保留于本地归档）。

### 普通原生生命周期/固定pin TLS：有限范围已通过

首个全新样本42.973秒停止：controller在任何当前PID启动telemetry之前
读取Native ledger，副本1的ordinary startup报实际原生锁竞争并退出1；
其余进程在启动完成前结束(-15)，未观测TLS付款，样本保留为未通过。
没有把观察超时当作终止：实际exit已确认；没有重启这些旧目录。
源码/时序与controller干扰一致，但此轮未证明其为唯一原因。

下一新样本采用既有network startup策略：仅先读所属当前PID状态文件，
四个普通startup实际完成后才轮换Native查询；缺失/锁竞争观测保持unknown，
不填height0。Native/Node代码、crypto、quorum、60秒轮、24高度和window未改。
仅全新一地区四副本、literal loopback及固定identity/certificate pins，
邻居为0--1--2--3；普通Native entry直接启动contact/Runtime，无controller
协议总线、live Challenge/vote/quorum/certificate注入或insecure fallback。

准备42.087秒、live164.517秒，四副本实际观察q2；干净停机8.898秒，
全范围303.651秒通过。各段预算保持prepare180/live600/cold180。
停止核验最终高度均8，同一高度7的native认证首次纳入q2；三份有序不同
prepare/commit保证原生BFT证明。fee各扣3，剩余+spent=original，c6/d2022
保持，owner/W钥文件在live与cold均不存在。四份Native全历史重放、262个
完整保留信封、573 packet/573 receipt网格档案及四组独立voter/caller heads
认证通过，私有字节/条目库存及所比对模式、大小、mtime未变。未启动Runtime作cold核验，
没有cold签署、init、pending recovery、caller-head adoption或原样长测重跑。
数量只描述核验范围，完成依据是实际最高状态纳入和fee/caller/cold行为。
普通Native/TLS终态（历史证据保留于本地归档）。

这个通过只是一地区同机有限normal ground路径；不替代完整fault、窗口2016
真实执行、independent custody/最新见证、cross-device、长历史/PQ/实际物理
route或全部S/R/I/A–G/N/P资格。所有此前失败、旧owner请求和余额不迁移。
VALUE-STRICT-01仍OPEN，旧价值库与其两处基线未改，地区strict不替代。

启动风险随后已完成真实OS锁反例和窄代码修复：反例0.170秒；精确readonly
startup等待，最多共享3秒失败/延迟及128锁拒绝，mutations不重试，普通live
恢复原Native对象/unknown策略。13项当前源检查7.652秒及新V8真Native入口/
无钥BFT构造1.374秒通过；首次五项逻辑通过/八项stale helper setup拒绝仍
未通过，helper准确绑定后仅换新fixture验证。Native/core/freeze均未变，
没有新full TLS或fault通过。见[原生启动锁合同与下一有限缺席leader门槛](REGIONAL_NATIVE_STARTUP_CONTENTION_REQUIREMENTS.md)。

Runtime判别及预算退出（历史证据保留于本地归档）
保存三个来源绑定终态和独立配置拒绝；首两次未通过不由最后小范围通过替代。
核心171文件、冻结正文/PDF/receipt和旧价值库两文件均再次验证原字节。
VALUE-STRICT-01仍OPEN，本轮未触及该库/发布包，未触发诊断或修复检查。

最终83步实际CLI在24.334秒终止通过，完整来源绑定与复用边界见
实施结果（历史证据保留于本地归档）。
核心171文件和最新冻结正文/PDF/receipt逐字节未变；没有官网/Library/远程发布动作。

## 有限缺席leader的后续行为

三健康普通Native/pinnedTLS节点实际round1认证最高q2、每份fee只扣3及严格
停止核验已在一次全新261.266秒范围通过。首329.533秒cold库存失败保留；
新0.008秒反例支持fixture准备及严格只读公开锚修复，Native/Node live未改。
[完整范围、失败和下一2016窗口容量门槛](REGIONAL_CHANNEL_MISSING_LEADER_REQUIREMENTS.md)。
这不替代full fault、完整窗口结算、跨地区支付或独立/物理资格。

普通窗口存在已证Native历史阻塞：实际64完整BFT检查点后，65 snapshot bound
拒绝，原生/磁盘不变。真实signer范围120秒耗尽仍未通过，容量/CPU归因待辨。
[完整历史和持久签署锁合同](REGIONAL_BFT_WINDOW_HISTORY_REQUIREMENTS.md)要求另签
规则，同时处理两者；不能提高旧bounds或缩短2016窗口。费用覆盖不保证活性。
