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

下一假设：普通V8 admitted BFT Runtime收到完整已认证通道提交并在本地
durable接受较高receipt后，普通启动/领导者调度应选择并认证费用预算挑战，
无需controller注入挑战或读取owner/witness钥；完整transport与native custody
仍分开。先在新source绑定的最小Runtime/native集成样本一次120秒、网络长
campaign=0判别。由实际counterexample选择修复，不为了过检查跳过high-QC锁、
旧caller-head或源绑定/完整authentication。终态/失败/预算即退出，保留原样。
不能重复原600秒stage/60秒轮/24高度或将旧fault/profile结果继承为新资格。

最终83步实际CLI在24.334秒终止通过，完整来源绑定与复用边界见
[实施结果](../operations/evidence/regional-native-channel-fee-budget-outcome-20261005.json)。
核心171文件和最新冻结正文/PDF/receipt逐字节未变；没有官网/Library/远程发布动作。
