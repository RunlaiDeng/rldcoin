# Channel cumulative challenge-fee authorization

Frozen whitepaper §7 / S6–S11 / R10–R13 remains authoritative. A one-use reserve can be consumed by a valid older challenge while the highest accepted state still needs protection. Receipt persistence and conservation cannot by themselves resolve that defect.

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

Fee-budget authority requires its own explicit signed profile; old one-use authority cannot imply it. The complete window, censorship/quorum response, independent freshness, witness custody and normal lifecycle remain separate qualification obligations.
