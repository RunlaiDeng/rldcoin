# 原生已接受状态看守：V7 地面候选

本候选对应冻结白皮书 §7 / S6–S11 的状态观察、预授权费用及原生纳入义务。
正文/PDF/官网不改变；全部 S1–S18/R1–R24/I1–I12/A–G/N1–N10/P1–P8
仍是项目验收目标。V7 新 admission/kernel/profile/implementation 只用于全新
签署零分配无价值 fixture；V6 或旧来源的值、私有目录、钥/头均不迁移。

## 真实最小判别和实现

一次 120 秒预算中的原生判别在 5.595 秒终止：较高完整状态已接受后，历史
较低状态进入 Close；无 actor/新 approvals 的 Challenge 使用准确既有储备，
普通模板/区块纳入推进 closing state，c+2016 截止不重置，完整 cold 重放一致。
该判别使用真实 public-seed party/witness 签名；未调用 owner/witness 私有服务，
不证明首次签署保管。原检查器通用 `channel_wallet_signing_integration` 标签在该
最小范围没有相应证据，应以此范围说明为准，不能借用该标签声称 custody。

`Store::channel_watch(miner, expected_head)` 与 `channel-watch` 是 read-only
原生候选观察：在 OS-locked 健康库上核对单独传入的完整当前 storage head，
从 pinned genesis 重放每个完整 ordered history event/receipt，重建最高 accepted
状态；不得从序号缓存、序列化 ledger/plan 或头摘要初始化权限。
只对存在更高 accepted 状态的 Closing 通道构造 Challenge。每个状态仍完整
认证实际两方、签署 funding、选定 witness、invoice、来源与 incident/provenance。
只选该最新收据签明的准确 reserve/fee，储备须当前存在、已成熟、足额且授权；
不存在/已消费/过期/隔离/slots 已满则输出明确 diagnostic，不虚构退款或纳入。

按绝对 deadline/channel ID 排序，最多原 companion 的四个 command slots。
每个 intent pin 正确的块内前驱：已选择的 challenge 在共享原生 kernel 的副本
上有序执行，下一 intent 必须在整块发行之前形成 head；完整组合还经过正常
Chain execution 检查。金额、发行、成熟、fees、四 validators/3-of-4、所有 history/
archive/wire/owner/witness 上限及 c+1..c+2016 窗口不改变。没有新 owner/witness
签名，没有私有状态写入。观察到的当前 head 不是独立最新证明。

普通 V7 BFT `bft_candidate` 在原 companion 已调用的入口优先加入上述挑战；
使用锁内当前头观察，而非采用外部 backup。完全 typed 相同 command 可复用；
原 command/slot 约束仍需正常验证，stale/非法提交留在原队列，不能取消重签。
最终纳入仍需要正常三 prepare/三 commit 及原生 finalize；候选没有扣款或付款
保证。Legacy/BFT epoch profiles 不自动获得通道权限。已有 high-QC 锁定的
proposal 仍按原 BFT 规则保留，不因 watcher 重写其值。

## 验收和准确边界

34 focused/native/build/unsuppressed all-targets strict 检查 71.276 秒终止通过。
双通道 native BFT case 用完整实际 prepare/commit/finalize 验证 empty ordinary
candidate 自动加入两条正确有序挑战，未认证的直接接受仍禁用，cold image
全重放一致。它调用普通 native candidate，但不等于新 ordinary Runtime/TLS
生命周期、真实进程中断或 sustained Byzantine/network campaign。

新的 CLI controller 建立完整 owner/witness/seal/receipt 后，使用预先签署的
历史 Close；随后三角色私有钥文件不存在。原生 watch、普通 mine 和 pinned
history-check 完成准确 Challenge，receipt 不 credit、challenge fee/change 守恒，
deadline 不变。Controller 的公开 fixture seeds 是已知的，删文件不等于物理
密钥不可恢复；历史 Close 由 fixture controller 提前授权，不冒称私有 action
signing service。所有私有 fixtures 和精确来源保留，绝不发布钥/日志。

每次新来源范围到失败/预算/正常终态退出，网络 campaign 为0；不复活原失败
fixtures，不重跑已通过三地区 long cycles，不改原 fault/owner 请求或预算。
共享 BFT/native 回归仅因实际 candidate 路径改变而一次验证，跳过已完成
34 通道行为。完整 2016 窗口、>200000 history、复制钥/全回滚/独立见证、
真实 power-loss/cross-device、费用覆盖、自动 incident 观察及全部物理/crypto
资格仍未完成。

## 实际失败：R-CH-FEE-01 费用覆盖丧失

**OPEN / 安全验收未通过，禁止把现有 receipt acceptance 采用为安全生产付款。**
`native_channel_watch_highest_complete_history_stale_head_and_consumed_exact_reserve`
在准确 V7 native 上真实接受 q1 和 q2，两者选同一个原生已成熟足额 reserve；
Close(q0) 后，合法 Challenge(q1, fee=1) 消费该 one-use reserve。q2 仍是最高
accepted，但 watch 明确返回 reserve absent/consumed，不能生成其 Challenge。
Native heads/cold replay/U/E/T 都正确，故守恒、收据持久化与 watcher 存在不能
证明最高付款受保护。该 counterexample 保留，不称付款安全通过。

范围：现 V3–V7 的 `Reserve` 授权为同通道任一合法更高状态的一次费用；其
selector 未限制某个 invoice/sequence。仅给后续收据换一个 reserve 也不能
无证据称修复；一个合法较旧状态是否能指定别的 reserve 必须模型判别。
receipt 目前的新接受标志表示本地历史事件，不能解释为独立付款安全资格。
本次不改 one-use 授权、不增加储备最低数量或容量、不退款/释放支付本金。

下一可证伪假设：在保持原费额/成熟/容量/2016 窗口的原约束下，完整公开
费用授权模型可阻止合法旧挑战耗尽最高已接受状态的覆盖，同时保留无需每次
付款 on-chain first-sign 的目标。先一次120秒/1次纯模型/最小原生判别，
比较旧规则和明确的新授权条款；检查同一储备、多储备、多个合法旧状态、
同序冲突/隔离、终态后返还及独立接收视图。终态、反例或预算即退出并保留，
未定义授权不得直接改原生；不得以16条上限当16条接受最低门槛。
具体源代码修复必须另立完整新 profile/source 与全新 signed no-value fixture，
原 V7 反例、source、cold、owner/witness journals 都保留；新通过不能回写旧失败。

下一模型可以比较 one-use 旧授权与显式 owner-authorized bounded fee-budget
候选：每次只消费准确费用，剩余保护余额继续在 E、绑定原始授权和当前完整
原生 successor，严格更高状态防重放，settlement 才返还未用预算。不得从旧
one-use authorization 推导该新权限。模型必须界定 cumulative spending ceiling、
窗口内有序多次挑战/同块顺序/费用上限/CPU与slots、top-up和耗尽停收条件；
即使余额保持，也不能声称克服任意审查/缺quorum或截止最后一块后的反应延迟。
这是待判别的新完整授权模型，不是本轮已实现行为或新增资格。

最终来源 `4110ffc46e80f80a83ac0f4d2ead624efe1137abfe1f4644f8c01e7533438ad2`、
binary `57dd7cd932f770efabdc6157ab0a2e35179e83a6dcbeff776feb07d546edefce`
下34+184 native行为/strict/build及70 CLI步骤均终止通过；CLI14.874秒，
共享回归221.791秒。171 core文件及最新冻结正文/PDF/receipt逐字节未变。
唯一汇总 observer 先用了错误的基线相对路径而拒绝，原件保留；修正为准确
crates/rld-value-successor路径后只读核验，不复跑任何native或旧strict。
完整依据：源绑定结果/风险（历史证据保留于本地归档）。
