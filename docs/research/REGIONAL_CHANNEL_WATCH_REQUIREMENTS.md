# 原生已接受状态看守：V7 地面候选

本候选对应冻结白皮书 §7 / S6–S11 的状态观察、预授权费用及原生纳入义务。
正文/PDF/官网不改变；全部 S1–S18/R1–R24/I1–I12/A–G/N1–N10/P1–P8
仍是项目验收目标。V7 新 admission/kernel/profile/implementation 只用于全新
签署零分配无价值 fixture；V6 或旧来源的值、私有目录、钥/头均不迁移。

## 真实最小判别和实现

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

## 实际失败：R-CH-FEE-01 费用覆盖丧失

**OPEN / 安全验收未通过，禁止把现有 receipt acceptance 采用为安全生产付款。**
`native_channel_watch_highest_complete_history_stale_head_and_consumed_exact_reserve`
在旧一次性储备规则下接受 q1 和 q2，两者选同一个原生已成熟足额 reserve；
Close(q0) 后，合法 Challenge(q1, fee=1) 消费该 one-use reserve。q2 仍是最高
accepted，但 watch 明确返回 reserve absent/consumed，不能生成其 Challenge。
Native heads/cold replay/U/E/T 都正确，故守恒、收据持久化与 watcher 存在不能
证明最高付款受保护。该行为是付款保护缺口，守恒不能替代费用覆盖。

范围：现 V3–V7 的 `Reserve` 授权为同通道任一合法更高状态的一次费用；其
selector 未限制某个 invoice/sequence。仅给后续收据换一个 reserve 也不能
无证据称修复；一个合法较旧状态是否能指定别的 reserve 必须模型判别。
receipt 目前的新接受标志表示本地历史事件，不能解释为独立付款安全资格。
修复不得从 one-use 授权推断新费用权限、不增加储备最低数量或容量、不退款/释放支付本金。
