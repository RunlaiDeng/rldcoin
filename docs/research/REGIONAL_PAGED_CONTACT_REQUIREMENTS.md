# Paged Native contact and complete evidence contract

S6–S7/S11/S17, I4–I6/I10 and F remain mandatory. This contact contract does not grant independent, long-history or physical-route qualification.

## 实现契约

新源码绑定的明确signed paged profile新增 `Contact(Frame)` 完整事件；原wire V3
不变。保留exact canonical frame及其全部证书、owner commands和事故；每次接收、
append、历史审查和cold均从pinned signed genesis验证完整有界proof。
目的区不能从本地/peer cache填补未携带的前驱。证据认证不选择本地finality，
不import/credit；只有独立本地BFT Import与原生成熟提供收款可用性。

最多256 contact records；原64活动集必须保留每条contact的source anchor、
所有价值/receipt依赖与各地区latest，否则拒绝。全原件保留，历史冲突扫描包括
contact原证据。精确重试在完整后来信封和当前原生历史重新认证后不增加事件。
原完整payload页及durable publication顺序不变；未完成出版仍拒绝，不授恢复权限。
保留logical64/256、wire3MiB、object/evidence8MiB及archive4096/256MiB。
本路径没有将proof拆成多条并绕过logical64，也没有serialized Ledger授权。

改变profile文本及native source后使用全新无价值signed genesis/currency；
旧private stores/余额/签署保管不能转换。旧绑定不继承新实现。

## 完整原生入队与停止核验的当前契约

`Store::bft_submit` 必须经 `Store::proof()` 从签署创世完整重放并携完整因果证明；
分页诊断视图的地区高度排序不能授权进口owner提交。保留完整原命令、证据多重集、
wallet批准/预留、独立caller与所有边界；入队不是扣款或签署共识。创世只读接收端
不得靠本地历史补未认证依赖，坏后置证明/缺前置/坏owner必须拒绝且不改变状态。

停止核验使用已有原生 `bft-network-check-batch`：最多4份完整原始信封，总8MiB，
每份3MiB边界仍由Native拒绝。每个完整后来信封仍认证，整批失败不返回成功，
不开Runtime、不catchup/recover/sign/reconcile或采用头。逐批绑定精确原输入摘要、
原货币/地区、完整ordered results/原value、verified/no-ledger-change/no-signing。
保留原完整payload，不能以digest替代Native验签。
