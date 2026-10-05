# 分页原生接触接收：完整事件与独立证明上限

范围：S6–S7/S11/S17、I4–I6/I10及F。唯一源码/fixture负责人为原任务；
正文/PDF/官网冻结，旧价值库 VALUE-STRICT-01 独立 OPEN。
[准确来源与各范围](../operations/evidence/regional-native-paged-contact-outcome-20261005.json)。

原180秒范围正常终止于121.522秒：四真实原生签署人到源高度66，原生owner出口
已经纳入，活动检查点64；完整因果证明被 `contact dependency bound` 拒绝。
出口、native head、账本及完整私有库存不变，不退款、不重签、不恢复。
这一来源原件保留，当前源码未重复该长范围。当前回归函数改为断言该已知拒绝，
没有执行它；“预期拒绝”的回归通过也不能称远程付款资格通过。

另一次全新30秒最小反例在18.744秒确认：源高度4/完整4检查点，目的分页库因
旧式日志写入拒绝，状态不变。这是独立缺口，不是高度66失败的替代解释。

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
旧private stores/余额/签署保管不能转换。主程序未重建，旧绑定不继承新实现。

## 已观察与仍待验

首次修复3.710秒编译可见性失败。修正后26.842秒范围中有限native付款/cold及
入口compile通过，但整个范围因测试helper多余Box分配strict失败，保持未通过。
只修正该测试分配后最终25.002秒范围通过：全新源高度4/目的高度3、八个实际
Agent、owner100出口、source fee1/destination fee1、99实际import及原生2块成熟；
完整same-process source/destination/八signer/wallet cold及caller heads/私有库存不变。
精确重试无append，坏后来完整签名、缺前驱、错目的区均不改变状态；只读native
副本中重新计算frame digest/message和manifest head的坏签名被完整cold拒绝。
最终CLI仅compile和地区库lib/tests strict通过，无生产豁免。

来源86文件 `659dbad3c6d109bd5a584f8a49ae1102f8875007e04a593c975e4ff2eba72a96`；
实现 `d50a9daa4d5de6488df22bed9673f3ad751ca2b55ea5a8102456a0d937b31d3a`。
core171、两旧价值文件、冻结文件及旧main binary字节未变。
短例不是新进程、三地区onward/return、普通Runtime/TLS、完整fault/2016窗口、
真正中断、cross-device/独立保管或物理路线资格。新增contact anchor的64集耗尽和
完整事件页字节耗尽也未取得持续负载资格。高度66完整proof仍OPEN。

## 下一条可证伪范围（尚未启动）

假设：在原有完整proof64界内，新typed contact能完成Earth→Proxima→Andromeda→Earth
实际owner付款、继续转出与返程，并保留永久ID、每步实际debit、费用、守恒和成熟。
一个全新signed零初始分配无价值fixture；四equal voters/每地区独立journals/heads，
实际有序3-of-4 prepare/commit；共享公共fixture钥匙仍不是独立保管。
单次180秒总墙钟/尝试1，包含compile/wait，network0。原600秒stage/60秒轮/
24新增高度/2016窗口、quorum/maturity及全部容量不变。
按每步独立export→完整Frame→native pending→实际认证Import→成熟判别；
不能用retained证据、构造command或余额总量代替收款。完整pinned冷重放结束后
私有全库存/head不变才通过。首个owner/proof/capacity/conservation/import/maturity/
cold失败或180秒退出，保留exact源码和现场，不复活旧失败、不退款/重签/原样重跑。

独立下一证明设计门槛：明确根化良基DAG和compact-complete native authority模型，
处理深度、fanout/shared ancestors、永久imports、认证CPU/RAM/disk/recovery和
污染传播；旧64完整proof不能被分帧/哈希/cache降为不完整授权。没有新模型/profile/
原生反例前，禁止再跑高度66同一长范围或声称全窗口/远程长期历史已解决。
