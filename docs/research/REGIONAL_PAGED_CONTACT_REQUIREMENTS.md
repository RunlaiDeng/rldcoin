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
前述源86短例不是新进程、三地区onward/return、普通Runtime/TLS、完整fault/2016窗口、
真正中断、cross-device/独立保管或物理路线资格。新增contact anchor的64集耗尽和
完整事件页字节耗尽也未取得持续负载资格。高度66完整proof仍OPEN。

## 历史约定：后续三地区范围（已执行，结果如下）

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


## 2026-10-05 因果证明修复与实际三地区循环

[各范围、准确来源和终态](../operations/evidence/regional-native-paged-cycle-outcome-20261005.json)。
原首范围5.212秒因测试helper误用不存在的减法函数而编译失败，未创建新fixture。
只改为checked Amount API后22.146秒实际失败：Earth4付款99已在Proxima3成熟，
Proxima实际消费该进口输出、owner授权继续转出98、到高度4已有原生出口；
完整carriage却被 `missing verified source checkpoint` 拒绝。Proxima已有8检查点、
1出口/1永久import，拒绝未改账本/native head/私有库存；旧现场及完整原文保留。

Native分页视图按地区height排列，Proxima1消费的Earth4证据在它后面。原地域
高度不能给不同地区建立因果先后。修复只对原有有界完整closure安排顺序：
checkpoint previous、每个完整block anchor、Import source checkpoint及epoch closing
证据均先于依赖者。Ready选择保持已有效retained次序；缺依赖/重复statement/环拒绝。
依然独立完整Native验签、genesis/owner/value/finality/era重放；排序不授任何权利。
所有原snapshot完整字节保持，逻辑64/256、8MiB/3MiB/4096/256MiB不变。

一次新180秒范围实际36.714秒完成最小原生反例、actual三地区循环、新进程cold、
入口compile和地区库strict。最小反例中原height视图必被Native拒绝，重排后与
完整原snapshot多重集合相同并被Native认证；没有删证据或重签certificate。
实际循环10.498秒，Earth7/Proxima4/Andromeda4，净99→97→95。Onward/return显式
只选99/97原import coin作为input，source fee1/destination fee1后确实消费；
每transition检查issued/liquid/escrow/pending守恒，最终escrow0/pending0。
每条contact证据先pending、独立本地认证Import再等原生2块成熟；exact retry不
append，重复Import在candidate阶段拒绝而不签署。三出口和三个永久import tombstone
都保留。三笔完整carriage分别4/8/12检查点、52189/103537/154885 frame bytes。

子进程从signed genesis完整重放三个Native、十二Agent、三个owner wallet，验证
另存caller heads、每进口与原输出状态及最终守恒，全部私有hash/mode/size/mtime
不变。公开fixturekeys由同一控制者复用，仍非独立/cross-device保管；controller直接
搬运frames，仍非ordinary Runtime/TLS或完整fault。该准确来源87文件
`e85db2d7ef1508aa5a5840f437d474cfb0ed6d0e17d66c0163c24acefb40d87a`。

最终枚举修正保留了原DFS完整ordered/duplicate dependency遍历；只有完整carriage
排序的依赖行转换为集合，避免改变缺旧前缀时的容量拒绝位置。一次45秒最小
范围实际28.414秒完成同一原生因果反例/完整原文集合认证、九个受影响regional
legacy contact方法、CLI compile/lib-tests strict。未重跑36.714秒三地区或原高度66。
最终来源87文件 `26076a643c2652e3fde1b1f178ea1bec0f1181836e5194807aec741cc125ade2`，
implementation `668b95fe03daac2b295d27dc7b4b622955e99ea2f8c976e898d83b4856b43f72`。
三地区通过仍绑定上述e85d来源，不能称在最终来源全套重跑。保存最终library test
binary仅证明这份测试构建，旧main binary未重建、旧绑定不继承新行为。

九个旧contact方法属于regional库，绝不替代rld-value-successor严格验收。来源相同
的3.948秒额外legacy记录保留；其controller继承了三地区fixture模板描述，实际命令/
日志只有这九个方法，不能读成另一次十二Agent/三地区范围。Checks中的counter字段
仅收集运行时refusal日志；原生最小反例的旧视图拒绝由测试实际断言及完整日志支持。
所有旧complete fault、source66 bound拒绝、超预算和编译失败保持未通过。

## 历史普通节点接入最小判别（已执行；以下保留原假设）

源码检查：`main.rs::Action::Proof`直接输出height-sorted `journal.evidence`，
`regional_bft_node.Runtime`以native `proof`填充每个完整BFT网络信封。
Native Envelope.verify要求独立完整proof；因此不能从上述接触Frame修复推断普通
节点的BFT carriage已可用。这是已定位的源码疑点，尚无实际新信封反例。

假设：实际跨地区import/onward后，普通Native proof接口仍能生成完整可认证的
BFT canonical envelope，所有原body/certificate与证据保持。一次全新签署无价值
源4/import3/onward4最小fixture；旧CLI视图与Native canonical pack/expand/verify
逐层判别，坏后来cert/缺依赖必须在sync/签署/head改变前拒绝。
单次60秒/1次含compile/wait，network0，最先失败/终态/预算即退出。
若实际拒绝，先修原生proof接口及来源绑定，再另建新identity的binary做ordinary
startup/mesh/TLS；不直接启动完整fault、不原样重复源66，不保留旧余额/保管。
所有原600/60/24/2016、成熟/票数/容量保持。此路径仍不解决post64 complete authority；
根化DAG/compact完整授权模型、完整2016窗口、独立/crypto/physical资格继续OPEN。


## 2026-10-05 普通证明及真实启动的终态

[证明接口各来源与终态](../operations/evidence/regional-native-paged-network-outcome-20261005.json)、
[真实启动反例、修复与最终绑定](../operations/evidence/regional-native-paged-runtime-retained-outcome-20261005.json)。
普通完整BFT信封实际23.424秒拒绝 `missing verified source checkpoint`；source4/import3/
onward4已原生扣款，拒绝时账本/head/全私有库存不变，不退款/重签/恢复。
Store.proof先从pinned genesis完整健康分页重放，再给每个完整checkpoint按前驱、
block/import/epoch依赖排序并独立Native验签；CLI调用此接口。旧legacy证据的
原顺序/重复字节保留。缺已退休前驱继续拒绝；不以cache或分帧补不完整授权。

22.375秒修复样本在私有观察note父目录政策拒绝，保持失败，未放宽权限；新建
0700观察目录后28.110秒Native/旧原文兼容/实际CLI通过，但测试err_expect告警令
整scope失败。仅改expect_err后，新来源99f85976/implementation38247bdb的一次60秒
范围实际44.063秒完成新Native夹具、独立release CLI和地区strict：实际CLI proof8
检查点、完整pack/check及原message binding一致，旧视图、坏后来证书和缺前驱拒绝；
首尾pinned history-check及全部私有库存相同。Legacy兼容复用前一范围未改的生产/
对应测试字节，没有宣称重跑。Checks反例布尔只收集运行时日志；通过测试对旧
视图拒绝有实际断言。Debug旧binary不变，不能继承新release工件行为。

同源下一真实Runtime范围5.825秒失败：构造器已返回且height4，但只保留1 Finalized，
没有Signed。停止后的结构性只读诊断看到compatibility header records0、独立分页
manifest count9；这些数字不授Native权威。源码定位CLI直接遍历空journal.records。
未再启动/Native打开/恢复失败夹具；失败发生在最终库存/cold检查之前，不能声称
该失败范围已经完整cold或验证了全库存不变。

Agent.retained_messages对健康保管与Native历史完整认证后，读取原分页流的每个
完整有序record并返回原message，序列化数组计账checked且原8MiB拒绝不变；legacy
走完整Journal状态认证并保持原message字节。接口不恢复/首次签署/sync或采用head。
库测试明确paged空头与>=8实际记录不同，返回数等于完整record_count，全部消息
各自构造原生完整Signed envelope并验签；legacy测试比较每个原message序列原文。

最终source87文件 `b4bc437957704130028e2732b8b7afb843740aeaa5fff685f23ba0dd05bf3aa7`，
implementation `cf4a2c7e1161811e7e2440fb36070f60e2f7f0f94f84a2144818075ec0d99069`。
一次60秒/1次actual47.519秒含compile/build/wait：全新signed无价值E4/P4与八Agent/
两owner wallets；实际只花原import99继续export98；四Agent实际CLI返回完整原消息
数与Native status相符。普通Runtime无key、无pending/outbox、stop_height4，构造
1.699秒，保留9 Signed+1 Finalized且local carriage，cold逐份Native认证10信封/8
完整检查点，state106492字节/32MiB、展开认证788975字节。Read-only Native白名单
实际记录无tick/sign/recover/sync；另存原voter head转换成Runtime配置并逐项核对，
没有从当前观察采用陌生head。原Native/signer/wallet/caller全私有hash/mode/uid/
size/mtime与Runtime caller bytes不变，停止cold也不改新Runtime私有库存。
Release CLI SHA `2e72ac63c32cf76596b0a152121f3b7caa1ad7b32ccec13e501d348784c9b76d`；
地区lib/tests严格检查exit0，无生产豁免。Core171/旧价值两文件/冻结内容/旧debug
binary再次exact核对不变。全部失败及原始报告、源码、私有fixture保留。

这些样本没有Service/TLS/普通网络广播/共识tick，不代替完整fault或2016窗口。
历史三地区e85d通过不变来源而复用，没有在最终源码重跑。Post64 compact-complete
native authority、长历史、独立/cross-device保管、crypto与physical门槛继续OPEN。
旧价值库两告警与120秒耗尽独立OPEN；地区库/旧regional原文兼容均不能替代。

## 下一ordinary Service/正常广播判别（尚未启动）

假设：已认证分页Native的普通默认Contact Service能在同一生命周期构造，并将
完整保留信封通过正常mesh广播交给一个配置邻居，而无需控制器搬运信封或新签署。
一次全新signed无价值import/onward夹具，stop_height4、无私钥输入、原voter/caller
绑定；新同机私有transport/pinned TLS与明确ground邻居，拒绝外部端点。构造/
有界carriage后独立完整Native逐份核验及原始head/库存；只证明运输保管时，必须
与ledger import/maturity分开，不能把出站排队称为收件或收款。
总墙钟60秒/1次，compile/夹具/等待计入；首startup/auth/carriage/native/head或
非预期私有变化失败、完整有限判别、预算任一到达退出。源码/能力/环境变化才
允许下一新scope；不复活失败夹具、原样重复、不签新款/恢复/退款。
原600/60/24/2016与成熟/票数/8MiB/3MiB/64/256/512/4096/256MiB保持。
多节点ordinary默认调度与实际value、fullfault/longhistory/independent/physical另验。
