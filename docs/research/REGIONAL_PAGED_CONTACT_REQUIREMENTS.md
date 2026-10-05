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

## 历史ordinary Service/正常广播判别（已执行；以下保留原假设）

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


## 2026-10-05 默认生命周期、TLS及正常接收的有限验证

[准确来源、四个终态和下一范围](../operations/evidence/regional-native-paged-service-integration-outcome-20261005.json)。
Native/Python未改，87-file b4bc4379 / implementation cf4a2c7e、release CLI
2e72ac63及原47.519秒strict/legacy证据保持。四次各60秒、1次的新私有无价值
范围均停止，不打开失败现场：9.189秒因观察器误读TLS字段失败，完整cold未到达；
修正观察字段后11.132秒通过默认Service广播、真实spool邻居10信封/回执和完整
原生检查。启用TLS监听仅说明适配器开启，该spool样本不是TCP交付证据。

下一新两Service样本5.675秒因观察器硬编码18库存失败，启动网络之前拒绝；新
地区同区域副本从签署创世初始化0、完整原生8-checkpoint同步到4已通过，但不能
称Runtime/TLS或全库存通过。按Native原消息/record_count推导完整库存后，全新
范围16.247秒通过两个默认无subcommand入口及正常TLS1.3传输，各自9 Signed+
1 Finalized的库存仅共享Finalized，普通接收后每端完整保留19，每端10个实际对方
原信封/运输回执；原生完整认证与普通依赖同步在去重前执行。控制器未造/搬信封，
两个进程干净停止；每端19信封/8-checkpoint和完整已认证前缀停止cold通过。

合法接收追加Native Evidence事件，可改变storage head与页manifest；保留每个
原不可变对象、完整旧前缀和原始信封。金额/高度4/tip/finality/epoch/permanent
import exact相同，原wallet/signer/caller及新Runtime caller bytes不变。最新Native
head仅是本地观察，另存后完整pinned genesis replay，不是独立最新权威。新副本
不拷贝ledger缓存、signer/wallet/key/runtime保管来初始化授权。四carrier中仅两端
实际运行，固定localhost TLS、公用fixture钥；不资格独立或跨设备操作。

这两个通过样本只验证完整承载、正常接收和保留认证。实际import99/onward98
属于新库夹具准备，并非Service实际新增进口；实际净97收款/成熟/继续转出/返程、
fullfault/2016/post64/longhistory/PQ/physical保持OPEN。原失败仍失败，旧源66不重跑。

## 历史普通进口与成熟判别（已执行；以下保留原假设）

可证伪假设：新鲜当前源E4/P4夹具中已经终局的P出口98，通过普通默认TLS中继
到新授权Andromeda；四个实际A Native/Runtime从签署创世及独立voter/caller目录
启动，完整认证出口及因果证明，普通leader从pending imports选择并由原三取四
prepare/commit实际纳入，指定收款人12净97在原两块成熟后可花。不以运输收据、
状态摘要或Python库存代替Native value授权。

一次180秒/1次/五个Native进程，夹具准备/启动/等待/停止cold全计时：一个无钥且
stop_height4的P source、四个fresh A voter，以明确固定localhost TLS拓扑
P–A0–A1–A2–A3连接，拒外部端点。只使用本次新夹具原出口，不发替代owner请求。
Controller不造quorum/block/import、不直接contact-apply/finalize，不搬运信封。
A有限stop_height4保持原24新增高度内；原600秒stage/60秒轮/2016窗口与maturity/
quorum/容量不改。缺可选telemetry保持unknown，不造height0或误判原生phase失败。

首实际auth/conservation/import/maturity/head/custody失败、完整有限判别或180秒
退出，保留原件/来源/私有目录，不重签/退款/恢复/原样重跑。通过须四副本实际
进口/永久ID/精确收款输出及成熟可花、兼容E/P/A完整守恒，clean exit后四Native
完整cold、所有完整信封、各voter与另存caller精确head认证；原源owner保管保持。
正常签署及认证接收允许新native/voter/caller日志合法推进，不能要求它们全目录
不变，也不能采用陌生head。失败与unknown如实保留。

即使通过，也只证明一段既有出口的实际接收：普通source owner提交/再次转出/
返程、fullfault/2016、post64/longhistory、独立/cross-device/PQ/physical另验。
旧价值库strict仍独立OPEN；源66只有compact-complete授权模型/profile及实际
Native变化后才允许另一个新长scope，不以hash/cache代替完整授权。


## 2026-10-05 普通实际收款终态与核算更正

[准确来源、各次失败和实际收款](../operations/evidence/regional-native-paged-ordinary-value-outcome-20261005.json)。
Native87/source b4bc4379、implementation cf4a2c7e、CLI2e72ac63和节点Python未改；
最终一次180秒预算actual65.805秒通过五个默认Native Service/Runtime。既有P出口
98经固定localhost TLS普通中继至新A地区，四个独立A Native/voter/caller目录各自
执行原三取四prepare/commit，实际在高度2进口净97，高度4原两块成熟、精确原
收款输出仍97且可花、finality覆盖进口。队列、运输回执和Native收款保持分开。
Control不造/搬运信封/投票/进口块；source为无钥stop4，原owner请求已在新夹具
准备期间签署/纳入，故不称普通source owner提交、onward/return的通过。

停止五进程均exit0：五Native pinned完整历史和voter/caller精确head检查；Runtime
完整信封分别10/44/44/44/44，共186，各信封完整Native验签/重放；A各16份不同
完整snapshot原文包括合法cert变体，不把数量当checkpoint选定或去重权威。四A
最终tip/state/finality相同，原Source owner/signer/caller和不可变旧历史原件保持。
TLS1.3/固定pin/无降级和原2worker/3秒attempt/.2秒锁边界逐次实际观察核对；所有
最终进度观察无error，未知与失败尝试仍原样记录，不授任何保管/账本/签署权。
临时尝试失败之后只有正常完整认证/持久保管/原生纳入才提供对应成功结论。

原17.683秒范围因观察器把已认证negative ACK当永久失败而停止，未成熟/cold；
0.973秒实际TLS持锁反例确认队列/无ack及后续真实保管。新62.910秒范围已实际
四副本进口/成熟、五Native/caller/176信封cold，但最后固定300断言失败，原源全
库存最终检查尚未到达，整scope仍失败。新26.298秒范围因连接重置被错误判为
永久故障而停止，未完成成熟/cold。0.694秒原2连接容量反例产生TLS EOF，源
精确证据/未ack保持，随后正常重试获得真实receipt；它不复现旧reset或证明唯一
根因。失败现场323/668/461私有文件全部hash/mode/uid/size/mtime不变；未打开
原失败Native/Runtime、恢复、退款或签替代owner请求。

**核算更正，不是经济参数更改：** 历史小夹具300发行预期曾进入前一integration
next-scope文字和controller；这个明确签署paged profile继承channels的起源
reserve-era曲线，Native Trust要求cap=10^35、初始reward=2.5*10^29 runlai，
执行内核逐块检查完整起源累计发行。一次network0的5.008秒新E4/P4/A0完整
Native状态/proof核对发行10^30、未进口毛98/净97；非起源发行、错received、重复
进口、遗漏escrow和错currency核算数据拒绝。最终实际E4/P4/A4集合issued与
liquid均10^30、escrow/pending0，完整每区及全exports/imports/received守恒。
数字是无价值fixture账本观察；历史报告保持原件，此前300预期不能提供当前来源
资格。不以Python账本/cache或状态hash授权Native，也不忽略任何真实channel escrow。

当前来源地区strict/legacy与CLI编译复用47.519秒准确证据，不重复；旧价值库
VALUE-STRICT-01仍独立OPEN，两处告警和120秒耗尽/原因未知均保持。完整fault、
2016窗口、source66/post64 compact-complete授权、longhistory、PQC/独立/cross-device/
physical和全部S/R/I/A-G/N/P资格继续OPEN。原600/60/24/2016及所有bound不改。

## 下一普通源端owner提交判别（尚未启动）

假设：全新签署零分配public-fixture currency/root采用准确当前paged admission与
原发行曲线，四个Native/voter/caller从genesis0创建并保留同一原始日志/锁/头。
原生认证准备前缀3之后，独立owner10钱包、caller及公共fixture key对一个毛100/
目的手续费1/本地fee1的精确出口请求审查与签署；typed bft-submit仅排队。四个
默认Native/Runtime正常携带该完整Submission及各自投票，在高度4由原三取四
证书实际纳入、扣准确原input并保留唯一export，排队/签署/transport不冒充debit。

总120秒/1次/四Native进程，全部root/准备签署与native前缀认证、owner动作、
startup/wait/停止cold计时。运行阶段不让controller造票/块/搬运；保留每个原始
voter锁和独立caller，不用历史Fixture的值/钥保管或cache初始化，不发失败现场
替代owner请求。先排队时四账本不debit；后完整停止cold须四相同 certified source
前缀及准确输入/100 export、owner/voter/caller heads、全部完整信封、原发行及
本区/全观察金额守恒。只有运输失败尝试保持unknown/零权利；所有实际typed/native/
auth/amount/head/custody拒绝或预算到达退出，失败不恢复/重签/退款/原样重复。

这一范围只验新ordinary source owner提交与纳入；目的实际收款、onward/return、
fullfault/2016/post64/longhistory/独立/crypto/physical另验。既有600秒stage/60秒轮/
24新增高度/2016窗口、成熟、票数、容量不变；不得仅因这些通过复跑源66长scope。
