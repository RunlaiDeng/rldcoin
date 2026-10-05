# 普通BFT完整历史/签署日志的共用原生保留层

状态：**普通Store/Agent写入、完整历史锁重放及显式原响应恢复已接入；首次300秒集成预算耗尽，容量/新进程/完整窗口资格仍OPEN**。
目标保持[完整历史合同](REGIONAL_BFT_WINDOW_HISTORY_REQUIREMENTS.md)及
[分页保留模型](REGIONAL_BFT_PAGED_HISTORY_MODEL_V1.md)。这是完整原生集成的一步，
不能将测试该层更多记录视为解决原第65检查点或128-record签署门槛。

## 已实现的原生代码与权限边界

`tools/regional-ledger/src/retained_pages.rs`实现
`RLD-NATIVE-COMPLETE-STREAM-PAGES-V1`。独立私有目录持有OS lock，scope绑定已
native验证的currency/region/admission、当前implementation、Ledger或BftSigner
用途及origin context。origin是调用者提供的存储上下文，**不是最新状态见证或
签署保管来源**；存储用途/公钥不授予成员资格。初始71-file来源没有新signed admission；后续77-file普通Store明确采用见下节。
普通Agent写入未转换，旧采用/签署目录没有转换。

只保留完整typed records：16条封为immutable页，当前清单包含有序页引用和
少于16条完整尾记录。页绑定scope、起始offset及exact predecessor；记录head
逐条绑定previous、index及完整canonical record。完整重读所有页/tail/heads，
不保存或从磁盘读取可初始化native账本/锁的Ledger/state cache。

`visit`的consumer必须从已pin genesis开始、完整native认证/执行每条记录，
把派生状态暂存到全部页、tail与外部exact head验证完成后才发布。存储API的
成功与`storage_head`只说明字节完整性；真实Ed25519测试也不等于native BFT
请求执行、epoch、所有者授权或Ledger acceptance。未认证的record可以有正确
字节head；必须由native consumer拒绝它，不能用页hash替代认证。

每页、tail清单与完整publication对象≤8MiB；一次batch≤16完整records，
当前tail+incoming完整编码先限定≤8MiB。完整档案≤4096文件/256MiB，计入
retained orphan、LOCK、当前manifest及发布期间的完整pending/commit包装。
只有全部容量检查通过才写；容量不足不推进head/count或创建pending。所有
文件检查owner、private mode、单hard link和无symlink；未知root/object entry拒绝。

## 已确认并修复的发布反例

初版先fsync待发布清单，后写完整封页。15条尾记录+第16条签署record封页时，
清单中只有新页reference，完整第16条仍在内存。故障在pending落盘后、页写前
发生时，目录拒绝继续但未保留该record。2.678秒最小新scope真实确认：准确
regression退出101，输出`pending lacks the exact complete signed record`。
这是已证缺口，原版不能获完整未发布响应保留资格。旧代码可由
[准确原生修复patch](patches/native-retained-pages-complete-pending-20261005.diff)
还原；[反例证据](../operations/evidence/regional-native-retained-pages-pending-counter-20261005-checks.json)
将counter证明与regression通过分开。

现版顺序：

1. 完整publication包含previous head、拟发布清单及所有新页的**完整原文**，
   先private create/fsync file及directory；不能只存引用。
2. 原文完全一致的新页发布并fsync，原对象不可覆盖；重复对象再次fsync。
3. 单独完整commit清单private create/fsync，rename为当前manifest并fsync目录。
4. 只在所有独有record原文已完整持久保存在页/manifest后，移除成功完成的
   冗余临时包装并fsync目录。任何未完成操作不清理残片；失败的实例不继续。

pending后、pages后、manifest已发布后三个故障注入边界都保留完整payload。
前两处原manifest不变；第三处磁盘可能已新manifest而内存head/count仍旧，
pending保留，旧/新head均不能自动打开或采纳。此层没有recover-only入口。
后续原生恢复必须核对完整已签request/response、原caller过渡head、用途/创建
来源和全部native历史，只能恢复确切既有响应，不能first-sign、重置锁或删除
不完整目录。实际SIGKILL、断电和跨设备恢复仍未验证。

## 准确限定证据

初版一次120秒scope实际20.746秒整体未通过：七个有限行为检查通过，strict
拒绝测试中`cloned_ref_to_slice_refs`。仅测试改用引用切片；一次60秒范围6.334秒
通过受影响发布行为和native库/tests `-D warnings`，无新增allow。原失败保留，
不将库strict替代旧价值库VALUE-STRICT-01。

数据缺口反例后修改publication协议，必要重验全部受影响append/refusal行为。
一次60秒scope实际22.139秒通过八个行为检查和native库/tests严格检查。一个
child入口标记ignored，实际由父检查分别在Ledger/BftSigner两个purpose调用
独立进程：每个流145条完整公共fixture签署record，9个完整页和1条tail；完整
record authentication与库存/hash/mode/size/mtime不变。**这些不是145条实际
BFT votes/原生账本高度**，是存储/验签consumer样本。同机外部heads不是独立
latest；故障注入不是实际进程/断电资格。

缺页/损坏/乱序/前向引用、旧head/错scope、实际held OS lock、未知root entry/
hardlink、未认证但hash自洽record、4096-file容量拒绝、8MiB输入拒绝和三发布
边界均限定在该来源。另一个最小aggregate-byte判别保留恰256MiB sparse残片，
加manifest即超容量，要求原子拒绝；它不重复145-record/文件容量scope，不称
有效页或持久custody。其终态单独绑定。

该byte范围首30.015秒/-15耗尽，编译2.08秒后未留下阶段终态，仍未通过。
换判别方法仅改测试观察：通过source/hash绑定本机`/usr/bin/openssl`，与Python
SHA256交叉检查，再对每个文件做完整SHA256和mode/size/mtime库存，未采样或
采用缓存digest。一次新的30秒scope在16.924秒完成focused byte检查及strict。
原始256MiB retained length加manifest实际拒绝，前后全部库存不变；native
拒绝两次累计12.455173秒、前后完整观察合计0.359867秒（只该样本）。旧30秒
scope具体卡在哪个阶段未知，不能从新计时断言旧唯一根因或已经优化Native。
[字节容量结果](../operations/evidence/regional-native-retained-pages-byte-observer-20261005-checks.json)
保留旧失败；生产primitive字节未改，没有打开原停止目录。

Native源新增该层后当前library identity改变，原69来源/主binary/历史有限scope
只保留原绑定资格。未重建或重新资格主candidate binary，没有启动旧fixture。
后续全新currency/genesis必须签署当前真实implementation，零初始分配，不迁移
旧价值、caller heads、fences、wallet或signer。Core171与冻结body/PDF不改。

当前71文件source commitment
`0bdde7ce08cba36710cd2fa51d4c7d67b7054f34e468cfe2d0e7a244b8186a69`，
library implementation
`98326b85f3b4ccc9774221a3d674b14fc7bc80d64f0c14f501ed8d93e78db8b9`；
最新test binary、准确各scope/source/旧失败与未完成项绑定在
[总结果](../operations/evidence/regional-native-retained-pages-outcome-20261005.json)。
Byte observer只改变测试源码与implementation身份；生产primitive未变，复用
此前八行为组的准确primitive来源，不宣称其在最终test源码上重新完整运行。

## 原71-file来源时的完整接入待办（历史，后续进展见末节）

H-native-paged-retention仍OPEN。下一源码动作是明确新signed history/admission/
signer domain，普通Journal保存完整本地certified events，普通Store从pin genesis
按顺序使用共享native执行核重建；BFT Agent则使用同层保存完整request/response/
observation/previous head并重建prepare-QC锁，钱包按当时完整native prefix审查。
新profile拒绝旧格式/admission、epoch缺口及未经执行的prefix，不降低3-of-4。
64证据/128活动观察可限定工作集，但所有签署原文必须仍在完整档案；跨范围的
依赖、永久ID、旧finality/incident仍需完整认证，不能移出工作集后隐藏冲突。
原profile的64snapshot/128-record、256 active blocks及网络3MiB保持原义。

完整接入可审阅后，才执行原计划**一次300秒**真实Store+Agent容量边界/新进程
cold/坏档/旧head/出版失败组件判别，编译和等待计入；预算目前未使用，网络
campaign预算0。2016真实窗口须另作实际成本预算，不增加原600sec stage/
60sec round/max24、成熟、票数或容量。首失败/完整判别/预算边界即退出；
失败先修复具体反例或换最小方法，不原样重跑。

完整BFT、epoch、owner/custody、完整价值DAG、实际窗口、独立最新状态、PQC/
physical和所有S/R/I/A–G/N/P义务仍未完成。旧VALUE-STRICT-01仍独立OPEN；
当触及其库或候选发布门槛，遵守既定300秒修复/120秒实际阻塞诊断条件。

## 普通BFT签署的完整record内核接入（2026-10-05）

`bft_replay.rs`已由普通`Agent`的`Journal.state`实际调用，不再复制逐渐增长的
record vector来生成每个历史prefix head。只在进程内从完整immutable header开始
逐条哈希canonical record，补回原JSON结尾；保留原`bft-signer-journal-v1`域、
完整旧head字节、128-record/8MiB门槛。它不序列化state/hash见证，也没有缓存
native账本、原生观察、角色、时代、签名或锁转移的认证结果。

每条完整record仍认证exact predecessor及key、签署时原生历史父状态、时代/
creation/rollover来源、完整proposal/prepare/commit/timeout/fence执行和实际签名。
`Journal.state_from_retained`用同一内核读取完整页，先绑定exact header origin、
key、purpose/currency/admission/implementation，再完整验证每条record与两个
分别提供的storage/native heads。派生state只在全部读取和两个heads通过后返回。
它是read-only镜像，**不创建分页签署目录，不签名、不恢复、不采纳caller head**。
该73-file来源时普通Store仍未接入新certified-event stream；后续77-file进展见末节。
Agent写入仍是原格式，该73-file范围没有新admission。

一次120秒最小判别实际25.212秒完成（编译及strict包含）：全新当前implementation
零初始分配fixture，四实际Agents签署8提案、32 prepare、32 commit；8个真实认证
高度，owner付款99/fee1实际纳入并成熟。每Agent18完整records，mirror各封一页并
保留2条完整tail；每个历史head与独立完整JSON序列化oracle比较，普通与页读取
得到完全相同的原生锁/state/head。后部坏签名、错误用途及任一陈旧head拒绝；
Store按另存head完整cold reopen、四Agent和mirror同进程cold reopen后，原私有
hash/mode/size/mtime未变。单独受影响durable-lock/旧备份/keyless exact retry及
role-origin真实认证/certificate变体/完整旧日志head也通过；当前library/tests strict
通过。没有新进程、真实SIGKILL、跨设备或独立最新状态资格，也未测>128签署。

[准确范围](../operations/evidence/regional-native-bft-record-replay-20261005-stage.json)、
[终态](../operations/evidence/regional-native-bft-record-replay-20261005-checks.json)、
[绑定及下一门槛](../operations/evidence/regional-native-bft-record-replay-20261005-outcome.json)。
73-file library source `66ab6d204fda70dc8dae18b404f91b3de754c0f202ce4af549a619dd479547ee`，
implementation `a2e80dcf80e6b145cbcd398de4a23e94f1b214561f703d969c2420a89f2ffae6`；
旧main binary未重建/重新资格，旧fixture、通道费用反例和完整fault失败未打开或改称通过。

下一实现仍是明确新signed profile的**普通Store certified-event和Agent分页写入**，
包括完整genesis/value/钱包signing-height/远程依赖/历史incident、separate caller head
及已落盘signed response的recover-only。完成可审代码后才运行原定一次300秒集成
scope（含编译），遇invalid tail/容量/发布失败或预算即停止保留，不原样复跑旧
fixture；保留旧64/128严格格式和新活动界，不删除任何signed history。该300秒scope
尚未开始，本镜像检查不能替代它。第65检查点、真实2016窗口及独立资格仍OPEN。

## 明确新规则的普通Store分页接入（2026-10-05）

新签署 `RLD-REGIONAL-BFT-PAGED-VALUE-CHANNELS-FIXTURE-V1` 采用独立
`paged-bft-admission-v1`域，绑定完整V8价值/预算/发行及新保留合同。四固定等权
验证者、三ordered prepare/commit不变；epoch拒绝。旧规则、目录、余额和签署
保管不转换。普通Store启用immutable signed-bootstrap header及完整typed certified/
evidence/receipt/incident-index流，从pin genesis逐条执行后才发布账本；commit、
cold及钱包历史审查共用完整native replay，bounded Journal view明确拒绝授权。

每个certified checkpoint包含一个完整新block及准确前一认证末block。完整已
native执行的前驱提供进程内Ledger，不能从磁盘cache/body digest开始。活动
VerifiedEvidence最多64；保护当前finality、全部coin/export/channel/reserve依赖、
accepted receipt anchors及各地区latest，保护集满则拒绝。完整原件不删除；
历史body witness只在这次genesis执行后建立、最多4096。完整历史冲突扫描覆盖
已退出活动集的原件。所有后来完整envelope再次验签，并按其自身地区signed
profile校验形状。根目录保留证明/metadata/residue与页共计4096文件/256MiB；
8MiB对象/current ledger/evidence、3MiB网络及旧64/128规则不变。

首编译5.680秒失败（work-valid Result与私有test接口）；修正后的8.563秒范围
在height3 candidate失败：watcher仍按bounded Journal重建，缺少前驱segment。
两失败准确来源保留。修复为receipt index从完整native Store流重放，且原生
Block历史事件准备已认证完整parent witness；未关闭watcher或跳过认证。

一次120秒范围实际88.056秒通过普通Store连续65认证高度，活动64；钱包实际
付款99/fee1并成熟，历史signing-height与固定latest head同进程cold通过。65个
certificates使用公共fixture prepare/commit各195签名，**没有BFT Agent投票保管**。
坏历史签名、签名完整但native Import无效的新尾、坏state与坏完整parent均拒绝，
账本/head/全部私有hash/mode/size/mtime不变；准确旧cert再次认证和保留，不
重新选择旧状态。最后66 records、4 sealed pages及2 tail。legacy两阶段最小行为
和库/tests strict通过。该长样本源`28413f12d1eb...`，后续修复不原样重跑它。

另一个一次30秒两地区最小counter在3.114秒失败：已执行的foreign legacy证据
重复到达，错误强制使用本地paged形状。counter成立，regression未通过。改为
按本身signed地区规则分派形状后，新源一次30秒范围4.255秒通过exact重复及
后部坏签名拒绝，库存/head不变，strict通过。counter stage的fixture注释误沿用
65描述；实际命令/代码/log均为小两地区检查，原记录保留，在总结果明确更正。
它不是跨地区价值或long样本。最终只新增根目录容量计账回归：一次30秒范围
7.844秒通过小primitive的外部file/byte/overflow超限原子拒绝及可容小metadata；
CLI入口仅compile-check，主binary未重建，库/tests strict通过。它不资格真实
完整Store满载、publication fault或CLI运行。

[所有终态与准确来源](../operations/evidence/regional-native-paged-store-outcome-20261005.json)
绑定最终77-file源`d3abffbce056...`、implementation`c0979d1d4a0c...`；
长65与mixed检查各有自己的source，复用未变代码证据，不冒称最终源码完整重跑。
core171、旧main binary、两旧价值库文件及冻结body/PDF/receipt字节未变。旧
snapshot65拒绝及所有fault失败仍归旧scope；它们不因新profile有限通过而改称通过。

下一可证伪假设H-paged-Agent：在明确新签署signer contract下，普通Agent保留
超过128条完整request/response/observation，逐条重放历史native parent和prepare
锁，独立caller head不变，pending只能恢复已落盘准确响应而不能first-sign。
必须先实现普通Agent完整页writer、historical parent cursor/全认证、purpose/origin/
creation及exact recover-only；当前旧Agent只有128原record和active evidence，
尚不能资格该假设。可审实现完成后才启动原定**一次300秒**Store+Agent判别，
含编译/等待，至少实际>128、真实owner/value、fresh-process pinned cold、坏后部
record/陈旧caller及发布失败；首失败、完整有限判别或300秒退出。网络预算0，
原600sec stage/60sec rounds/max24/成熟/票数/2016均不改。该scope尚未启动。

新Store receipt/channel、历史冲突及完整容量的native资格、image restore、普通
transport、epoch、实际2016完整结算、新进程/真实中断/跨设备/独立latest和完整
fault仍OPEN；不将账本有限接入当全部原生paging或协议完成。


## 普通Agent分页写入及历史原生锁重放（2026-10-05）

新规则合同继续绑定明确 `RLD-NATIVE-PAGED-BFT-SIGNER-V1` header/stream。
普通Agent create/open/sign/status/recover-only查找已实际分派到该路径：只在native
创世边界为active原始成员创建，header不可变，原记录不转换。header中空records
不是完整签署状态，Journal.state明确拒绝据此授权；Agent.head/status取完整页流
head。所有原request、message、observation和previous head完整写入16-record页，
完整pending包装先持久落盘，正常响应仅在完整publication/fsync之后返回。

PagedReplay使用一个从pin genesis开始的普通Native历史cursor，按签署观察高度
推进、执行全部certified/evidence/receipt/incident事件。每个历史parent/epoch/
finality/state必须完全相符；每个request由同一旧State投票内核执行，保留全部
prepare锁、actual signature和exact response检查。不得借当前活动64快照推旧
parent，也不从页digest/serialized Ledger/state初始化。所有后来native历史和
整个signer流必须通过后才释放state。scope绑定当前implementation、signed
currency/admission、完整header/key/creation/purpose；native/caller头继续分开。

新请求必须绑定当前native parent、safety和私钥。准确无钥重试完全认证已有
原件，只接受当前caller head，或最后一个原response的exact previous head；
没有原request不能first-sign。完整档案计入header/LOCK及所有孤儿/残片，保持
4096-file/256MiB、8MiB对象；旧128-record格式继续拒绝，不从旧private state迁移。
普通CLI初始化/status/签署入口使用Agent.head与完整retained-request谓词，当前
只完成入口编译，没有重建或资格旧main binary/普通网络生命周期。

一次60秒初scope实际37.861秒整体未通过：真实native组件在23.452秒运行完成，
四真实Agents签署8proposal/32prepare/32commit、普通Store高度8、owner99/fee1
纳入并成熟；每Agent18完整原records，一页及两tail。保存separate caller头后
同进程Agent cold、无钥准确重试、stale caller/keyless-first-sign及回滚native视图
拒绝、全私有hash/mode/size/mtime不变均通过。入口compile通过，但strict因
`items_after_test_module`拒绝；整个scope仍失败，不叫全通过。

只把完全未变production replay定义移到测试模块之前，并新增三高度小反例。
首夹具1.499秒编译失败（测试误调用私有set_approval），生产未改；改为公开typed
Vote字段后一次30秒10.795秒通过。四实际Agents/三native高度，主动清空**仅
进程内活动snapshot集**后仍从完整原始Native档案认证旧votes；单独完整hash
自洽但最后signature坏的流拒绝，私有库存不变。此操作模拟活动证据不可用，
不是实际第65检查点或>128签署容量。受影响旧durable-QC/keyless-retry内核、
strict和入口compile通过；没有重复8/65长样本。

复核发现held-open Native后来出现pending incident marker时，历史cursor未
重新检查。全新height0/four empty signers最小counter在3.943秒失败并证实缺口，
无votes、无已认证事故或价值变更。修复在cursor构造与state释放时检查Native
healthy/zero guard，并重验全部保留事故证明/index/safety。一次30秒范围9.942秒
通过marker拒绝、受影响三高度完整历史/坏签名回归、strict和入口compile；全部
拒绝保留原件和heads。它不自动完成pending事故或恢复签署响应。

[准确源/终态与下一gate](../operations/evidence/regional-native-paged-agent-outcome-20261005.json)
绑定现78-file源`00feaf5ab202...`、implementation`26b13da2133c...`。
8样本只绑定其最初来源；其后production仅replay定义换位置、Native健康/事故
检查加入，所有改变受影响consumer单独核验；不冒称最终完整suite或重新8长测。
旧main binary、core171、legacy价值两文件、冻结正文/PDF/receipt均未变。

以下为78-file来源时的下一假设（历史；本次终态见末节）：

H-paged-response-recover：准确已签响应在pending/pages/manifest三个
保留位置中断后，只在native完全重放、immutable header/purpose及caller separately
retained exact request/previous head全部匹配时恢复，不first-sign或创建缺失目录，
不重置锁/领受新头。现Stream.open遇pending/commit残片严格拒绝，**没有中断
promotion/recovery API**。先形成完整恢复合同/源码，再一次60秒小组件判别：
三个实际保留位置、错request/head/坏signature/无custody均拒绝，含编译等待，
首失败/完整有限判别/60秒退出，保留原件；网络预算0。

原定一次300秒完整Store+Agent资格scope仍未开始，须恢复实现可审后才执行，
实际>128完整记录/超过活动界native历史/价值锁、新进程pinned cold及坏档/旧caller/
发布失败，预算包含编译和等待。原网络600sec/60sec/max24/2016/成熟/票数和
capacity不改变。完整窗口、fault、epoch/role paging、image/restore、长期history/
PQC、独立freshness/custody和physical继续OPEN；VALUE-STRICT-01独立OPEN。


## 原响应恢复、容量反例与首次集成终态（2026-10-05）

`retained_recovery.rs`只允许明确BftSigner用途的一次原始append恢复。完整pending
保存新页原文；从原页逐条重建prefix/head及确切旧manifest，当前manifest必须
逐字节等于旧或拟发布版本。完整native history/record/signature/prepare lock和
caller的确切request/previous head通过后才fsync原页、发布清单；不得first-sign、
创建缺失目录、重置投票或采纳观察头。仅移除已经完全发布的冗余包装，全部
孤儿/残片计账，响应释放前再核验native历史及incident guard。CLI recover-only
明确调用这一原生接口，不读取密钥；普通open仍拒绝pending。

一次60秒范围实际21.377秒通过三个真实native prepare-QC锁的发布注入边界；
返回原先相同响应，错误请求/头、缺失目录、keyless新请求及完整hash自洽坏
签名均拒绝、库存未变。它不是实际SIGKILL或owner付款/独立保管资格。
实际4096文件反例23.575秒失败：已发布manifest仍被多计一个不需创建的commit。
最小修复仅计实际/必要commit；新45秒范围27.279秒通过，孤儿/完整原文保留，
只删除完成的pending。该存储签名fixture不授予native BFT容量资格。

恢复实现可审后，原定一次300秒集成已运行并于300.033秒预算耗尽/-15终止。
这是首次真实普通Store+四Agent跨界尝试，未重跑旧manual65或8样本。最后
记录的完整阶段为height24、每人54records、active24，163.531秒；最终head/
height未知，不打开/恢复停止现场。>128、height65及fresh-process cold均未完成。
独立30秒范围仅编译新测试定义/CLI及lib-tests strict，4.326秒通过；不能替代
失败集成或VALUE-STRICT-01。[精确来源、五个终态和下一判别](../operations/evidence/regional-native-paged-response-recovery-20261005-outcome.json)。
现81-file源`56f88b7f8a92...`/implementation`642609498aa4...`，core171、旧main
binary及冻结正文/PDF/receipt未变。最终只比80-file容量修复来源多测试注册/新
集成测试定义，production逐字节相同；不宣称最终来源完整suite重新通过。

下一H-paged-sign-cost：单次sign内重复完整重放是否占测得签署墙钟至少50%。
先加test-only分阶段时钟：first native/record replay、request scan、current
execution/sign、second完整replay+new record、append/fsync及Store finalize。
一次60秒/1次、全新签署当前来源fixture、最多10个本地高度、四实际签名者/
owner付款/分别caller heads及pinned完整same-process cold；编译等待计入，
网络预算0。首认证失败、完整成本判别或60秒退出，保留来源现场，不原样重跑。
小于50%即推翻；若占主导，再设计一次调用内完全认证cursor复用，必须保留
签名前及释放前完整history/incident检查，另行全新fixture验证。不能用成本
判别充当跨128/65、新进程、完整2016窗口或完整fault通过。原600/60/max24/
成熟/票数/容量全部不改，legacy strict、独立/长期/physical义务继续OPEN。
