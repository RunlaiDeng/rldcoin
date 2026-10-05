# 普通BFT完整历史/签署日志的共用原生保留层

状态：**共用字节保留层已实现；普通Store/Agent/钱包接入仍OPEN**。
目标保持[完整历史合同](REGIONAL_BFT_WINDOW_HISTORY_REQUIREMENTS.md)及
[分页保留模型](REGIONAL_BFT_PAGED_HISTORY_MODEL_V1.md)。这是完整原生集成的一步，
不能将测试该层更多记录视为解决原第65检查点或128-record签署门槛。

## 已实现的原生代码与权限边界

`tools/regional-ledger/src/retained_pages.rs`实现
`RLD-NATIVE-COMPLETE-STREAM-PAGES-V1`。独立私有目录持有OS lock，scope绑定已
native验证的currency/region/admission、当前implementation、Ledger或BftSigner
用途及origin context。origin是调用者提供的存储上下文，**不是最新状态见证或
签署保管来源**；存储用途/公钥不授予成员资格。当前没有新signed admission，
普通Store/Agent/CLI不自动采用该格式，旧采用/签署目录没有转换。

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

## 必须继续的完整原生接入

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
普通Store仍未接入新certified-event stream，Agent写入仍是原格式；没有新admission。

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
