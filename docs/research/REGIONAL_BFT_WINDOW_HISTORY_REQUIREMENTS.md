# 普通 BFT 通道窗口的完整历史与签署保留

状态：**新明确分页profile真实Store65/四signer>128/新进程cold有限集成已通过；完整窗口及远程价值资格仍OPEN**。
旧普通V8 Native实际在第65检查点拒绝；原生签署日志
的实际容量门槛及重放CPU归因尚未验证。I7/I10、S11/S16/S17、R10/R11/R22
仍未完成。本记录约束后续新profile设计，不能修改冻结正文/PDF或旧signed规则。

## 当前原生反例

Native来源`c2b5e8bc...`、implementation`ec6f4960...`、binary`838873ba...`
及core171保持准确字节。全新公共authority seed61、零初始分配、明确签署
V8 admission，使用实际Store candidate/full replay/finalize逐块执行。完整
prepare/commit各三distinct ordered公共fixture签名，不创建BFT Agent或owner
保管。1..64连续认证检查点真实保留，65以`snapshot bound`拒绝。拒绝未改变
原生journal/chain/ledger/book或磁盘库存/hash/mode/size/mtime；保留当前head
后新的Store open完整重放成功且不变。此cold在同一进程，不称独立或断电保管。

包含编译共49.515秒，预算一次120秒。64 snapshots/256 blocks/8MiB逻辑界限
未改，2016窗口未改。这证明普通历史无法跨越必要窗口；不是完整结算、owner
付款或真实签署锁的资格。模型中给上下文2021/2022不能替代实际连续历史。

另一个真实Agent判别创建四独立native signer和四分别fsync caller heads，
Native Propose/Prepare/Commit逐步认证普通Store。首次夹具编译0.540秒失败
（私有函数和遗漏EpochFence分支），未创建原生fixture。修正代码使用新authority
seed63和新目录；120.028秒/-15预算终态未通过。最后完整stdout进度height20、
records45/45/45/5，83.007秒；不推断最终高度或调用者pending/head。不做startup/
recover-only/重签/退款或领受更高头，保留所有原件。

签署耗时包含Agent validation、Store replay、fixture库存hash及caller fsync；
当前只看到组合耗时增长，**未知哪项为主要原因**。源码MAX_RECORDS128是确实
约束，但静态预测不能冒充首个实际拒绝，更不能扩大记录数或丢弃旧票。
[完整来源与结果](../operations/evidence/regional-native-bft-window-capacity-outcome-20261005.json)
绑定三次终态。可审阅的[准确Rust夹具](../../tools/fixtures/regional-bft-capacity/README.md)
逐字节保留通过/未通过的原代码；相对manifest只验metadata，未重复运行旧scope。

## 后续方案必须同时处理的义务

1. **明确新采用规则。** 新signed admission、存储/签署domain及实现身份。旧BFT、
   unanimous/segmented、epoch/value profile不得自动采用，不能降低3-of-4或从旧
   private journal转换；改变native后用新签无价值currency/genesis，旧失败原件保留。
2. **完整认证历史。** 每个区块、完整prepare/commit、关闭/父检查点及epoch声明
   必须保留、按顺序从已pin signed genesis原生执行。16事件immutable pages可用于
   integrity定位；digest、manifest、序列化Ledger或cached head从不初始化权威。
   活动256块/64认证观察及每对象/metadata/evidence/payload8MiB保持有界；所有
   旧签署证据仍在4096-file/256MiB完整档案内，满载明确拒绝，不删旧证明。
3. **原生持久签署锁。** 账本分页本身不解决原128-record signer。新机制必须完整
   保留原请求、response、native observation、previous head、prepare-QC锁及所有
   已认证epoch events，按顺序重放生成当前投票状态。old/candidate/new-voter与
   separate caller头/pending继续分离；不能从摘要重置journal或在新目录首次补签。
4. **完整价值规则。** 发行/永久imports/export IDs、全部channel provenance/incident、
   owner signing-height及evidence依赖仍从shared native执行核派生。Close c及c+2016
   不重置，E责任及fee累计不变；晚到证据可认证不能自动创造权限。历史64活动界限
   不能藏旧冲突，也不能把未执行的归档节点当import/支出的授权。
5. **本地和远程分别资格。** Native ordinary startup/commit/cold/Wallet/BFT signer应
   共同使用明确新历史规则；网络payload3MiB及64 checkpoint范围仍独立。证据分片
   /完整依赖重建必须单独native认证，不能依靠peer cache补权威或把单地区只读
   stream verifier当普通账本升级。epoch/reconfiguration/independent/physical另验。
6. **失败原子性与成本。** Missing/reordered/corrupted/forward-reference/unsafe files、
   磁盘满/中断发布须保留残留且拒绝、不推进chain/锁/头；pending signed响应只可
   exact recover-only。量化完整重放、签署、fsync、wire及档案成本；不能以优化缓存
   绕过当前incident、owner、trust或最新caller-head条件。200000时代仍独立未验。

这些是完整目标的必要设计条件，并非新profile已经实现或获审。只降低不必要
重复计算也不能解除保留容量；只改证据64也不能解除signer128或证明窗口活性。

## 后续已执行的改变方法判别

H-sign-cost：在全新明确V8及原生签署/独立caller目录中，具体是哪类操作占据
height增长成本。一次60秒（编译/等待均计入）、最多12连续认证高度，分开记录
实际Agent.sign、Store.finalize与fixture库存/head/fsync的单次耗时及调用角色。
分阶段计时只量成本，不验证签名、进度、余额、最新状态或真实资产权限。

首不合法动作、完整限定样本或60秒即退出；记录缺失/预算耗尽未知，不延长旧
120秒、不继续旧失败目录、不原样再跑。若成本归因成立，针对完整原生历史/请求
认证形成可执行新paging/replay模型，再开发上述全部范围；否则换最小方法，不能
凭旧组合耗时优化production。无ordinary网络campaign，原max24/round60保持。
完整2016实际挑战/结算、故障恢复、历史容量、独立防回滚/PQC/物理资格继续OPEN。
旧价值库VALUE-STRICT-01仍未通过；本次不新增lint allow或生成候选发布包。

该新计时样本已在24.715秒完成，Native高度12，完整cold/四voter及独立caller heads
通过，全部私有库存/hash/mode/size/mtime未变。84次真实Agent.sign累计17.915988秒；
前置库存/state/head计算1.911762秒、caller fsync0.800069秒、Store.finalize1.134307秒、
context/candidate0.226924秒。sign占这些独立计时总额81.4769%，不是全程CPU比例；
验签/历史重放/Native response persistence内部未分开，不推为单一函数根因。
最后h12 Prepare/Commit各0.4896..0.5402秒。完整绑定见
[成本判别](../operations/evidence/regional-native-bft-cost-attribution-20261005.json)。
旧120秒budget仍未通过，signer实际first-capacity门槛/旧最终heads仍未知。

下一实现门槛H-paged-history：形成可执行的新profile模型，完整顺序block/certificate
与持久signer请求链均保留在immutable bounded pages，通过从pinned genesis执行
派生当前状态，同时保持64/128活动窗口而不以磁盘摘要/serialized ledger初始化
权威。模型需保留全部锁、absolute c+2016及永久ID，并给出2017高度、遗失/乱序/
损坏/旧caller头/出版中断拒绝的反例；每对象8MiB/4096 files/256MiB档案和旧profile
规则不改。一个设计模型及其有限判别预算120秒、一次；模型不是Native/crypto/
完整2016普通运行资格。明确counter及安全模型后，才在新signed genesis/profile
下实施ordinary Store、BFT signer、钱包/证据所需完整规则，不仅另做只读verifier。

该模型门槛已产生[可执行模型和准确局限](REGIONAL_BFT_PAGED_HISTORY_MODEL_V1.md)。
完整2018模型高度/12108签署记录保留，887文件/24013495字节，活动64/128；
七个有限行为组通过，首次整体scope因攻击fixture误把已认证相同字节当伪造而
10.700秒退出1，原失败保留。改用不同未认证完整提案的单项30秒scope在0.579秒
通过；模型源和其余方法未变，来源绑定复用，未重复轨迹或宣称完整suite重跑。
这是理想认证/单era/价值子集与抽象出版模型，不是Native或独立custody资格。
下一门槛为新明确原生规则下普通Store与BFT signer共同分页，一次300秒组件
判别（实现完成后执行、含编译、无network），旧64/128及全部旧失败不改变。


2026-10-05 后续实现：新明确signed paged profile的普通Store/钱包历史接入，
65实际native认证高度、99/fee1付款成熟、完整坏尾拒绝及同进程固定head cold
在88.056秒完成。公共fixture quorum签名不是实际Agent投票保管；旧V8第65
拒绝仍是旧规则失败，signer128及完整2016仍OPEN。mixed foreign-envelope
反例3.114秒成立、修复4.255秒通过；root侧档案容量计账小组件及CLI仅编译
7.844秒通过。各scope绑定各自源，不重复65长测或改称full fault；细节、
旧失败和下一原定一次300秒Agent gate见
[普通完整流接入](REGIONAL_NATIVE_COMPLETE_STREAM_REQUIREMENTS.md)及
[准确总结果](../operations/evidence/regional-native-paged-store-outcome-20261005.json)。


后续普通Agent正常分页写入及逐条historical native lock内核已接入；四实际
Agents/8高度/72签署/owner99成熟的有限样本完成，但整个37.861秒scope因strict
模块位置告警失败，保留未通过。生产项移序/夹具私有接口修正后10.795秒小范围
通过缺活动parents时完整原始native重放及hash自洽坏signature拒绝，旧锁路径/
strict/入口compile通过。held-native新pending事故标记3.943秒counter成立；健康/
guard/full事故重验修复后9.942秒affected范围通过。没有8/65长测重复、实际>128/
真实eviction签署/新进程或完整窗口资格，准确源及下一恢复gate见
[Agent结果](../operations/evidence/regional-native-paged-agent-outcome-20261005.json)。
原定300秒仍等待完整中断recover-only实现，不把正常页写入当保管恢复完成。


2026-10-05 后续新profile的真实签署容量门槛已在单次103.160秒范围跨越：
Native65、四journal147/146/146/146及1原timeout恢复、活动64、付款成熟，
>128坏signature/缺档/旧caller拒绝和新进程完整cold通过。只适用于85文件源
`f34e58af93aa...`，不是旧V8/legacy容量放宽或整体窗口证明。原300.033秒
耗尽及新夹具路径118.279秒失败保留；精确成本/修复/全部来源见
[结果](../operations/evidence/regional-native-paged-cursor-capacity-20261005-outcome.json)。
完整2016窗口/settlement与receipt锚、跨地区65之后完整价值证据、ordinary
Runtime/TLS/fault、epoch/长期/独立保管继续未完成。下一180秒native remote
crossing判别按共用层文档执行，不能由本地分页容量通过替代。
