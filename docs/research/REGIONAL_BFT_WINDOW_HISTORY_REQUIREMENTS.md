# Ordinary BFT history and signer retention requirements

The historical active checkpoint and signer-record bounds do not establish a complete challenge window. Pagination must retain authenticated originals and all locks without borrowing authority from a cached state.

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
