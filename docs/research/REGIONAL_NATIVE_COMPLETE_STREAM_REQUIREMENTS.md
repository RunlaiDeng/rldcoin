# Shared complete Native history and signer retention

This candidate keeps genesis-derived ledger replay and separately supplied exact caller heads. It cannot recover authority from a serialized ledger or a stored digest.

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

Ordinary Store and Agent history retain complete certified events, requests, exact responses, native observations and prepared-QC locks. Incomplete publication is refused or follows the explicit exact-response recover-only contract; it never permits first signing in a replacement directory. Immutable pages and every failure residue count toward the declared file/byte capacities. Independently authenticated latest heads and full native replay remain required at recovery.
