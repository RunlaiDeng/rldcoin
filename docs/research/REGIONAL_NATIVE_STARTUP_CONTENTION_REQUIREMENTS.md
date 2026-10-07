# 原生启动观察的有界锁竞争等待

Verification-only ground candidate. Independently supplied caller heads, complete native authentication and all declared limits remain required. No independent custody, sustained fault or physical qualification follows.

## 修复边界

`tools/regional_native_startup.py` 的 `Inspection` 只用于构造阶段，允许固定
观察集合 `contact-status`、`bft-context/status/retained-messages`、`proof`、
`bft-network-pack/check/check-batch` 和 `bft-installed-epochs`。每次仍调用
完整原生程序；只对本机已验证的完整精确错误
`native rejected: regional candidate rejected: lock acquisition failed because the operation would block`
等待。不同/附加错误、无效currency、签名、RESTORING、IO/timeout均原样拒绝。

每个Inspection共享最多3秒的失败锁尝试及延迟，最多128次锁拒绝，25ms步长。
完整成功原生重放保留原30秒每调用/输出限制；3秒不是整个startup、重放CPU
或socket尝试上限。默认startup配置及Service首观察各有一个Inspection，
Runtime构造的所有观察共享一个Inspection；不改变native历史/金额/成熟、
quorum、capacity或已配置block/round/deadline。

所有未列明命令直接单次转交，包括sign、recover-only、sync、init、finalize、
epoch/custody恢复。不能补签、清除native reservation、自动领受caller head、
返回伪观察或从Python缓存初始化权威。原有native/current proof和完整caller
约束仍执行。Runtime构造完成/异常退出后恢复原native对象；普通tick/receive
仍使用原有lock refusal及unknown观察策略，没有新增live等待或延长共识轮。
