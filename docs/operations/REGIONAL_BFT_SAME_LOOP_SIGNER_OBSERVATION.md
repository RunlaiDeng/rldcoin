# Joint 普通循环中的单次原生签名头观测候选

Verification-only ground candidate. Independently supplied caller heads, complete native authentication and all declared limits remain required. No independent custody, sustained fault or physical qualification follows.

## 实现边界

`JointEpoch.advance` 仍执行原有当前 Native membership、初始化/恢复、outbox 和新 voter
完整原生签名头检查。普通循环只把刚完成的这一次检查，以不可变完整 canonical 字节，
交给同一 `Runtime._tick` 的局部操作对象。直接 `tick`、startup、incoming activation、
角色 handoff 及其他调用仍走原有接口；没有跨循环缓存、持久化或恢复该观测。

观测同时绑定 Runtime 对象、该次私有操作对象、完整 signing binding 和完整 caller head。
两份字节合计上限仍为 8 MiB。其他 Runtime/操作、caller pending/outbox/初始化或 binding
变化、限额收紧及超容量均回到原来的完整新查询；没有未核验数据的签名回退。
无 Native journal 的 keyless Python 状态不产生这种观测。

每次 `sign` 仍先执行原有新 Native signer/head 查询，并在 Native 原子签名路径中检查
exact expected head、当前会员、时代、锁、完整 owner/value/evidence。观测只用于本轮
调度和本地诊断，绝不授权签名、同步、证书、账本或 caller-head 采用。每个 incoming 完整
信封仍先通过原有 Native 认证；未更改 dedup 或 receipt/custody 规则。
