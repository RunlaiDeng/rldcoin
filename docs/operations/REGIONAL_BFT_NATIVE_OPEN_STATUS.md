# 原生 BFT 同次持锁打开的完整状态观测候选

该原生源码改变实现身份，必须使用全新签署的无价值创世/货币及私有目录；
不得迁移旧余额或签署保管。

新 `open_state` 是原打开路径的私有实现，返回实际持锁Agent及刚完成完整核验的State。
`open`仍走同一路径并丢弃结果；正常签署、expected-head、recover-only及持久化不变。
只有 `open_with_status` 在同次打开内绑定该完整结果、精确最终head/binding/creation/records，
CLI保留Agent锁直到输出结束。没有Agent内缓存、跨打开/进程复用、序列化账本或解码状态基底。
Status只能序列化，字段私有；它不能授予签名、freshness、membership、账本或恢复权。

原 `bft.next` 路径仍先完整核验原journal与完整候选，再确认exact extension，fsync、rename及
目录fsync。只有全部成功后返回最终候选状态；任何错误都不输出状态，也不凭旧状态跳过验证。
这保持既有中断发布行为，并不新增恢复权限。所有Native OS锁、caller头、签署预留、证据、
origin/readiness/时代/incident/owner/value及容量门槛保持。完整JSON字段和原输出顺序保持。

本改动未提高任何历史、记录、容量、成熟、round、票数或时间限制，不具备长历史、独立保管、
掉电/跨设备或物理星际资格。所有旧失败、源码、报告和私有状态保留；I1–I12仍未完成。
