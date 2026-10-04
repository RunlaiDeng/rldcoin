# 原生 BFT 同次持锁打开的完整状态观测候选

2026-10-04。该原生源码改变实现身份，必须使用全新签署的无价值创世/货币及私有目录；
不得把修订53/54的余额或签署保管迁移到这个候选。

既有 `bft-status` 先调用 `Agent::open`，其中完整核验 journal 及可能存在的 `bft.next`；
CLI随后再调用 `journal.state`，重复完整签名、签名高度历史、原生父级、状态机及锁验证。
停止分项测量中地球新 voter 查询均值0.425672秒，但该测量不能证明唯一故障原因或吞吐。

新 `open_state` 是原打开路径的私有实现，返回实际持锁Agent及刚完成完整核验的State。
`open`仍走同一路径并丢弃结果；正常签署、expected-head、recover-only及持久化不变。
只有 `open_with_status` 在同次打开内绑定该完整结果、精确最终head/binding/creation/records，
CLI保留Agent锁直到输出结束。没有Agent内缓存、跨打开/进程复用、序列化账本或解码状态基底。
Status只能序列化，字段私有；它不能授予签名、freshness、membership、账本或恢复权。

原 `bft.next` 路径仍先完整核验原journal与完整候选，再确认exact extension，fsync、rename及
目录fsync。只有全部成功后返回最终候选状态；任何错误都不输出状态，也不凭旧状态跳过验证。
这保持既有中断发布行为，并不新增恢复权限。所有Native OS锁、caller头、签署预留、证据、
origin/readiness/时代/incident/owner/value及容量门槛保持。完整JSON字段和原输出顺序保持。

新增实际Native回归待执行：持久prepare-QC锁、输出与原完整核验字节一致、持锁时第二打开拒绝；
真实头前进后旧头不能授权下一次签署；已认证中断扩展输出绑定最终head/state；改变签名和
损坏中断字节拒绝且不改写原件。完整184原生、strict、480过程、新driver与全新普通/cold/fault
必须分别执行；目前只完成源码修改和格式检查，没有构建/测试或速度提升资格结论。

本改动未提高任何历史、记录、容量、成熟、round、票数或时间限制，不具备长历史、独立保管、
掉电/跨设备或物理星际资格。所有旧失败、源码、报告和私有状态保留；I1–I12仍未完成。
