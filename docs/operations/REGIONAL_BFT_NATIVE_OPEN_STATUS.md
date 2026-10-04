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

新增真实 Native 回归已通过：持久 prepare-QC 锁、输出与原完整核验字节一致、持锁时第二打开拒绝；
真实头前进后旧头不能授权下一次签署；已认证中断扩展输出绑定最终 head/state；改变签名和
损坏中断字节拒绝且不改写原件。完整 184 原生、strict、完整 480 过程、3 Runtime 保管及
新 driver 已实际执行通过。全新普通/cold/fault 是单独的交付关卡，目前正在普通三地区实验。

本改动未提高任何历史、记录、容量、成熟、round、票数或时间限制，不具备长历史、独立保管、
掉电/跨设备或物理星际资格。所有旧失败、源码、报告和私有状态保留；I1–I12仍未完成。

后续实际检查：[386冻结报告](evidence/regional-bft-open-status-frozen-checks-20261004.json)
精确重建39.102秒、strict13.962秒、184原生69.482秒、完整480过程293.031秒、
3真实Runtime保管3.925秒通过；原生/strict不复用。新driver
[四Native单向离线付款/cold](evidence/regional-bft-open-status-oneway-default-native-lifecycle-20261004.json)
4.129秒/48完整签名交换通过，显式unanimous控制者样本，不是自主BFT全故障资格。
[两个独立新genesis的组件测量](evidence/regional-bft-open-status-fresh-component-comparison-20261004.json)
各31真实Native timeout记录、6轮交错查询，全私有字节/权限保持，旧/新status均值
0.023160/0.015039秒。高度0、没有块/owner支付或普通liveness，不把这个组件样本外推
到旧故障、普通吞吐或长期历史。新的三地区ordinary/cold正在全新私有范围运行。
