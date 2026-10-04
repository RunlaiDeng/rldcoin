# 单次 transit 操作内的完整 frame 认证

旧完整 `_transit_check` 先通过 `packet_check` 完整检查 frame，再对同一份不可变 raw bytes 调用第二次 `inspect_frame`。新私有 `_packet_frame_check` 在原包签名、schema、base64、frame 全部签名域/digest/载荷和货币网络绑定通过后返回该操作的完整结果。公共 `packet_check` 保持原二项返回；transit 在同一调用内使用刚检查的 header 来核对独立已签署 receipt-route，再检查所有有序 hop、签名、父 ID、目的和 contact 角色。

不增加缓存、不保留 header/payload、不更改 wire/private wrapper 或 Native。512 个进程见证仍只保留不可变 visited-node tuples，完整 canonical transit、网络/contact/domain/limits 仍决定命中；更改 bytes、限额、驱逐和冷进程照常全验。归档文件/展开/保管 fsync、TLS、新挑战、Native owner/value/finality 和 caller head 保持各自检查。

46 项现有 mesh/批次检查通过（3.587 秒），四项新攻击检查通过（0.024 秒）：即使包及 route 正确签署，坏 payload、完整其他 currency frame、坏 route、非法 hop/contact 和收紧 frame 上限仍拒绝；不将拒绝对象发布为见证。返回结果和原接口一致。

五组交替的约 1 MiB 完整运输包组件观测，上一冻结每次完整 frame 认证两次，新候选一次，完整 packet/route/hops 结果相同；观测 0.0434–0.0437 / 0.0313–0.0316 秒。该检查与同机普通付款部分重叠，不能作为隔离性能或普通吞吐证明，更不能证明上一失败唯一原因。这些通用地面 payload 不提供 Native 价值权威。

正在运行的 327 文件有界入队冻结未改变。新 helper 尚无独立冻结普通生命周期、完整回归和全历史冷核验；旧失败余额、预留、保管及队列不迁移/重启。资格必须来自新的准确源码和全新无价值现场，不借用前冻结的完整周期或故障结果。
