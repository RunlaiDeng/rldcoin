# 单次 transit 操作内的完整 frame 认证

旧完整 `_transit_check` 先通过 `packet_check` 完整检查 frame，再对同一份不可变 raw bytes 调用第二次 `inspect_frame`。新私有 `_packet_frame_check` 在原包签名、schema、base64、frame 全部签名域/digest/载荷和货币网络绑定通过后返回该操作的完整结果。公共 `packet_check` 保持原二项返回；transit 在同一调用内使用刚检查的 header 来核对独立已签署 receipt-route，再检查所有有序 hop、签名、父 ID、目的和 contact 角色。

不增加缓存、不保留 header/payload、不更改 wire/private wrapper 或 Native。512 个进程见证仍只保留不可变 visited-node tuples，完整 canonical transit、网络/contact/domain/limits 仍决定命中；更改 bytes、限额、驱逐和冷进程照常全验。归档文件/展开/保管 fsync、TLS、新挑战、Native owner/value/finality 和 caller head 保持各自检查。

新来源必须独立绑定其构建与必要验证。完整周期、独立保管与故障资格不能由同次认证复用推得。
