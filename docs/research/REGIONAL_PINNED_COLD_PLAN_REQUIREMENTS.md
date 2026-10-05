# 原生固定头只读冷核验计划 V1

本契约用于停止后的完整 BFT 信封认证。实现是地区候选的独立命令
`bft-network-check-plan --file <absolute-plan> --expected-head <external-head>`。
它不安装证据、恢复事件、生成签署、改变账本或选择进口；普通 Runtime 尚未采用。
更换原生来源必须使用全新签署零分配 genesis/currency 和独立全新保管目录。
冻结白皮书及经济/共识参数保持。

1. 调用者提供域外单独保留的准确最新 native storage head，非零。命令在原生
   OS 独占锁内核对它，从签署创世执行完整当前历史；不从元数据、Python ledger、
   缓存、hash 或调用者 JSON 初始化账本。原 head 自观察不证明独立最新保护。
2. `RLD-BFT-COLD-NETWORK-PLAN-V1` 严格 typed manifest 仅含 format/currency/region/
   batches，每行 sha256/bytes/envelopes。未知及重复 typed 字段拒绝。路径引用只由
   原生 Hash 的小写十六进制生成 `<sha256>.json`，不能由广告或输入传入任意路径。
3. 计划与批文件在一个单独绝对输入目录。拒绝符号链接祖先、链接文件、目录、
   缺失或非普通条目；Unix 文件打开使用 O_NOFOLLOW。每个文件仍最多8MiB；所有
   包括未引用残留的输入文件最多4096/256MiB。输入路径并不提供保管/抗并发权限。
4. 保留有序重复引用。每批1至4份完整信封/8MiB，每完整wire3MiB，整个计划最多
   512份完整信封；重复引用同样计入总份数和处理字节，处理字节至多256MiB。
   并未提高 Native 历史、64快照、伴随器32MiB/512、接收槽或网络负载上限。
5. 核对准确完整批字节的长度、摘要和声明份数后，每一份调用原有原生展开和
   验签/前缀/创世/epoch/finality/所有者/价值/incident检查。相同body、statement或
   文件摘要不允许跳过后续完整认证。原生已有过程内前驱复用只按其原安全约束使用。
6. 原生 pending incident 或完整已认证但未索引 incident 拒绝，不reconcile，
   不清除标记/证明。返回前重新核对 native head、事件目录/guard 和分页的完整
   manifest/原页面结构；Native锁覆盖整个操作。遗留 inline、未完成分页 publication
   或恢复目录仍按原规则拒绝。外部绕锁破坏和跨设备最新保护没有由此获得资格。
7. 每份认证只保留有界 message_id/value。整个输入目录的最终摘要清单必须与初始
   相同。任意后置坏签名/缺依赖/域或头错误/输入变更/事件/容量失败返回错误，命令
   不输出任何部分通过。最终响应还绑定整个原始manifest摘要、准确head、currency/
   region、每批摘要与有序结果，verified=true、ledger_changed=false、signing_authority=false；
   完整响应最多8MiB。成功摘要是本次认证结果，不是签署/当前可花/新鲜性授权。
8. 本组件来源检查预算一次300秒；CLI预算一次120秒，全新无价值E7/P4/A4因果样本
   对照8个原四份批调用和一个8批计划，实际512份计划与后置坏完整证书/缺因果依赖、
   旧/零head、第五份、513总数、变更摘要、事件拒绝并保留私有字节。首失败/完整判别/
   原预算退出，失败原件不重开或原样复跑。不启动普通完整周期/故障测试。

源码通过、小历史同字节重复样本和512份count上限不等于512份不同复杂证明负载、
旧E11/P7/A9范围、普通完整价值生命周期、持续故障、来源66容量、200000块era、
独立保管/最新头或物理/跨星际资格。必须在新的实际来源和对应范围下另行验收。
