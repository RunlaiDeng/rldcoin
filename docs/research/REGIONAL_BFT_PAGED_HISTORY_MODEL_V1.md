# BFT 完整历史分页保留：可执行模型

状态：**有限模型行为已验证，Native实现缺口仍OPEN**。本合同对应
I7/I10、S11/S16/S17、R10/R11/R22，不改变冻结正文/PDF、采用规则、旧fixture或资格。
[模型](../../tools/bft_paged_history_model.py)与
[攻击检查](../../tools/test_bft_paged_history_model.py)均为数学设计工具。

## 前提与适用范围

`RLD-BFT-PAGED-HISTORY-MODEL-V1` 是独立模型域，**不是签署的新Native admission**。
理想认证器的完整原文集合模拟真实验签：producer明确认证的确切角色/签署者/
payload才能接受。其公开标签没有密码安全；摘要自洽不加入该集合。Native替换
必须使用真实准入、签名和共享执行核，不能调用此oracle或信任Python重放结果。

单一era、四等权voter、三distinct ordered prepare/commit；旧domain、未知era、
不足/重复/错角色票拒绝。模型起点是已经合法发行的100000金额切片，**不授权
新创世分配或发行**。价值部分只含一个通道的费用预算、关闭/挑战/结算，以及
理想兼容历史中一次export/import的U/E/T和永久ID；没有完整任意多源DAG、owner
签署保管、来源终局transport、成熟、incident/quarantine或epoch手交资格。

出版顺序是内存抽象；没有实际文件、OS锁、fsync、SIGKILL、断电、跨设备或独立
最新状态见证。caller latest head是单独给出的确切前提，模型不能证明该前提
独立存活。若归档和全部caller heads同时回滚，仍未资格。

## 存储与执行合同

- 每流从固定genesis/domain/stream开始；账本保存完整block+prepare/commit，
  每voter保存完整request、proposal、response、previous caller head、观察父
  检查点、prepare-QC/timeout。外部caller heads与五个存储流分别绑定。
- 完整16事件immutable pages绑定确切流、事件起始offset、前页digest和长度；
  manifest保存有序页引用及少于16条完整tail事件。成功封页后tail的所有证据仍
  在页中；替换的manifest只含索引和已被后继保存的证据，不丢弃任何独有签署字节。
  未引用对象、失败出版的完整prepared manifest和拒绝marker也计入容量，不能删除。
- 每对象及manifest≤8MiB、完整档案≤4096 files/256MiB。活动账本观察最多64、
  每voter活动记录最多128；重放一次只执行一个完整block。活动队列中的digest
  只为观察计数，不用于恢复或授权。永久ID/未导入transit各≤4096。
- 只从genesis新建空派生状态。账本和四voter流同步重放；每条签署请求重新审查
  当时真实已执行的父账本、完整提案及价值操作。不能从serialized ledger、摘要
  映射或缓存初始化。保留记录按顺序重建prepare-QC锁；认证换轮仍不能改锁定提案。
  提升签署高度需要已执行原高度的完整终局证书；旧高度/轮和旧caller head拒绝。
- 每完整证书先验角色/阈值/确切payload，再staged执行所有价值变化；非法尾部
  不改变当前Ledger或Signer。只有所有流的完整尾部和确切latest heads均验证
  后，才向调用者返回派生结果。读归档不改库存。
- Close c仅一次设定c+2016；预算事先覆盖fee_limit×2016×16，Challenge引用确切
  generation，累计fee只从E转U。截止块仍可挑战，结算严格晚于截止且只一次；
  重放历史imports不能再次credit。所有转换核对互斥U/E/T守恒。
- 容量拒绝在出版前发生且不改库存；注入出版中断保留新页/tail残片与原manifest。
  marker后读取/写入均拒绝，模型没有resume、recover-first-sign或删除残片入口。

此proposal只说明完整记录可以有界保留；不承诺200000块、真实签名/证明大小、
长期CPU或远程3MiB/64-checkpoint证据可用。Native老64snapshot/128-record限制
没有变化，旧profile不能自动采用本模型或把旧签署目录转换。

## 准确执行与保留失败

一次120秒scope实际10.700秒退出1。2018连续模型高度完成，c=1、deadline2017、
第二挑战恰在2017、2018结算；累计fee2，通道本金/剩余预算只归还一次，永久import
仍在。四voter完整记录3026/3026/3028/3028，合计12108；每流活动128，账本活动64。
887 files、24013495 bytes（原始编码后的模型文件字节，不含Python对象开销）。
损坏/缺档/乱序/前向引用、容量/孤儿、完整非法价值尾部、旧域/era/quorum/角色、
签署锁换轮及出版中断七个行为组通过。

首次另一个攻击检查失败：共享理想认证集合中，前面的检查已认证相同空block81
的完整签名；后面把完全相同字节称为“伪造”，因此合法接受。该fixture错误
不是证书验签漏洞，也不是“整套通过”。[原失败](../operations/evidence/regional-bft-paged-history-model-20261005-checks.json)
保持completed=false；[准确输入修正](patches/bft-paged-history-model-auth-fixture-20261005.diff)
可还原初始来源。

改变方法后一次30秒**只运行该攻击检查**，0.579秒退出0。以不同完整提案确保
commit原文不在认证集合，尽管页/头哈希自洽仍拒绝；明确认证该确切原文后接受。
旧归档/旧caller头仍拒绝。模型代码SHA-256始终
`53650b7d8b36b36581f8aa92cc66e282ee475ebdc79362827a03fcfce1354d58`；
其余七方法及setup/helpers逐字节未变，用方法来源哈希复用原通过结果，未重复
2018轨迹或完整新suite。[针对性结果及复用绑定](../operations/evidence/regional-bft-paged-history-auth-fixture-20261005-checks.json)。
Native69/core171、原binary和冻结正文/PDF/receipt核对不变；没有打开旧私有
fixture、启动网络、读写钱包、重签、退款或移动旧价值。

## 下一条原生判别与退出

H-native-paged-retention：只有明确新signed admission/storage/signer domain与全新
无价值genesis，Native普通Store和BFT Agent的完整证书/请求历史能否共同分页，
从固定genesis真实执行，保留全部caller/pending/锁/ID/incident并安全拒绝旧格式。
本模型不能替代两个原生路径及钱包签署高度/完整证据/epoch的实现；不能只升级
只读archive verifier、增大旧64/128或把历史未验页作为prefix authority。

先实现可审阅的新规则和两条完整原生存储路径，再运行一次最小组件scope，
**总墙钟300秒、1次，编译和等待计入，网络campaign预算0**。以真实旧64snapshot/
128-record反例边界的连续认证/持久签署及全新进程cold、缺档/损坏/旧caller头/
出版失败拒绝判别，不复用旧失败目录；实际2016窗口先单独设计成本预算，不能
增加网络原600/60/max24或用模型高度替代。首拒绝/完整判别/300秒即终止，
保留源码/命令/精确终态；失败后换最小方法，不原样重跑。

新Native源影响完整输入身份，所有后续fixture必须新签零分配currency/genesis。
当来源/范围触发旧价值库VALUE-STRICT-01或候选发布门槛，串行执行其既定独立
修复/检查，不能由本模型或地区strict替代。长历史、完整fault、独立保管/PQC/
physical及全部S/R/I/A–G/N/P资格继续OPEN。

后续源码已实现[共用原生保留层](REGIONAL_NATIVE_COMPLETE_STREAM_REQUIREMENTS.md)。
实际故障注入确认并修复“pending只有新页reference、缺完整未发布record”反例；
这是存储组件的进展，普通Store/Agent/钱包仍未接入，原300秒集成判别未启动。
不能将该层145条fixture签署record当实际BFT高度或以存储digest代替原生重放。
