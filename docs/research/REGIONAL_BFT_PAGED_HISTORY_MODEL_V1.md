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
