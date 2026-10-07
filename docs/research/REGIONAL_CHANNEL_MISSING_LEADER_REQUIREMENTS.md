# 通道最高状态：普通 Native/TLS 的有限缺席 leader 验收

状态：一次同机无价值候选的行为通过；完整故障、2016块窗口、跨地区价值、
独立保管、长历史、密码及物理资格继续未完成。S11/S17、I7/I8 的有限证据。
正文/PDF/官网不改；原费用覆盖反例、旧完整fault失败和旧owner请求保持。

## 假设和准确实现范围

高度6的原生有序四验证者列表确定round0 leader索引2。不启动其普通进程；
0、1、3使用事前明确身份/IPv4端点/证书pin，链边及额外1--3边保持连通。
实际Native入口普通启动、默认Python companion及原生证据/投票校验负责
超时、后续轮、最高接受q2挑战与三取四终局。live controller只启停与观察，
不构造或搬运Challenge、投票、quorum/certificate或完整信封。

准备中创建四个全新原生账本、四份独立signer/caller head及公共fixture钥，
实际普通历史覆盖Open、ReserveBudget、接受q1/q2及预授权旧q0 Close于6。
owner/W钥文件在live前删除，投票钥只供其原生原目录使用。两个样本分别
使用公共fixture authority seed13/14；货币/创世不同，不迁移余额或保管。
这不是主网或独立操作者，也不是复制钥或全状态回滚的资格。

Native69/core171及main binary与已验证V8来源准确字节不变。Node live仍是
`eb8cd6e18`启动等待修复后的来源；本次改动为fixture准备/停止检查集成。
未重复地区strict、旧价值strict、已通过正常TLS长范围或旧三地区campaign。

## 保留的失败及可证伪反例

首范围准备42.679/live216.695，总329.533秒；三健康账本在7或8已包含q2，
费用各扣3，四native/caller和三份round1完整信封分别认证。然而最后全私有
库存/元数据比较失败，**整范围仍未通过**。首controller调用普通`mesh.Node`
核验未启动carrier；其mesh状态仍保留初始化时空contact配置，而正式pin配置
已改变。普通构造器不是保证只读的检查器。

只读mtime定位看到未启动carrier的`mesh-state.json`及父目录在cold阶段变化；
这不能重建全部旧before字节，也不独自证明其唯一差异。新的0.008秒反例
准确证明：配置增加邻居时普通Node写入广告/游标；严格`MeshInspection`拒绝
不匹配配置且文件/目录库存、hash、mode、size、mtime不变。先明确准备准确
配置后，严格完整冷检查通过且上述比较不变。无网络进程/原生签署或旧fixture
启动。首诊断preflight因模块名错误拒绝，scope未开始、fixture未创建，记录保留。

## 修复与当前验收结果

[fixture入口](../../tools/regional_channel_missing_leader_drill.py)只允许固定一次范围；
已有报告/目录拒绝重复。准备时完整创建包括不启动carrier在内的正式pin状态，
然后独立保留setup public key/node ID/network/config commitment。停止核验使用
已有严格`MeshInspection`，不读private identity、不初始化或更新广告/游标；
配置不匹配拒绝，不从被检查状态领受锚。完整归档仍逐个认证；摘要不授权账本。

一次全新修正范围准备42.551/live160.834/clean shutdown10.578，总261.266秒：

- 三健康副本最终均7；同一q2挑战checkpoint的prepare/commit均三distinct ordered
  healthy keys，round1；对应完整Proposal含三份原生认证的round0 Timeout票。
- 最高sequence2，fee各扣3，剩余+spent=original；原Close6/deadline2022不变。
- 三进程exit0，无强杀。四份完整Native genesis重放/pinned history/caller核验，
  133个完整Runtime信封与339运输packet/219receipt认证；不启动Runtime/recovery。
- 未启动leader保持6/q0/spent0；其Native、voter、caller及transport库存/hash/
  mode/size/mtime从live前到检查后不变。全部私有目录同样比较不变；没有比较
  其他POSIX元数据，不称独立最新状态或跨设备/断电保管证明。

每个范围一次；准备180/live600/cold180秒，原round60秒/24高度/2016窗口/成熟/
票数及capacity不变，完整fault campaign预算0。新通过不改首失败的状态。
全部来源、预算及工件：结果绑定（历史证据保留于本地归档）。
旧价值库VALUE-STRICT-01仍OPEN，无新增告警豁免或候选发布包。

## 后续已执行判别：完整窗口的实际历史能力

本样本只到7，不能证明完整窗口结算。当前源码保留64 snapshots/256 blocks，
而Settle要求h>c+2016。下一假设：ordinary V8 BFT最先遇到的完整证据/历史
容量拒绝阻止正常到达窗口结算；需原生行为确定具体门槛，不能仅算数字当通过。

一次120秒（编译计入）的全新无价值native执行harness：真实连续认证checkpoint
到当前64快照容量及下一步拒绝，比较原生ledger/evidence/book前后不变，禁止
伪造高度或从cache初始化权威。此为独立容量组件判别，不延长本24高度普通网络
范围，不启动旧fixture/保管恢复/owner新请求；网络campaign预算0。首refusal、
完整判别或120秒即退出，保留来源/日志；若没到门槛，保留未知并换方法，不原样
重跑。已证容量阻塞须另签bounded BFT history/checkpoint设计及实现，不能提高
旧限额、剪除签署证据、缩短2016窗口或把有限q2纳入称为长期结算资格。

后续实际Native反例已确认64快照保留/65拒绝，49.515秒；真实Agent补充判别
120.028秒耗尽，尚未证明signer门槛/CPU归因。保留所有失败与原limits。
[窗口历史及签署义务](REGIONAL_BFT_WINDOW_HISTORY_REQUIREMENTS.md)记录准确范围和
改变方法的一次60秒成本样本；不是完整窗口/全协议资格。
