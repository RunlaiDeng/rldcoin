# V5 通道签署见证地面契约

此候选推进 S11/I10/R10/R11 的签署保管缺口，不构成其全部通过。冻结白皮书、
旧失败、金额/发行/成熟/票数/原网络预算均保持。V4 实际同钥新目录反例仍失败；
V5 使用新来源、显式 admission 与全新签署无价值 genesis，不能迁移旧值或私有状态。

## 权限与安全假设

Open 的实际资金所有者及双方完整签名可指定一把独立用途的 witness 公钥。
它必须不同于双方、货币 authority 与本地区 validator keys。无此资金条款时，
通道价值 kernel 仍可验证历史模型行为，但公开 owner signing/creation/recovery 服务只读拒绝。
见证身份来自完整原生重放后的已认证 funding，不能来自发现、peer、自签身份、hash 或备份。

`RLD-NATIVE-CHANNEL-WITNESS-V1` 是分别加锁的私有地面日志。见证完整签名绑定
purpose/domain、profile/currency/region/key、前一个准确见证头及完整 Birth/Advance。
Birth 保存空记录的完整 owner inception/native observation；Advance 保存一条完整原始
owner response。按序从完整原生 funding 与每条签名重建 owner journals；不能从解码
缓存/最高序号/hash 初始化权限。相同 owner/channel/profile 的第二 inception 拒绝。

三个准确当前头（native、owner、witness）由调用者分别留存并显式提供。缺头、零头、
不符头、旧 owner backup 或未完成创建均拒绝新签。此样本中角色同机/同进程执行；
它只在见证日志与独立留存头幸存的假设下约束本原生 API。复制所有钥、见证日志与头
同时回滚、见证身份重新创建、实际独立运营/设备或原始泄露钥离线签署不在本证据内。
不能用 `independent_operations_qualified:false` 的样本宣称独立见证或 S11 完成。

## 持久化、失败与恢复

Owner 先保存自己的原签名/最高状态，见证再签署并持久保存准确扩展，两者完成后
才能释放响应。见证阶段拒绝或写入失败不返回 partial，也不撤回原签名、解预留、退款
或重置序号。正常 open 验证 `owner.next`/`witness.next`，不能自动促进它们。

`channel-owner-recover` 不读取任何角色钥，只可恢复完整认证的准确已有响应。
所有者 caller head、请求/review、完整响应、见证 caller head、准确目标 owner extension
以及待处理见证的最后所属响应均在任何发布前检查。错误头/其他所有者/坏签名拒绝后
两日志和待处理文件必须保持。之后 fsync/rename 的 I/O 失败仍留存相应原件；这不是
两个目录跨设备原子性或电源故障证明。

`channel-owner-finish-witness` 显式读取见证钥，首次确认已持久保存的最后一条 owner
原响应；不读取 owner 钥，不签另一 owner state。它与无钥 recover-only 是不同权限。
如果原 owner 签名尚不存在，它必须拒绝。未完成 Birth/创建保持只读，不自动重建。

Owner 每日志仍为 128 记录/8 MiB；见证为 256 有序项、完整组合文件 8 MiB。
完整编码、原生历史/evidence/档案容量均保持；不能丢弃未确认记录或提高限额。
限额上的真实长期服务连续性与见证轮换仍需单独实现/验收。

## 已验证范围与下一判别

准确结果（历史证据保留于本地归档）
区分首轮严格拒绝、原生正常样本、恢复顺序反例、修复及各来源的检查。合成
`witness.next` 是发布边界样本，不能称实际 SIGKILL、掉电、跨设备或完整 fault pass。

V5 Receipt/Close/Challenge 的完整 party proof 尚不携带见证认证；返回的 witness_head
只说明本地签署服务观察，不能被接收方当原生资金权限。实际 V5 CLI 收据接受样本
已显示这种范围：双方收据通过且 monetary ledger 未变，但没有见证 proof 字段。
下一主线先规定并实施完整签署见证证明、原生 receiver/state-action 的认证关系及
latest-state 信任边界；遗漏/错角色/旧 inception 的完整 party-only 证明必须被新 profile
拒绝，原认证双方+见证可继续。不能只把 digest/head 放进 receipt 或放宽旧 profile。

下一次范围须在当前检查终态后选择；先模型/最小原生反例，单次 120 秒/1 次，
来源变化必须新 signed no-value fixture，网络 campaign 预算 0。到反例、拒绝、完成或
预算即停止保留原件；再按实际行为决定实现验证。独立/全回滚、wallet-app、加密完整
channel backup、watcher/inclusion、重组/完整窗口/长期历史、完整网络及物理资格仍开放。
