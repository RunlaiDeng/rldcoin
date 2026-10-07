# 原生通道状态见证授权 V6 候选契约

新的 ground admission/kernel/profile V6 要求所有新 Open 资金条款明确单独 witness
角色；无钥条款、双方/authority/validator 角色复用必须拒绝。该用途只是双方选择的
状态共同授权与保管见证，不能单方支付/发币/终局。原共识票数、挑战窗口、金额、
发行、成熟、reserve 与容量保持。新源码、新签无价值 currency；V5 私有状态不转换。

完整公开 proof 绑定 exact profile、完整 state、两实际有序 parties、原 owner inception
承诺及可选完整 invoice statement，使用独立签名域。Native 总是先认证双方完整
state 及签署 funding，再认证其选定 witness 的完整证明。Receipt 还须逐字匹配 invoice；
Close/Challenge 等共享状态验证也必须认证 proof。Digest/inception/head 都只是签名
绑定的断言，单独不能授予权限，也不是接收方已独立验证私有 custody 的证据。

公共组合只构造未经见证授权的草稿，不可支付/接受/结算。分别留存且完整 native
认证的 owner journals 已见证保留完全相同的最高确认请求，才能由已认证 witness journal
签署 seal；derive 原始 Birth 而非从旧备份采用新 inception。Seal 绑定双方原部分
批准和完整输入体，公开签名/响应持久保存后才能释放。历史 cold replay 完整核验
每个 seal、原顺序 heads、实际 owner partials 与本地 native 签名/值/incident 边界。

两方与见证各有独立钥权限；首次 seal 显式读 witness native key file，不读 owner
key。准确 recover-seal 无钥，不能首次签署，不能发布不相符 pending；所有 caller
heads/完整 body/signatures/角色均在变更前检查。所有旧字节与失败残留保留。

见证256项/8 MiB包含seal，owner128/8 MiB保持；不能为测试提高上限或删历史。
同机 sample 仍不能证明独立 latest/common rollback/copied witness key、设备或真实
interrupt/power loss/长期容量/轮换；原有效旧状态在挑战模型中仍是历史授权，不能
声称单个证明代表最新。Watcher/2016窗口/独立安全与全部S/R/I/A-G/N/P目标仍需完成。

## 最高确认与最新保护的边界

见证按完整自身日志重建两方已确认的原生签署记录；不能将它们称为某个
独立设备此刻的绝对最新头。更高未确认 own 响应不匹配此记录，不能 seal。
原生 owner 继续签下一状态前须完整认证上一个状态的见证 proof，已 seal 的
旧 body 再次首次 seal 必须拒绝；其历史公开授权只能准确 recover，不变成
最新观察。所有者准备/签署/见证 advance/seal 逐条核对原始 Birth，Native
Receipt前后保持相同起点及上一完整授权声明。全钥/日志/头同回滚仍未解决。
