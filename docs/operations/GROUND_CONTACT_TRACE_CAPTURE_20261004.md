# 有界实时接触链：组件观察与资格边界

2026-10-04。唯一活动假设仍为 H-service：尚无目标回执的当前父块控制包，
在普通准备/接触阶段受历史重复承载或服务拒绝延迟。停止快照不能复原实时调度。
本次交付关闭最小样本的实时采集缺口；尚未判定原失败的原因，也没有新完整故障通过。

## 实现与保管语义

`RLD_GROUND_CONTACT_TRACE=1` 显式开启进程内私有元数据环，默认关闭。
最多 128 行、每行 1,024 字节、快照 192 KiB；仅保存包/帧/完整信封摘要、
固定邻居、尝试序号、请求 nonce、单调时刻和有界拒绝类别。
不保存负载、密钥或 Native 账本；不输出到伴随进程 stdout。
普通入队、准备交换、请求发送、对端认证保管、实际本地保管、目标回执和
Native 完整信封接收分别记录。Native 接收事件只在正常完整认证、依赖同步和
保留成功之后产生。目标运输回执不代表 Native 接收或可花费。

所有 Native 验证、TLS pin、挑战/精确交换绑定、fsync、签署头、四项接收槽、
票数、成熟高度、期限和容量保持原要求。追踪需要额外散列和状态字节，可能改变时序；
它是明确开启的观察候选，不能替代关闭追踪的既有资格，也不提供账本授权。

独立采集器固定拥有的进程身份及预先给定 network/node 绑定，读取私有状态环；
原生状态等其他字段即刻丢弃。事件丢失、拒绝、身份变化和格式不符明确记录。
PID/进程命令关联是观察边界，不是独立最新状态保护。写入失败保留部分日志并向观察者
抛出，不能重启节点、恢复签署、采纳调用者头或使协议跳过同步。

## 最小实际进程验证

初始冻结 396 文件：
`3c270788a5d0c19fcad439a9fe7d28b6948c7b457c739d7d263b8a46e680c712`。
首次 30 秒观察收到 130 个未知样本；最终私有环已有 621 项、493 项被淘汰。
缺失的实时 OS 身份没有保留，因此不能把原失败确定归因于启动竞态，也不能证明未送达。

加入明确拒绝分类后的冻结仍为 396 文件：
`2309a18199c5e7714017b56780001cbdf2527c57b574cc759d09d83ebc9f4c57`。
三个后续组件都在观察循环之前被注册检查拒绝，原现场没有恢复。
达到小型重试预算后改用不含账本的短进程反例，实际定位到两个观察者错误：
macOS Python 框架启动器与最终解释器是不同文件；C 与 UTF-8 语言环境把中文
命令路径呈现为不同字节。注册现在核对完整实际参数及已知拥有的解释器映像，
再以同一语言环境连续确认稳定身份，分别处理两种观察，不比较异域摘要。

该修正的独立实际进程样本在 0.793 秒完成，四个样本中一个为启动状态文件尚未创建；
其余接受的区间没有丢失或拒绝事件。来源入队、真实固定 TLS 请求 nonce、
目标持久回执及 Native 接收关联同一个包和完整信封。私有日志为 0600，
节点 stdout 无追踪内容，实际拥有的进程全部停止。合法信封保留成功；针对性
Native 反例中，无效信封虽然可获得运输回执，仍不产生 Native 接收事件。

这是控制器签署 fixture Timeout 的直接组件，显式 Python 启动，使用旧已核验 Native
二进制；不是普通共识完整范围或默认启动程序资格。四份拒绝/失败原件和初始源码保留。
精确默认启动程序已重建（41.51 秒），527 项完整过程回归及三个真实 Runtime
保管阶段通过。184 Native/strict 引用逐字节相同 Native/core 的既有证据，
本轮未重跑。重建二进制摘要为
`a4f5e23204f1a8d7d76545d95f88bd556a4ba7e8f5905b77c52529b02d4cb979`。
这些是受影响回归资格，不是新的完整付款或故障通过。

## 下一判别及退出条件

重建和必要检查已通过，全新普通三地区付款循环现已启动。先完成同一来源的全新普通三地区循环及停止核验，
再最多一次新的完整有限故障判别；不能套用旧循环给改变的普通运行时授权。
采集精确普通包链，不修改 600 秒阶段、60 秒轮或成熟/容量门槛。

- 若完整链定位选择/服务拒绝，修复该已测路径。
- 若目标已保管而 Native 未接收，切换到接收路径判别。
- 若观察缺口阻止归因，报告未知并缩小反例，不重复完整范围或推断通过。

物理接触、独立运行/保管、长期历史、持续 Byzantine 负载和未来新主网均未资格。
本地提交不等于发布。证据仅公开审阅后的摘要，私有现场/原始日志不发布。

证据：`evidence/regional-contact-trace-live-process-initial-failed-20261004.json`、
`evidence/regional-contact-trace-live-process-retry1-registration-failed-20261004.json`、
`evidence/regional-contact-trace-live-process-registration-locale-failed-20261004.json`、
`evidence/regional-contact-trace-live-process-stable-registration-image-failed-20261004.json`、
`evidence/regional-contact-trace-live-process-image-registered-component-20261004.json`。

重建/回归证据：`evidence/regional-contact-trace-frozen-source-20261004.json`、
`evidence/regional-contact-trace-frozen-checks-20261004.json`、
`evidence/regional-contact-trace-runtime-custody-20261004.json`。

## 普通循环终态及单次故障判别启动

同一冻结来源的普通三地区付款返程 757.729 秒通过，停止冷核验 63.199 秒通过；
E11/P4/A4、issued/liquid/pending 300/300/0，12 Native、12 收款、4 时代保管、
1,792 档案，私有字节/权限不变。Node 共启动 56 个实例，原地面条件/门槛未放宽。

原观察器的精确路径字符串检查未接受默认驱动中的 `../` 拼写，零实例不等于零事件。
没有修改或重启协议进程；独立只读补充观察先核对本任务已启动控制器的父进程及完整参数，
按实际文件路径确认相同冻结脚本，且明确从晚附加时刻开始。它记录 32 个实例、
6,022 项缺失事件和 427 个观察间隙；原预设 32 实例上限没有提升。
完整普通循环追踪覆盖为 false，这些部分元数据不能复原遗漏部分或归因 H-service。
付款结果来自完整原生认证循环及停止核验，二者结论不同。

原观察器及补充观察原件全部保留。预算内唯一新的完整有限故障判别已经启动，
使用已修正的实际路径识别，从拥有的控制器启动时开始观察；预定原控制器只启动
12 个伴随进程实例，32 实例观察上限仍不变。原 600 秒阶段、60 秒轮、24 高度、
票数、成熟与容量不变。现只声明已启动，不声明通过、H-service 归因或完整覆盖。
若再次观察缺失，按既定分支缩小反例，不重复完整范围。

循环及覆盖证据：`evidence/regional-contact-trace-three-region-cycle-20261004.json`、
`evidence/regional-contact-trace-three-region-cold-20261004.json`、
`evidence/regional-contact-trace-three-region-observer-coverage-20261004.json`。
活动范围绑定：`evidence/regional-contact-traced-joint-fault-scope-binding-20261004.json`。

## 单次完整范围终态与本阶段决定

该范围在原 600 秒窗口内未导入成熟，失败；外围 894.190 秒后全部拥有的协议进程
停止。兼容认证前缀停止 E13/P11/A12，issued/liquid/pending-gross 为 300/290/10，
pending-net 为 9；四收件方均 VERIFIED_EVIDENCE_PENDING_IMPORT。
213.504 秒严格停止核验通过：12 原生、4 收款、4 时代保管、1,749 完整 BFT 信封、
3,906 运输档案，所有私有字节和权限未变。三份原 owner 请求均 INCLUDED_IN_LOCAL_LEDGER，
各自最新独立头及完整签署高度重放匹配，预留零；不恢复、替换、退款或迁移它们。

12 个实际 actor 日志的完整规范字节链、来源/二进制/观察器/设置锚绑定均已核对。
所有环从事件 1 收集，无淘汰和拒绝；52 个启动身份不匹配样本和退出时未知明确保留。
最终尚未发布到状态文件的内存尾部仍不可观测，因此零环丢失不等于完整最终尾覆盖。
所有认证与完整当前信封关联来自本次严格冷证据，不靠元数据摘要授权。

P11 当前父块有 18 个本地完整信封、54 条目的路径，42 条目标保留精确信封；
其余 12 条目标信封和目标回执均不存在。三条缺失路径的中间实际保管到首次普通
转发准备分别约 31.533、34.397、64.313 秒；来源一条 Timeout 包入队到首次准备
约 88.318 秒。源 P0 的一个 round-0 Prepare 包已准备 66 次、发送 60 次；
中间 P1 实际保管 23 次（含 deferred），但只准备转发两次、发送一次，P2 拒绝了
这次入站而未取得保管。这条精确路径支持 H-service 的目标保管之前分支。
后期 round-2 包可能接近停止边界；它们缺失不能单独证明长期饥饿。

**H-service 的范围判别完成，具体调度/验证原因仍未证明。** 对这 12 条认证缺失路径，
没有证据支持目标已保管后的 Native 遗漏。不能由总拒绝次数或等待区间推断哪条
局部公平租约、历史选择或验证 CPU 是原因；不能把一次新失败恢复为完整资格。
一次完整判别预算已用完，下一方法限定为本地转交反例：区分实际 Mesh 占用与
未占用时保留的 ordinary/TCP 选择需求。先用精确现有调度函数及真实固定 TLS
小样本，最多两个组件对照；若反例不存在则切换验证 CPU/包选择的操作成本探针，
不以更多完整范围或放宽原门槛来替代归因。新修复必须由该反例证明行为变化后再决定
必要的资格范围；这份失败和其请求/所有头始终保留。

终态证据：`evidence/regional-contact-traced-joint-fault-fresh-20261004.json`、
`evidence/regional-contact-traced-joint-fault-failed-cold-observations-20261004.json`、
`evidence/regional-contact-traced-joint-fault-owner-head-observations-20261004.json`、
`evidence/regional-contact-traced-fault-current-proxima-path-observations-20261004.json`、
`evidence/regional-contact-traced-current-proxima-live-wait-reconciliation-20261004.json`、
`evidence/regional-contact-traced-joint-fault-stage-decision-20261004.json`。

### 最小转交反例已执行

第一份真实固定 TLS 对照在约 0.559 秒完成：实际 OS mesh 锁首先使前台 ordinary
选择尝试按原边界拒绝，随后释放该锁，并让拥有选择意图的前台线程在 Mesh 外
等待一个受控屏障。此时 `local_mesh_owner` 为 null，但保留的 ordinary 意图仍使
实际请求遭 custody refusal，延迟接收器也未保管。前台重新尝试选择并清除意图后，
同一完整已认证请求在延迟接收器中实际持久保管；来源以新请求重试并实际保管回执。
拥有的线程/socket 全部关闭，没有 Native、钱包、签署或旧现场调用。

这证实调度允许“没有实际 Mesh 租约，却因空闲保留意图拒绝接触”这一可复现行为。
屏障是受控的锁外暂停，不是本轮 Native CPU 测量；它尚未证明 31–64 秒等待的全部
原因。下一修复应保留 ordinary 选择的 owner/purpose、真实尝试的公平性、两 TCP 槽、
所有验证及实际 fsync，同时使锁外暂停不无限阻断可用 Mesh 的接触工作。
组件对照预算最多两份，首份已用；先由修复后的同一反例证明行为变化，不启动新的
完整故障范围。若改变调度不能同时保留原实际选择/保管回归，就退出该方案并切换
测量，不能为得到通过降低这些要求。

证据：`evidence/regional-idle-ordinary-intent-component-20261004.json`。

### 空闲意图的有界优先修复

保留 ordinary owner/purpose 作为原线程重试权；新增进程内实际尝试标记与短暂优先
截止。只有当前实际争用，或真实 EAGAIN 结束后原有 0.2 秒窗口，才给予 ordinary
优先；实际 Node 租约仍保护完整验证到关闭。成功、终止与关闭清除优先；两 TCP
角色和 ordinary/TCP 交替、原锁/socket/槽/认证/fsync 上限均不变。短暂让锁窗口
避免立即被连续 TCP 重抢，不能宣称任意 CPU/线程时序下的无条件饥饿自由。

第二份组件先发生真实 OS 锁 EAGAIN，释放锁后让同一 owner 在锁外等待窗口过期，
两次固定 TLS 交换都实际取得目标和来源持久收据，来源以完整 transit 摘要确认
抑制；owner/purpose 始终保留，随后同一普通选择成功。约 0.696 秒完成，全部
拥有线程/socket 关闭，无 Native/钱包/旧状态调用。首次观察断言错误地把 packet ID
同 transit 摘要比较，在第一次双端持久收据之后中止；失败私有现场与报告保留，
修正观察断言后用新目录重验，并未改变协议实现或用该失败宣称成功。

工作来源相关 50 项回归通过；新增真实 TCP 长租约使普通尝试 EAGAIN 后短暂让锁，
普通重试完成，两 TCP 角色随后各取得实际 Node。审阅指出测试应等待入站 waiter
注册且不能把租约释放后的 append 顺序当成授予顺序，已固定屏障并比较角色次数。
精确来源 396 文件冻结为 `67ad71f18be1578005caab76689297d7b12f8ba1d46c9e804bc72ced6fd2d858`，
Native/core 字节未变；默认驱动实际重建，528 项完整回归 286.381 秒、三个 Runtime
保管边界 3.592 秒通过；184 Native/strict 检查复用逐字节未变来源证据。两组件判别预算用完，
本阶段反例行为修复；尚未启动新的普通循环或完整故障资格，旧失败保持失败。

证据：`evidence/regional-bounded-ordinary-preference-component-20261004.json`、
`evidence/regional-bounded-ordinary-preference-observer-failure-20261004.json`、
`evidence/regional-bounded-ordinary-preference-source-inventory-20261004.json`、
`evidence/regional-bounded-ordinary-preference-stage-decision-20261004.json`。

完整核验：`evidence/regional-bounded-ordinary-preference-frozen-checks-20261004.json`、
`evidence/regional-bounded-ordinary-preference-runtime-custody-20261004.json`、
`evidence/regional-bounded-ordinary-preference-oneway-default-native-lifecycle-20261004.json`。
下一单次普通循环使用精确重建驱动、新签无价值 genesis 与全新目录，默认追踪关闭；
只有循环/严格停止冷核验通过后才决定新的有限故障预算，当前完整故障预算仍为零。
若普通循环失败，保留现场并按停止核验/新反例判别，不原样重复。

### 新普通范围的控制器观察失败与独立修复

第一份默认关闭追踪的新普通范围在 346.082 秒后失败并干净停止；已达 E8/P4/A0，
32 次正常启动。保留的仙女座副本 1 状态明确 `native_observation_available=false`
且观察为 null；原控制器 pending 谓词直接下标造成 TypeError，未完成价值返程。
31.436 秒严格停止检查通过：12 原生、4 收款观察、4 时代保管、492 完整信封、
1,088 运输档案；私有字节和权限完全未变。没有恢复或改写其值/头/失败报告。

控制器现在只把不可用或 null 的可选观察返回为等待未知；仍需全部四副本正常
观察与原有每条出口记录判据，不制造高度/导入，不重置 600 秒截止。原状态字节
对照证实旧谓词抛错、新谓词返回未知；8 项冻结控制器检查及 16 项相关检查通过。
节点来源 `67ad71...` 与二进制 `3019b6...` 保持逐字节不变，控制器三文件单独冻结
`50259ae2b36b96272e8676f7a0630fc314d7b34d1a25891b6a7f9e2f707640d2`；
执行其入口使实际导入 corrected Campaign，其他依赖固定到原节点来源。

下一完整有限故障的停止核验发现独立控制器来源绑定缺口，提前修复：默认路径
仍要求节点目录中精确 drill；显式分离路径核对完整控制器清单、全部规范路径及
父目录无链接、实际 drill/价值审计/密文计量三个摘要，再执行全部原冷检查。旧
控制器 manifest 的历史节点 pin 不提供 Native 权。分离核验三文件冻结
`4bb57a09e076b25ac6d74f3c1dde0352cf8f2e8fc8f8372a4d6987ad9c4ead09`；
18 项冻结检查与 45 项相关检查通过，同一旧失败仍在原生阶段前被拒绝。首次相关
检查缺少测试所需二进制环境，原日志保留；补齐准确冻结二进制后通过，无代码降级。

新控制器单次普通范围预算为 1；只有完整返程及严格冷核验通过后，才决定新有限
故障范围，当前故障预算仍为零。若失败，保留原件、停止冷核验并换最小判别；
不得原样重复、改付款、抬上限、放宽成熟或把历史失败回写为通过。

证据：`evidence/regional-bounded-ordinary-preference-three-region-cycle-20261004.json`、
`evidence/regional-bounded-ordinary-preference-three-region-failed-cold-observations-20261004.json`、
`evidence/regional-bounded-ordinary-preference-pending-observation-counterexample-20261004.json`、
`evidence/regional-retained-pending-observation-component-20261004.json`、
`evidence/regional-pending-observation-cycle-controller-source-20261004.json`、
`evidence/regional-separate-fault-controller-verifier-source-20261004.json`、
`evidence/regional-controller-observation-binding-checks-20261004.json`、
`evidence/regional-pending-observation-stage-decision-20261004.json`。
