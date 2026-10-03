# Rldcoin 主计划当前状态

对应主计划与白皮书 1.11。

2026-10-03 用户决定：废弃主网的全部资料不再作为实现、资格或完成度依据。当前评估仅使用无价值测试网及对应准确版本的地区候选证据。

**目标协议已定义；完整协议资格与实际星际支付服务尚未完成。** [主计划](RLDCOIN_MASTER_PLAN.md)将 I1–I12 定为强制条件，A–G 仍是必需地面基础。完成 A–G 或一次演练都不能自动标记全计划完成。

后续演练路径约束已实现 `Scope.rebind`，只重新绑定完整存在的私有路径，保持角色/成员/阈值/时限和所有空 slot；同源/嵌套/父目录别名、相对/越界/缺失/符号链接路径拒绝，既不复制也不创建签署保管。[四项新路径和十项既有范围检查实际通过](operations/evidence/regional-role-fault-private-rebind-local-checks-20261003.json)。这不是成功冷现场或故障演练结果，运行冻结源未改动。

## 2026-10-03 独立有界出站候选：69 项相关检查通过，待冻结普通付款

[普通 BFT 生命周期的单出站线程](operations/REGIONAL_PARALLEL_CARRIAGE.md)在完整 Runtime 冷打开之后默认启用原固定 TCP adapter；其他线程/第二 worker/重入拒绝，无 Native、钱包或签署接口及前台回退。原四出站联系/四 transit/十六 receipt/三秒 socket/0.2 秒本地锁、所有容量和 Native 20/600/300 秒规则保持。只有至多 64 KiB 的 canonical 最后 TCP 观测；无 pass 为 unavailable/null，并行 TCP 耗时不冒充串行 tick 阶段。短时 mesh 选择锁争用只成为未知；坏签名/结构仍拒绝。停止须等待当前本地保管和全部入站/出站线程真正退出才释放 service 保管。

[69 项实际相关 Native/TLS/接收/观测检查](operations/evidence/regional-parallel-carriage-local-checks-20261003.json)通过，耗时 95.125 秒，含七个新 worker 与两个 mesh 锁/损坏检查。真实 Native Commit 已持久入队，在普通 Native contact-status 被屏障阻塞时仍以真实固定 TLS 送达；收件 Native 高度零、不因运输入账。两个本地票的六个消息/目的对用原四对预算的两次 component broadcast 排空，不是普通调度完成。首轮测试的接口错误和未入队目的案例、第二轮失败源/日志均保留；正确入队前置后八项聚焦检查通过，随后关闭等待修改再经完整相关 69 项通过。Native/Core 与前冻结逐文件相同，组件使用原 Native binary；新的冻结 ordinary startup、完整过程、保管及付款/全部历史冷核验尚未运行。此前发送/接收 ID 环的失败仍失败，没有重启旧请求、解除预留、放宽阈值/关卡、发布或采用。

## 2026-10-03 发送 ID 环候选：295 项过程通过，第三笔付款关卡失败

[逐邻居 V3 调度](operations/INTERSTELLAR_TRANSIT_ID_RING.md)改为保存最后实际携带的包 ID，在其排序后继继续，发送前仍持久化。真实签名收据使首四包归档后，冻结 V2 实际跳至旧第 9–12 包，新版本继续第 5–8 包且归档仍完整可读/认证；插入亦不改变原等待后继。旧 V2 私有状态拒绝而不转换，原四 transit/十六 receipt、认证、Native、时限/容量保持。首轮测试误用不存在接口而失败，原测试源保留；修正为实际 receive 后两个聚焦检查及[169 项相关传输/冷检查](operations/evidence/regional-transit-id-ring-local-checks-20261003.json)通过。尚待新的完整冻结普通付款/历史冷验收；不把这个动态排序缺陷当作上一失败的唯一原因。

已冻结 322 文件，集合 `170038ab55273e32c06debe4f11192929b68b81f80b7e50c591e36ac78263403`。Native/Core 与上一冻结逐文件相同，复用已实际通过的 167 项原生/严格检查而未重复声称执行。[新的发布构建和 295 项完整过程检查](operations/evidence/regional-native-bft-transit-id-ring-checks-20261003.json)实际通过，构建 39.856 秒、过程 226.222 秒；[三个真实 Runtime 签署恢复分支](operations/evidence/regional-native-bft-transit-id-ring-runtime-custody-20261003.json)实际通过。[全新普通两次交接/三笔付款](operations/evidence/regional-native-bft-transit-id-ring-payment-campaign-20261003.json)运行 1188.846 秒后在原 600 秒第三笔付款纳入/收款成熟关卡失败。20 次启动实际完成，控制器共识授权调用零，全部归属节点正常停止；保持原 20 秒基准、300 秒冷启动观察及所有认证/容量，没有重启、退款、替换请求或改判。完整成功历史冷核验和后续有限故障演练未运行。

[停止只读冷观察](operations/evidence/regional-native-bft-transit-id-ring-failed-cold-observations-20261003.json)确认五个完整 Native 前缀均为高度 11/时代 2、各发行 300 守恒；前两笔已纳入/预留零，第三笔仍 SIGNED_PENDING_INCLUSION/预留 20，三个 owner head、11 voter/8 readiness 另存 head 相符。3,626 运输归档和 171 当前父块完整 Native 信封实际认证，全部私有字节/权限/属主/链接数未变；这不是全部历史成功冷验收。9,708 条有界事件/2,967,617 字节无遗漏或容量拒绝，记录的 Native receive 无失败。第六轮最终有三个 Prepare；节点 3 冷留存三个不同 Commit，其余各两个，而最后普通搜索均只观察到两个，说明停止留存不能替代当时完成证书/入账。末阶段五个顺序冷启动各用 22.682/27.334/33.753/34.464/21.767 秒，时间域与停止阶段仍需区分，不据此宣称唯一原因或放宽原关卡。

[当前消息运输核对](operations/evidence/regional-native-bft-transit-id-ring-current-carriage-20261003.json)对 35 份完整源 Native 认证消息逐个比较：已有目的地运输收据却未进入 Native 的当前消息为零。第六轮节点 3 的 Commit 在其他四个目的地均无包/收据/Native 留存，节点 2/4 的 Commit 则已到达其余节点；这是停止后的路径观察，不证明精确选择/到达时序或唯一因果。旧失败状态完整保留，不启动只允许成功高度 14 付款/冷现场进入的后续有限缺席演练。

[最后三份 Commit 的完整路径核对](operations/evidence/regional-native-bft-transit-id-ring-final-commit-carriage-20261003.json)再次原生认证三个源完整信封并认证五个停止运输库存。节点 3 的四个目的包均已在其源端活动队列中，均无目的收据且其他载体均未保留；未丢失、未归档或退款。其最后记录 tick 中 Commit 原生签署成功，随后 TCP 阶段只用约 0.000031 秒，正常停止处理可使 TCP running=false；这不能证明签署发生于原关卡之前，不能从停止留存追溯付款通过。全部私有文件仍相同。后续改进须把有界运输与耗时账本认证的推进分别观察，保留同一普通生命周期、精确预备交换/挑战/本地持久收据、单一出站调度所有者及停止保管边界；当前版本尚无独立出站工作线程。

## 2026-10-03 有限新时代缺席领导者演练：控制器与冷核验入口已实现，尚未正向运行

[单独演练](operations/REGIONAL_BFT_ROLE_MISSING_LEADER_DRILL.md)只从完整高度 14 付款/冷核验成功现场进入，重新实际认证后保留原现场并创建私有同机副本。控制器只读 Native，当前端点验证者缺席时由普通节点独立推进，再以四加五共九次启动完成追赶。原阈值、600 秒关卡、保管日志/head/空角色保持；独立冷模式认证全部历史信封/归档/时代/付款，并核对真实三票正轮次证书。当前运行的 318 文件源未改动。[28 项实际局部检查](operations/evidence/regional-role-missing-leader-final-local-checks-20261003.json)通过；[旧失败现场的实际 CLI 入口拒绝](operations/evidence/regional-role-missing-leader-failed-entry-refusal-20261003.json)通过，未访问不可达的源/binary/manifest 参数，未创建演练现场。正向演练及新冷模式尚未执行；不构成 R11、跨区域价值、真实中断、独立或复制密钥保管资格。

## 2026-10-03 接收 ID 环候选：283 项过程与三项签署恢复通过，第三笔付款关卡失败

[新轮转候选](operations/REGIONAL_CONTACT_RECEIVE_ID_RING.md)仅为既有 novel/background 类各保存一个进程内最后选择的包 ID，从其排序后继继续并环回。既有数字 rank 会随成功接收移除而跳过下一批等待项，新局部反例直接保留该差异。保持非空双类各占两个原四槽、proof 变化仍 novel、空类让余量、每份 transit/receipt 和完整信封认证后再去重；未改变持久状态、Native/Core、签署、阈值、时限或 socket/容量。重启只清调度 ID，完整 Native 冷检查保持。[23 项局部模型/冷映射/阶段及两项真实两次交接 Native 接收回归](operations/evidence/regional-native-bft-receive-id-ring-local-checks-20261003.json)实际通过；后者验证冷 Service 接收新票/提交、合法 proof 变化与坏后续签名拒绝，原始信封/head/ledger 保持。已冻结 318 文件，集合 `5dec4efdc1007c9a4a6b279f12930eafdbacce1f47df29d481ebfb89a17218f1`；Native/Core 每个库存字节与上一冻结精确相同，复用其已实际通过的 167 项原生及严格检查，不重复声称执行。[冻结发布重建和实际 283 项完整过程检查](operations/evidence/regional-native-bft-receive-id-ring-checks-20261003.json)已经通过；[三个实际签署状态恢复分支](operations/evidence/regional-native-bft-receive-id-ring-runtime-custody-20261003.json)已经通过，含两种提交发布失败，保留独立 caller head 后重新打开不重复签署。[全新普通付款流程](operations/evidence/regional-native-bft-receive-id-ring-payment-campaign-20261003.json)于 1401.795 秒失败，止于原 600 秒第三笔付款包含/终端观察关卡；全部 20 次普通启动已完成，控制器共识授权调用为零，归属进程全部正常停止。未重启、退款、替换请求或改判。[停止冷观察](operations/evidence/regional-native-bft-receive-id-ring-failed-cold-observations-20261003.json)确认五个高度 11/时代 2 完整 Native 前缀，各发行 300 守恒；前两笔纳入/预留零，第三笔 SIGNED_PENDING_INCLUSION/预留 20，11 投票/8 批准另存 head 相符。3,825 运输归档及 108 当前父块信封认证，全部私有字节/属主/权限/链接数不变。[当前运输观察](operations/evidence/regional-native-bft-receive-id-ring-current-carriage-20261003.json)有 9 份目的地收据对应 Native 未保留消息；[停止日志出现观察](operations/evidence/regional-native-bft-receive-id-ring-log-presence-20261003.json)不重构确切接收选择，不能证明唯一因果；源 0 的三包未出现于发布日志，源 2 的六包仅最后八条或更少状态中出现。10,781 条有界事件/3,265,879 字节、遗漏零。完整付款/全部历史信封冷验收及额外缺席核查没有通过。这三项局部保管检查不构成普通运输、真实进程中断或独立保管资格。原 Native 20 秒基准/600 秒关卡/所有上限保持，不改判、重启或迁移上一失败现场。

## 2026-10-03 停止核验的只读载体保管边界：8 项局部检查通过

停止角色核验新增明确拒绝：配置为 null 的未来时代 slot，其 fixture voter/readiness 及分别保留的 caller 名称空间必须不存在目录、普通文件或悬空 symlink。既有历史时代保管不删除、不打开、不初始化/恢复。[8 项实际局部检查](operations/evidence/regional-role-keyless-cold-local-checks-20261003.json)通过（四项既有 Native/外部配置映射与四项新增缺席状态检查），测试仅使用新临时目录；没有访问当前或旧付款私有现场，没有改变 Native/Core/普通运行时。运行中的 315 文件冻结管线仍使用原核验器，不能把新检查追溯为该管线已执行；若完整付款/原冷检查成功，后续故障前还须绑定 exact run/cold/source 的停止缺席核查。[单独停止缺席核查入口](operations/REGIONAL_BFT_ROLE_FAULT_SCOPE.md)现已实现，复用成功范围门槛并绑定 run/cold/source/binary/原 verifier/外部设置，先确认归属进程停止，输出在私有现场/冻结源码之外；[确切已保留的失败周期入口反例](operations/evidence/regional-role-keyless-stopped-entry-final-refusal-20261003.json)实际在任何 source/binary/私有访问前拒绝。初版源码与观察也保留；没有对当前未结束周期执行正向核查，也没有重复 Native 认证或提供独立 freshness。此工具边界不是全故障/独立保管资格。

## 2026-10-03 兼容事故证明提前拒绝候选：167 项原生、273 项过程通过，第三笔付款关卡失败

[停止后的提案运输核查](operations/evidence/regional-native-bft-role-certified-leader-proposal-delivery-20261003.json)对三份实际源 Native 认证提案确认：载体 3 留有相应 destination 包与签名运输收据，但没有相应原生保留提案，其他载体或源端均有；所有私有字节不变，没有私有运输密钥读取/运行/恢复，不重构此前选择时序或证明唯一失败因果。该载体最后进程的 99 次 bft-epoch-activate 累计 266.66 秒；当前实现中同步依旧逐对为兼容历史认证事故证明，原生检查入站消息/时代证明继续完整认证。

[新的负向事故预检查](operations/NATIVE_COMPATIBLE_INCIDENT_PREFLIGHT.md)只把原有有界区域/规范顺序/结构不兼容判据放到事故证明双历史认证之前；结构上不可能证明冲突的组合立即拒绝，不授予任何权威。潜在冲突仍完整认证两份历史才允许成功，普通入站证据在存储/去重前的全部认证和 commit/replay/fsync、时限/阈值/上限保持。[实际四项既有事故与一项新反例](operations/evidence/regional-native-compatible-incident-preflight-local-checks-20261003.json)通过；初始过滤器未包含新测试，明确另跑新用例：兼容但坏签名的事故组合拒绝，普通证据准入仍拒绝且 journal/ledger/incident 不变；真实冲突仍成功认证，篡改的潜在冲突仍拒绝。这是改变 Native 实现的独立候选，必须新冻结、全套原生/过程/严格检查及全新签名无价值创世/私有目录，不迁移任何失败余额/保管；普通付款、完整冷/全故障/物理独立资格未完成。 最终冻结 315 文件，集合 `ec14673fa9d81193e0c5fc0d8c7d5be88650db4a43893c75e4dea87d52d54b12`，Native 源 `e5a0fb4b2dcd359021208ab27d78c4c2d06c5fbc58856dc6a6bf4c29ec4b992c`，新实现 `5415647bdccf790c871f27e02e115549f3b32161e05faf8606409ed8fdb987fc`。[实际发布构建、严格检查、167 项原生和 273 项过程回归](operations/evidence/regional-native-bft-compatible-incident-checks-20261003.json)均通过；[三个真实 Runtime 签署保管分支](operations/evidence/regional-native-bft-compatible-incident-runtime-custody-20261003.json)通过，分别验证正常 Prepare/Commit、pending 发布失败和 outbox 发布失败后原样恢复确切已保留响应，不重复签署。新签名无价值 currency `17dc344828e0f336279cc427a385ed90773608e11cfbe8cd5e7a1ce86d494fba` 的[全新普通三时代付款](operations/evidence/regional-native-bft-compatible-incident-payment-campaign-20261003.json)实际运行 1,219.225 秒后，在第三笔入账/全体终点的原 600 秒关卡失败；20 次普通启动实际结束，控制器共识权威调用零，全部归属进程停止，不延长、重启、恢复或替换请求。[严格只读停止检查](operations/evidence/regional-native-bft-compatible-incident-failed-cold-observations-20261003.json)认证五份高度 11/时代 2 完整 Native 前缀，各发行 300 守恒；前两笔纳入/预留零，第三笔仍 SIGNED_PENDING_INCLUSION、预留 20，没有退款。11 投票/8 批准日志与另存 head 核查，3,764 运输归档和 170 份各自当前父块信封认证，私有字节/属主/权限/链接数不变；不是全部历史成功冷验收或全故障。[完整有界 trace](operations/evidence/regional-native-bft-compatible-incident-collection-20261003.json)保留 9,617 事件、2,946,331 字节，缺序零、未触及 8 MiB 上限；操作耗时不是隔离性能基准或唯一因果。[确切当前运输核查](operations/evidence/regional-native-bft-compatible-incident-current-carriage-20261003.json)完整 Native 认证 36 份源拥有的当前消息，再按严格 MeshInspection 核查目的包/收据：载体 2 的五份目的包与签名收据已保留，但其原生 body 尚未保留，包括轮次 5 提案/一份 Timeout，以及轮次 6 的两份 Prepare/一份 Commit。原私有现场不变，收据不授予 Native 权利，也不重构全部此前调度。原生负向检查仍有独立安全回归，但此次普通活性失败，未发布/采用。


## 2026-10-03 原生证书未来领导者调度：263 项过程通过，第三笔付款关卡失败

[后续角色故障范围入口](operations/REGIONAL_BFT_ROLE_FAULT_SCOPE.md)已实现为独立控制器辅助：只接受精确成功的五载体高度 14 三时代付款及完整停止冷核验，绑定 run/source/binary/setup，要求全部 11 投票/8 批准 head、五份完整账本及全部信封/运输归档/所有者检查；Native/Core/普通依赖字节必须不变。当前 Native 查询提供实际时代/成员/高度的缺席 leader 后继门槛，已离席 keyless 载体不能充当 voter。10 项范围模型通过，确切已安装时代失败 run 实际拒绝，未调用 Native 或访问私有现场。辅助入口不提供账本/保管权威，也不是已执行故障或 SIGKILL；后续须实际重验源、运行和冷核验，完整 R11/全故障仍未通过，不改判旧失败。

[独立调度候选](operations/REGIONAL_BFT_CERTIFIED_LEADER.md)允许本地合法未来 leader 用完整前一轮三票 Timeout 证书发起提案，不必等自身计时器逐轮追赶；先保持当前 Prepare/Commit 和已有未来 Proposal 的优先级。保留行只选候选轮次，完整证书/HQC/价值/锁/head/领导权仍由 Native 验证，正常首次 tick 出块间隔、32 轮/128 签署/每 tick 两签及全部期限不变。[9 项新模型及 9 项既有阶段检查](operations/evidence/regional-native-bft-certified-leader-local-checks-20261003.json)通过；真实两次显式交接 fixture 的篡改证书用例拒绝无签署/head/ledger 变化，正例保持正常出块间隔后原生从本地轮次 0 发出合法轮次 2 提案，再 Prepare 且不重复提案，其他 heads/ledger 不变。最初正例误期待首次启动计时的 tick 即签署而失败，源/日志保留，修正观察时机后单独重查通过。显式携带设置不是普通全周期/全故障，短暂同机重叠不是隔离性能基准。Native/Core 精确不变，不改动正在运行的上一冻结，不迁移旧钱包/余额/保管。首次库存断言误要求上一包已含 AGENTS.md，冻结准备拒绝；保留其不完整源码库存与生产脚本，另取新目录显式加入 AGENTS.md 和三份新入口。最终冻结 311 文件、集合 `8348e6808d2df439a623b4a84a230afce0ef024b9c41bd6d595d02adf9740b19`；[实际发布重建与 263 项完整过程回归](operations/evidence/regional-native-bft-role-certified-leader-retry1-checks-20261003.json)通过，[三个真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-certified-leader-retry1-runtime-custody-20261003.json)通过。166 原生与严格检查绑定上一个精确相同 Native/Core 的报告复用，本次没有重跑。测试与上一普通运行同机部分重叠，耗时不作为隔离性能基准。[全新私有目录普通三时代付款](operations/evidence/regional-native-bft-role-certified-leader-retry1-payment-campaign-20261003.json)实际运行 1,282.859 秒，在第三笔入账/同步成熟的原 600 秒关卡失败；所有归属进程停止、控制器共识权威调用零，没有延长/重启/恢复或替换请求。[严格停止只读核查](operations/evidence/regional-native-bft-role-certified-leader-retry1-failed-cold-observations-20261003.json)认证五份高度 11/时代 2 完整 Native 前缀，各发行 300 守恒；前两笔纳入、预留零，第三笔仍为 SIGNED_PENDING_INCLUSION、预留 20，没有退款。全部 11 投票/8 批准日志和另存 head 核查，3,595 运输归档与各自当前父块完整信封认证，私有字节/权限/属主/链接数不变。10,555 条有界 trace 零进程序列缺失；本机时间观察不授予权威或证明唯一因果，尚非成功全部历史冷验收/全故障。未来 leader 的局部原生正反例仍成立，但此次普通周期失败，不发布采用或声称该修复已解决普通活性。

## 2026-10-03 已安装历史时代原生观察候选：166 项原生、252 项过程通过，付款成熟关卡失败

[上一新顺序周期的有界时间记录](operations/evidence/regional-native-bft-role-contact-order-timing-20261003.json)保留实际 8,998 事件、零缺序/容量拒绝；最后五个进程的显式时代激活各 59–144 次、累计约 29.20–82.45 秒，最长已计量 tick 阶段约 7.91–17.76 秒。观测只覆盖被计量操作，阶段不含最后状态发布/间隔，跨进程时钟不比较；不是隔离基准或失败唯一原因。

[新的独立原生观察候选](operations/REGIONAL_BFT_INSTALLED_EPOCH_OBSERVATION.md)在原生锁内完整历史重放后，仅按当地有序 `Epoch` 事件返回确切已安装原证明并匹配当前 chain epoch；已验证但未选中证据不进入观察。伴随先完整认证新信封和同步依赖，再比较完整 canonical 证明字节，确切历史已安装项可省重复 pack/activate；变化的合法证明仍走 Native 激活，坏后续信封仍先拒绝，原证据/head/锁及 16 时代/8 MiB 上限不变。

初次冻结因 CLI 引用库内部私有函数构建失败；第一次修正发布构建通过但新原生测试漏掉 Box 包装，严格检查失败。两次源/构建/失败日志原样保留，没有从失败构建运行付款。第二次修正冻结 307 文件，集合 `d77a9e264fb9eac4277178f02b72948511082b8a34d45bd8311953ebd721b0f7`、Native 源 `1be82ddceb9a0b053d30e335a74a9f5ceefa5c1f635e0499bd714c58ebe0fddd`；[发布构建、严格检查、166 项实际原生测试及 252 项完整过程回归](operations/evidence/regional-native-bft-role-installed-epochs-retry2-checks-20261003.json)通过，[三个真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-installed-epochs-retry2-runtime-custody-20261003.json)通过。Core 精确不变；此次 Native 源已变，原生测试实际重跑，没有沿用旧 Native 资格。全新签名无价值 currency `dffdfc437dd564d399d1fc65c6090f2de4d45008076c142bb281f6d1c8644862` 的[普通三时代付款](operations/evidence/regional-native-bft-role-installed-epochs-retry2-payment-campaign-20261003.json)实际运行 1,196.720 秒，在第三笔付款入账/成熟的原 600 秒关卡失败；所有归属进程停止，控制器共识权威调用零，不延长/修复/重启原现场。[严格只读停止核查](operations/evidence/regional-native-bft-role-installed-epochs-retry2-failed-cold-observations-20261003.json)确认五份完整 Native 前缀高度 11/11/12/12/12、时代 2，各发行 300 守恒；固定签署源载体 2 已实际纳入三笔所有者付款，钱包预留均零，领先载体的第三收款输出 10 在其高度 12 已成熟；高度 14 是完整五载体验收的固定终点，不是该输出的成熟高度。落后载体不是全局未入账证明，运行仍未完成全体到达高度 14 的关卡。11 投票/8 批准日志和另存 head 核查，3,689 运输归档全部认证，65 份各自当前父块完整信封 Native 认证，全部私有字节/权限/属主/链接数不变；不是全部历史成功冷验收或全故障通过。[只读有界 trace](operations/evidence/regional-native-bft-role-installed-epochs-retry2-collection-20261003.json)保留 9,010 事件，阶段/进程时钟不授予权威或唯一失败因果。后续未来 leader 的过程检查短时同机重叠，不称隔离性能基准。没有旧余额/现场/保管迁移，未发布或采用。

## 2026-10-03 当前请求/历史收据公平调度 V2：选择与失败保管检查通过，普通付款待验收

[上一停止现场的严格只读观察](operations/evidence/interstellar-requested-receipt-rotation-observation-20261003.json)确认某邻居 271 份可携带收据中有 32 份匹配当前签名库存请求，下一静态 16 条批次仅匹配 1；其它已知邻居下一批亦有零匹配。原现场字节不变，没有身份私钥读取、socket、签署、恢复或 Native 价值操作；不是此前实际排队过程重构、唯一失败因果或原失败改判。

[新 V2 私有调度候选](operations/INTERSTELLAR_REQUESTED_RECEIPTS.md)仍用 16 条收据，按确切已认证 peer inventory 请求与历史反向路由公平分配，各自独立逐邻居有界 cursor 按实际已携带数量持久化后才 I/O；交错两个类别并用持久化计数奇偶轮换首类，一条收据的收窄字节预算也不会排除另一类。所有收据、四 transit、64-MiB 组合状态及原 Native/归档/网络/签署/时限不变，完整签名/匹配/重复归档 fsync 不减；请求与存储摘要不授予托管或 Native 价值。旧 V1/伪造新 marker 缺字段的私有状态原样拒绝，无转换，严格冷检查同时绑定两份 cursor 键集到外部固定联系。

首批 25 项实际通过；扩大相关 166 项时，两条新测试误引用共享包装的顶层字段而出错，其余通过，原失败测试源码/日志保留。改为确切包装 `state` 的字段后，最终 8 项新检查实际通过，覆盖请求入首批且保留历史、双类全轮转/冷保留、同行隔离/公开构造不写、持久化/容量拒绝不推进不删证据、单条字节预算交替、旧身份/伪造字段拒绝、cursor 回绕与非法值。这八项新检查没有 Native 账本/钱包或旧现场变更；另新增严格只读外部 cursor 键集拒绝用例通过。冻结 306 文件，集合 `360a2a0fdba18e9ada1f02d95f0b7dde006ef2f53145a41ee087d89c17d5c710`；[发布构建与 251 项完整过程回归](operations/evidence/regional-native-bft-role-requested-receipts-checks-20261003.json)及[三个真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-requested-receipts-runtime-custody-20261003.json)实际通过。Native/Core 精确不变，165 项原生/严格检查复用未重跑。[新普通三时代付款](operations/evidence/regional-native-bft-role-requested-receipts-payment-campaign-20261003.json)实际运行 1,320.181 秒，通过两次交接和三笔原生所有者签署，在第三笔入账/成熟的原 600 秒关卡失败；原 20 秒基准/既有换轮退避和全部上限不变。所有归属进程已停止、控制器共识权威调用零。[严格只读冷观察](operations/evidence/regional-native-bft-role-requested-receipts-failed-cold-observations-20261003.json)认证五个高度 11/时代 2 完整原生前缀，各发行 300 守恒；前两笔纳入且预留零，第三笔为 SIGNED_PENDING_INCLUSION、预留 20，没有退款或替换请求。全部 3,829 运输归档及 111 份当前父块信封认证，11 投票/8 批准日志及另存 head 相符，原私有字节/权限/属主/链接数不变；尚非成功全周期冷验收或全故障通过，未发布/采用。 [停止后确切查询](operations/evidence/regional-native-bft-role-requested-receipts-stopped-phase-20261003.json)在四个投票者上通过 Native 生成包含 Spend 的未签署高度 12 模板；各自当前轮次的上一轮仅保留 1–2 份不同 Timeout，不足形成三票证书，当前本地均不是对应轮次 leader。没有 Runtime 启动、钥匙读取、签署、安装/同步或恢复，原私有文件不变；这是最终静态状态，不重构此前排队时序或证明唯一失败原因，未签署模板也不授予入账。

## 2026-10-03 普通接收/共识阶段有界时间观察：232 项通过，付款在高度 10 失败

针对上一整批轮转运行在高度 10 留存三份 Prepare、零 Commit 的失败，加入[本进程有界观测](operations/REGIONAL_BFT_PROCESS_OBSERVATION.md)：记录完整信封原生认证/依赖同步后接收、原有 distinct-vote 搜索、当前 native context/round 与 timer age、原签署 pending/head/outbox 路径及每 tick 阶段耗时。128 条原始标量事件、单条 1,024 字节/192 KiB 快照、32 操作计数；重启清空、淘汰明确计数，不读入或恢复任何授权，不改变原生源、签署规则、时限、批次或容量。遥测不进入普通控制台消息，独立只读收集器需绑定进程序列并报告遗漏/容量。

聚焦 15 项请求顺序/有界遥测检查通过；首轮加入真实原生信封反例时，测试引用了错误的压缩 snapshot 字段，原失败测试源码及日志保留。改用确切 native-packed committed-vote 路径后复查，再冻结源码、运行完整过程回归/真实 Runtime 保管及原 600 秒关卡下的全新三时代付款。尚未宣称本次普通周期或全故障通过，全部原失败目录保持。

冻结 303 文件、集合 `035fdbf0efa7da165c01fda58f02b016db86096a8f861b2c5f33ef10eae0f0a0`；[发布构建与 232 项完整过程回归](operations/evidence/regional-native-bft-role-process-observation-checks-20261003.json)及[三个真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-process-observation-runtime-custody-20261003.json)实际通过，Native/Core 精确不变，165 项 Native 与严格检查明确复用。[新普通三时代付款](operations/evidence/regional-native-bft-role-process-observation-payment-campaign-20261003.json)在原关卡运行 791.309 秒后失败：第三笔签署前 600 秒高度期限到期，所有归属进程停止、控制器共识权威调用零，第三钱包未创建。[严格停机只读检查](operations/evidence/regional-native-bft-role-process-observation-failed-cold-observations-20261003.json)确认五份 Native 完整前缀均为高度 10/时代 2、发行 300 守恒；前两笔已入账且预留零、另存钱包/投票/批准 head 相符；全部 2,353 运输归档与活动包认证、29 份当前父块完整信封 Native 认证，全部私有字节/权限/属主/链接数不变，仍非全部历史成功冷验收或全故障通过。

[只读有界收集](operations/evidence/regional-native-bft-role-process-observation-collection-20261003.json)实际保存 7,952 事件、2,319,313 字节，低于独立 8-MiB 诊断上限，进程序列遗漏零。[时间分析](operations/evidence/regional-native-bft-role-process-observation-timing-analysis-20261003.json)确认高度 8 轮次 0，载体 2/3/4 首次查询到三份 Prepare 比自身 Timeout 请求晚 48.936861/49.626719/62.747093 秒；载体 0 较晚 Prepare 后正常发出 Commit，未形成完整提交门槛。不同进程时钟不可跨域比较；本机另有候选请求顺序回归短时重叠，不能当隔离性能基准或唯一失败因果。高度 10 停止时普通查询最多两份 Prepare、零 Commit；冷存留票也只有一或两份，不能把早先高度 8 的三票结论套到高度 10。原源码、失败报告、全部现场和本进程 trace 保留，不重启或延长关卡。

后续 BFT 普通循环顺序候选把完整既有接收、唯一 Native 共识 tick 与 durable broadcast 放在唯一普通 TCP 批次之前；新回复留待下一接收 tick，异步 Server 的完整认证/保管不变。原循环的真实 Native 回归在发送点观察到零票而失败；调整后观察到两票、另存 head 相符、pending/outbox 清空及完整 Native 认证的已排队 Commit，下一 tick 未再次签署。[38 项相关检查](operations/evidence/regional-native-bft-contact-order-local-checks-20261003.json)通过。保持原接收四条、邻居尝试/每交换四 transit/十六 receipt、每 tick 两次签署上限与全部时限，不增加第二共识 tick/额外 socket；非 BFT 原顺序保持。原观测周期按原源码/原期限失败，未改判。新顺序已冻结 304 文件、集合 `7b8cf5660eb2233bd32f29371344ffef3f89d9fa10e146c117559ab9f47abfbb`；[实际发布构建与 242 项完整过程回归](operations/evidence/regional-native-bft-role-contact-order-checks-20261003.json)及[三个真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-contact-order-runtime-custody-20261003.json)通过，Native/Core 精确不变，165 项原生/严格检查明确复用。汇总脚本最初误预期 241 项，但实际日志 242 项全部通过；原生产脚本和计数失败记录保留，修正后核对日志摘要并沿用已通过的构建/检查，没有重跑。[全新普通三时代付款](operations/evidence/regional-native-bft-role-contact-order-payment-campaign-20261003.json)实际运行 788.597 秒后在第三笔签署前的原 600 秒关卡失败；所有归属进程停止、控制器共识权威调用零、第三钱包不存在。[严格停机只读检查](operations/evidence/regional-native-bft-role-contact-order-failed-cold-observations-20261003.json)认证五份完整 Native 前缀高度 9/时代 2、发行 300 守恒，前两笔已入账/预留零，11 投票及 8 批准日志/另存 head 相符，全部 2,372 运输归档与活动包认证、41 当前父块完整信封 Native 认证，私有文件字节/权限/属主/链接数不变。当前父块仅有一份 Prepare、没有 Commit；完整成功冷验收/全故障未运行，不改判或延长原关卡，未发布或采用。

## 2026-10-03 逐邻居整批轮转 V2 候选：225 项通过，普通付款在高度 10 失败

新的私有 `RLD-CONTACT-TRANSIT-SCHEDULER-V2` 在实际最后携带的原包位置之后继续下一批，计入路径/已验证 hop 抑制跳过的项；空批次才探测一步，当前位置在当前保留池内归一化。每个邻居独立、发 socket/spool 前持久化，其他邻居/global cursor 不影响；全部原包/签名/路由/收据和 Native 授权仍完整验证。保持四条 transit、16 收据、256 活动包、64-MiB 组合状态及全部原归档上限；旧 V1 私有身份/状态原样拒绝、不转换、移除联系仍不删包。严格冷检查另要求活动 cursor 的键集与外部固定联系完全相符，不修复不匹配状态。

[初始 92 项相关回归、最后 14 项调度和一项新冷绑定检查](operations/evidence/interstellar-transit-batch-scheduler-checks-20261003.json)实际通过；这些批次计数有重复，不相加为不同用例。除原五种固定池的逐邻居全覆盖/持久化/容量/原包保持，六次失败准备的四条名额现在实际覆盖 24 条不同包，第七批覆盖全部 25；空抑制批次不授予收据，大型保留 cursor 在单条字节批次下仍完整循环，V1 明确标记和缺失绑定均原样拒绝。没有 socket/原生价值/旧现场访问；性能选择检查不证明当前普通共识失败的唯一原因或全活性。准备新冻结、构建、225 项完整过程回归、真实 Runtime 保管与普通三时代付款，仍用原关卡和 fresh 无价值目录。

已冻结 300 文件，集合 `40004ac994cf14590bf32165e949f2295e91722a5616251825550cf9bfdeca50`；Native/Core 精确不变。[实际发布构建与 225 项完整过程回归](operations/evidence/regional-native-bft-role-transit-batch-checks-20261003.json)通过（构建 38.766 秒、过程 156.337 秒），158 项运输/58 项角色过程/5 项观察/4 项冷映射实际运行，Native165/严格检查明确复用。[三个真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-transit-batch-runtime-custody-20261003.json)在新目录实际通过。[全新普通三时代付款](operations/evidence/regional-native-bft-role-transit-batch-payment-campaign-20261003.json)实际运行 789.146 秒后失败，原 600 秒第三时代签署前关卡到期。15 次普通启动通过，最长 11.680 秒；停止遥测为高度 10/时代 2，第三钱包/首次签署不存在。控制器共识权威调用零，所有归属进程已停止；完整历史成功冷验收和全故障未运行，失败 source/report/stores/logs 原样保留、不恢复或延长关卡，未发布采用。[停止后的完整原生/运输只读检查](operations/evidence/regional-native-bft-role-transit-batch-failed-cold-observations-20261003.json)已完成：五份 Native 完整前缀均为高度 10/时代 2，发行 300=可流通 300、无出口/导入；前两笔已入账、预留零、另存钱包 head 相符。Native 11 投票/8 批准日志与另存 head 一致、pending/outbox 零；全部 2,453 运输归档和当前活动包认证、未索引文件零；当前父块 52 份完整信封原生认证，仍非全部历史成功冷验收。最多 51 活动包，组合状态约 5.30–13.62 MB、每载体归档约 41.22–44.52 MiB，私有字节/权限/属主/链接数不变。五载体当前父块均保留轮次 0 的三份不同 Prepare 和四份 Timeout，却未保留任何 Commit；停止留存不能重构 QC 到达相对于原生封轮/进程局部 seen 集的先后。下一步需在新运行中记录真实接收/当前阶段的有界时间与选择观察，不能凭冷票数修改封轮签署规则、放宽阈值或断言唯一因果。

## 2026-10-03 逐邻居活动轮转 V1 候选：221 项通过，普通付款在高度 9 失败

新的私有身份/状态显式绑定 `RLD-CONTACT-TRANSIT-SCHEDULER-V1`，每个固定邻居独立保存有界活动起点；TCP 和 spool 准备交换后、打开 socket/写联系目录前各持久化推进一步。其他邻居与普通 tick/global diagnostic cursor 不能改变该邻居的活动选择。公开 exchange 构造不推进，不授予托管；失败发送继续保留所有未收据包，正常 TCP 已验证 hop 抑制/周期探测/重启失效规则不变。保留四条 transit、16 收据、256 活动包、64-MiB 组合状态、全部原包/路由/hop/Native 检查及原归档上限。移除联系只忘轮转元数据，旧身份/状态缺少或更改新绑定时原样拒绝；全新私有目录，不迁移证据或价值。

[实际 94 项相关回归与 11 项新调度检查](operations/evidence/interstellar-transit-scheduler-checks-20261003.json)通过。新检查以 5/15/25/64/256 固定包和四邻居真实 prepare 加普通 tick/冷打开，确认每个邻居至多一个完整池轮转内覆盖全部待送包；还检查同行隔离、公开构造不写/global cursor 不影响选择、发布失败不放出 bundle/推进、旧状态/身份拒绝、非法 cursor/绑定、原组合容量拒绝、移除/重新加入不删包、已验证 hop 抑制不授予收据、字节收窄/一条消息轮转、真实 spool 写入失败保持证据，以及最大 cursor 回绕。无 socket、原生账本/付款或旧现场操作，静态覆盖不是动态布局/实际 BFT 完整活性资格。现准备新冻结、发布构建、221 项完整过程回归、真实 Runtime 保管分支和新普通三时代付款，不改判此前高度 9/10/11 失败。

已冻结 300 文件，集合 `da2b75eb153632ae1fac371694910000198a0d352e65fb4ff65cda929bff959d`；Native/Core 精确不变。[实际发布构建与 221 项完整过程回归](operations/evidence/regional-native-bft-role-transit-scheduler-checks-20261003.json)通过，新增 11 项运输调度检查，154 项运输/58 项角色过程/5 项观察/4 项冷映射实际运行；Native165/严格检查明确复用。[三个真实 Runtime 签署保管分支](operations/evidence/regional-native-bft-role-transit-scheduler-runtime-custody-20261003.json)也在新目录实际通过，未跳过原生签署、pending/head/outbox 顺序。[全新普通三时代付款](operations/evidence/regional-native-bft-role-transit-scheduler-payment-campaign-20261003.json)在原参数/时限下运行 787.630 秒后失败，原 600 秒第三时代签署前关卡到期；15 次普通启动通过，最长 11.419 秒。控制器共识权威调用零，所有归属进程已停止；第三钱包/签署未创建，不恢复/迁移此前失败现场，成功后的全部历史冷验收/全故障配置未运行，未发布或采用。

[停止后的只读冷检查](operations/evidence/regional-native-bft-role-transit-scheduler-failed-cold-observations-20261003.json)确认五份 Native 完整前缀均为高度 9/时代 2，发行/可流通 300 守恒；前两笔已入账、预留零、另存钱包 head 相符。Native 11 投票/8 批准日志与另存 head 相符、pending/outbox 零；全部 2,224 运输归档和当前活动包认证、未索引文件零，当前父块 99 份完整信封原生认证。最多 81 活动包，组合状态约 4.87–16.60 MB；私有字节/权限/属主/链接数不变。尚不是全部历史终局冷验收或完整付款通过，也不证明轮转优化是唯一因果。

[全新合成目录的真实批次重叠观察](operations/evidence/interstellar-transit-scheduler-batch-overlap-20261003.json)以固定 25 包、单邻居连续六次准备但不发送，四条批次逐次只前移一格：24 次发送名额仅覆盖 9 条不同包，相邻批次各重复 3 条。全部未送证据保留、无 socket/原生价值/旧现场访问；不是实际线型共识失败的唯一原因证明。后续 V2 候选应在实际最后携带包后继续扫描，空批次才一步探测，并以新私有绑定拒绝旧状态，保持所有认证和上限。

## 2026-10-03 活动帧共享存储候选：210 项回归通过，普通付款在高度 9 失败

新的 `RLD-CONTACT-ACTIVE-SHARED-FRAME-V1` 私有原子状态在同一文件中保存每份原包/路由/hop、完整 canonical 摘要和长度，并共享确切完整帧字符串；网络/节点作用域、组合元数据和共享对象共同计入原 64-MiB 上限。逐份还原原样完整 transit 后仍由原 Node 冷检查验证全部签名/路由/帧，存储摘要不授予账本、签署或托管权。保持 256 活动包、20-MiB 原单次交换、四份 transit、16 收据、32 完成高水位及 4,096 文件/256-MiB 归档上限；Wire Mesh V3/TCP V4 和 Native/Core 不变。旧 inline 状态即使伪加新字段仍原样拒绝，旧身份也不转换；此前失败目录、未收据证据和价值不迁移。

[实际 94 项相关存储回归](operations/evidence/interstellar-active-shared-state-checks-20261003.json)通过，其中 15 项新检查覆盖 exact 冷还原/共享不可变字符串、不同帧保留、组合容量拒绝、展开前长度拒绝、数量上限、损坏/缺失/未引用对象、外部归属、完整路由/hop 摘要、全部存储哈希重算后仍拒绝坏原包签名、旧状态/身份拒绝、原子发布失败、冷多跳/收据，以及真实 SIGKILL 在替换前与替换后目录同步前的现场保持和冷签名认证。中断未返回 acknowledgment，保留替换前 staging 残留；同机进程中断不是断电/跨设备资格。随后完成新冻结、构建、完整回归与真实 Runtime 保管分支；普通三时代付款结果见下，未改判前一完整周期失败，未发布或采用。

已冻结 299 文件，集合 `2f1ede8e5da00b9a003d83424c2c8c2e974aa7952dade03840ee1eefb88d8a64`，Native/Core 精确不变。[实际发布构建及 210 项完整过程回归](operations/evidence/regional-native-bft-role-active-sharing-checks-20261003.json)通过，15 项新增活动存储检查、143 项运输、58 项角色过程、5 项观察和 4 项冷映射实际运行；Native165 与严格检查明确复用。随后[三个全新真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-active-sharing-runtime-custody-20261003.json)实际通过（3.506 秒），未绕过原生签署/head/pending/outbox。

[旧停止现场的只读存储组件对照](operations/evidence/interstellar-active-sharing-component-comparison-20261003.json)仅在内存构造新包装并逐字还原五份原完整状态：原约 56.74/66.98/67.01/66.89/16.93 MB 可保存为约 18.59/28.33/37.44/29.01/7.70 MB，全部处于原 64 MiB 内。每份 pack 约 0.12–0.73 秒、unpack 约 0.09–0.58 秒；没有开旧节点、转换私有文件、删证据或自行执行原生认证，全部原私有字节/属主/权限/链接数不变。该组件结果不能替代新网络的普通调度、签名、完整付款或故障验收。

[全新普通三时代付款](operations/evidence/regional-native-bft-role-active-sharing-payment-campaign-20261003.json)实际运行 786.055 秒后失败：原 600 秒第三时代签署前关卡到期，五个原生账本均停在高度 9/时代 2，第三钱包/首次签署不存在。15 次普通启动观察通过，最长 12.437 秒；控制器共识权威调用零，全部归属进程已停止。成功后的全部历史冷验收与全故障配置未运行，原失败目录/source/logs 全保留，不续跑、恢复付款或放宽关卡。

[停止后的原生/运输只读检查](operations/evidence/regional-native-bft-role-active-sharing-failed-cold-observations-20261003.json)完整冷重放五份 Native 前缀，均发行 300=可流通 300，前两笔已入账、预留零，全部另存钱包 head 相符。全部 2,388 份运输归档及当前活动包签名认证、未索引文件零；当前父块 68 份完整 BFT 信封原生认证，尚非所有历史信封终局冷验收。Native 11 份投票/8 份批准日志冷检查，另存 head 全匹配且 pending/outbox 零，私有字节/属主/权限/链接数不变。新状态实际约 5.14/8.84/12.79/10.66/5.90 MB，最多 65 活动包，没有观察到状态/归档容量拒绝；停止大小不重构每次被拒接的隐藏原因。旧停止数据的空间改善不等于本次共识/完整付款通过；不得认定唯一因果或降签名阈值。

另一份[新合成运输目录的实际轮转观察](operations/evidence/interstellar-active-peer-rotation-observation-20261003.json)在固定 25 包/四出站邻居、每轮四次 TCP 准备再一次普通 tick、持续失败但不删包的情况下，执行 80 次真实准备/20 次完整 tick 与冷打开；每个邻居仅选到 20 包，五包重复遗漏。跨邻居总合集覆盖全部 25 包，没有 socket/原生账本/价值或旧现场访问。它证明当前全局活动 cursor 在这份静态布局的逐邻居公平性缺口；既不是实际五载体线型网络的完整调度复现，也不能认定为当前付款延迟的唯一原因。原待送达证据保留、四条 batch 不变，修复还需新格式/逐邻居持久化和完整后续验证；当前冻结周期不受改动。

## 2026-10-03 有界签票查询索引候选：195 项回归通过，第三笔因活动状态容量未完成

新的 `regional_bft_query_index.py` 仅在 Runtime 完整冷原生检查完成后使用，绑定当前 Messages 对象及其确切不可变记录/快照池、完整原生 context、存储/币种/authority/签署 binding 和当前限制。保存成功且 Messages 更替时清除，失败保存保留原状态/见证，关闭或重启不采用旧见证；追加、本地标记/完整证明更替、context/scope/限制变化重新构建。只保留有界 canonical payload 字节与不可变查询元组，每次返回重新解码，原始记录/载荷和 pack-state 不变。8-MiB/512 见证上限超出则完整旧扫描，不采用部分行；不落盘、不缓存原生 ledger、quorum 或授权。保持不同证明/相同 value 的全部原顺序，单一签名人不能增票；所有冷启动、每份新完整信封、依赖同步和原生 quorum/签名/证书/时代/head 验证不变，原容量和时限不变。

十项合成选择/替换/可变返回隔离/完整证明更替/预算回退/同签名人变体/持久化失败检查，以及原九项阶段分支实际通过（19 项）。另实际通过暖见证下坏完整证明的原生拒绝回归，原账本/caller/存储不变；该项与十项索引检查共 11 项，计数不与前一批叠加。[停止现场纯查询组件对照](operations/evidence/regional-native-bft-role-query-index-component-comparison-20261003.json)在五份旧只读数据的 208–212 条保留记录上，原 32 轮证书搜索筛选约 0.502–0.570 秒，建索引加筛选约 0.015–0.017 秒，暖查询约 0.00055–0.00064 秒；五份查询结果逐字一致，见证约 90,058–93,597 字节。没有实际启动旧 Runtime、重放全部历史信封、签名、原生 quorum/完整 tick/TCP 测量或写旧私有数据；组件优化不证明解决晚到/完整付款失败。随后已完成下述新冻结、构建、195 项实际回归和三个真实 Runtime 保管分支；普通周期仍失败，未发布、采用或标记全资格。

冻结 297 文件，集合 `72a58070445c96da73590a79dcff0c3b724c38f66f0dd2601c699e0ad6a7409b`。[实际发布构建与 195 项回归](operations/evidence/regional-native-bft-role-query-index-checks-20261003.json)通过，新增十项索引检查；Native/Core 精确相同，165 项原生与严格检查明确复用。[三个新目录的真实 Runtime 保管分支](operations/evidence/regional-native-bft-role-query-index-runtime-custody-20261003.json)也通过，没有绕过原生签署或另存 head/outbox 顺序。[同机辅助源码评审](operations/evidence/regional-native-bft-role-query-index-local-review-20261003.json)钉住确切字节、九项纯内存边界检查，没有开节点、读私有 fixture 或获得独立运营/安全资格。

[全新普通三时代付款](operations/evidence/regional-native-bft-role-query-index-payment-campaign-20261003.json)运行 1,608.510 秒，第三时代签署前高度关卡在原 600 秒内以 583.767 秒通过，随后第三笔在实际高度 11 签署；共 20 次普通启动观察通过，最长 57.889 秒。最后原 600 秒入账/成熟关卡到期而失败，源/全部现场保留、所有归属进程停止、控制器共识权威调用为零；成功后的全部历史终局冷验收与全故障配置未运行。局部加速和本次跨过关卡不证明唯一因果；节点身份/包排序与执行节奏不同，未做配对整轮对照。

[停止后的原生/运输只读观察](operations/evidence/regional-native-bft-role-query-index-failed-cold-observations-20261003.json)与[活动状态容量统计](operations/evidence/regional-native-bft-role-query-index-active-capacity-20261003.json)把原生账本、Runtime 留存和运输存储分别保留：五份完整原生前缀均为高度 11/时代 2，发行 300=可流通 300、无出口/导入；前两笔纳入且预留零，第三笔仍为 SIGNED_PENDING_INCLUSION、预留 20。全部 2,992 份运输归档认证、未索引文件零；当前父块 55 份信封完整认证，尚非全部历史信封终局冷验收。11 份投票/8 份批准另存 head 相符，全部私有字节/权限/属主/链接数保持；未续跑、补签或释放付款。此次明确的 `durable state capacity reached` 来自中继原 64-MiB 原子状态上限，BFT 状态约 6.07–6.82 MB，未达到其 32 MiB。载体 1/2/3 的保留 mesh-state 分别为 66,978,596 / 67,012,360 / 66,888,202 字节，不能通过提高上限改判成功。

载体 1/2/3 活动包分别为 120/131/139，其中未收据包 120/131/136；仅载体 3 有三份完成但仍活动的记录。其确切 frame 字符串累计约 65.01/64.74/64.78 MB，去掉重复后的不同字符串约 26.33/35.12/26.87 MB，重复部分约 38.68/29.62/37.92 MB。容量统计只检查字节/结构，不自行授予原生认证；原始所有私有字节/权限/属主/链接数不变。下一候选需以显式新私有格式共享活动包的完整确切帧，逐包保留原包/路由/hop/摘要与原样展开认证；仍以组合元数据/不同帧计入原 64 MiB，保持 256 活动包、全部未收据证据和原归档/网络/批次上限。不得用完成归档规则删除未获收据 transit、把摘要当权威、迁移旧状态/价值或把本次失败当成通过。该停止现场对应的共享活动状态尚未实现；随后候选进展见本页新段，原失败不改判。

## 2026-10-03 当前阶段有界推进候选：185 项回归和真实保管分支通过，完整付款仍失败

[新随机无价值创世、两次交接至高度 10 的原生顺序检查](operations/evidence/regional-native-bft-post-role-ordering-20261003.json)实际执行 242 次 CLI（34.145 秒）：同轮迟到完整 Prepare QC 可提交；先 Timeout 再首次旧 Commit 必须拒绝，原签名日志/另存 head/残留不变；recover-only 不能首次签名，合法未来 Prepare 可跳轮。它没有普通节点或运输运行，不是旧失败现场复现或独立运营资格。

[原代码确切 tick 的真实原生签署观察](operations/evidence/regional-native-bft-tick-phase-gap-20261003.json)另执行 13 次 CLI：自身尚未 Prepare、完整三票 QC 已在时，第一 tick 只 Prepare，下一 tick 才 Commit，首份返回观察仍为签署前状态。合成分支还显示当前 Prepare 后同 tick 可直接跳未来轮，从而失去旧轮首次 Commit 资格；不能据此断定全部失败现场时间路径。

新的最小调度在自身 Prepare 后重新读取原生签名者状态，核对确切当前 context/round/准备值和未提交，并仅在已有完整 QC 时同 tick 原生 Commit。每 tick 至多两次正常原生签署，各自保留原 pending/head/outbox 持久化顺序；进展后将未来轮准备留到下一 tick，重新报告原生状态。原生锁、完整三份不同签名、封轮后首次旧 Commit 拒绝、无钥迟到证书安装、容量及原 20 秒基准计时/600 秒高度关卡保持。九项请求顺序分支通过，覆盖两票不足、延迟 QC、合法未来/超时、状态漂移、无钥、完整旧证书及同值不同完整证明。

[确切候选 AST 加真实原生签署](operations/evidence/regional-native-bft-bounded-phase-native-check-20261003.json)在同一个新随机 fixture 正常推进至轮次 4，没有回滚 head；存在合法未来轮次 5 和三份其他签名的完整 QC 时，一次 tick 实际 Prepare/Commit，日志恰新增两条、当前另存 head 匹配、全部此前投票/批准/head 原库存不变。36 次 CLI 耗时 13.082 秒，签署请求由真实原生检查；其 carriage/broadcast/outbox 是合成适配，尚未运行完整 Runtime 启动、最终高度 11、普通付款/成熟或全故障配置。当前源字节与该确切候选一致；随后完成新冻结、构建和下述全新私有目录验收，没有改判上述合成适配的范围。

冻结 294 文件，集合 `789d1db451389769125f3d46525080e5c171970fadbbd9f6ccd0e7aa56de396d`；Native/Core 精确不变。[发布构建和 185 项实际回归](operations/evidence/regional-native-bft-role-bounded-phase-checks-20261003.json)通过，新增九项调度分支；原生 165 项和严格检查明确复用而非重跑。[全新普通三时代付款](operations/evidence/regional-native-bft-role-bounded-phase-payment-campaign-20261003.json)仍失败，运行 791.860 秒：原 600 秒第三时代签署前关卡到期，五载体高度 10/时代 2，第三钱包和首次签署不存在。15 次普通启动观察通过，最长 11.712 秒；控制器共识权威调用为零，所有归属进程已停止。成功后的全部历史终局冷验收未运行，全故障配置也未运行；未发布或采用本候选。

[停止后只读观察](operations/evidence/regional-native-bft-role-bounded-phase-failed-cold-observations-20261003.json)完整原生重放五个前缀、核对 11 份投票与 8 份批准日志的另存确切 head，前两笔均原生纳入且预留零；完整认证全部 2,518 份运输归档，约 41.838–47.886 MiB，未索引文件为零。另完整认证当前父块的 79 份信封，尚非全部历史信封：轮次 2 的三份 Prepare 已存在于载体 1/3/4，载体 0/2 仅两份；载体 3/4 已实际提交。载体 2 已 Timeout 到轮次 3，载体 0/3/4 仍在轮次 2。所有私有字节/权限/属主/链接数保持，未恢复签名、续跑或提高容量。

[三份确切原生 Prepare 的运输取证](operations/evidence/regional-native-bft-role-bounded-phase-failed-prepare-carriage-20261003.json)确认源载体为 0/3/4。载体 4 的 Prepare 尚未到达载体 0；其目的载体 2 的包已有原样完整运输和认证目的收件，却未出现在载体 2 共识记录。[目的载体只读原生检查与处理日志](operations/evidence/regional-native-bft-role-bounded-phase-missing-vote-reception-20261003.json)确认该完整信封在载体 2 也通过原生验证；其当前进程日志无该包拒绝记录，也无 contact 观察不可用样本。归档包装当地文件 birthtime 到最后遥测仅 10.493 秒；冷状态有 10 份尚未保留的新目的信封，该包排序第 10。文件时间不是签名的运输时间，停止后不能重构进程内 seen 集合或完整当时选择顺序；这支持继续检查晚到积压和传输/处理节奏，尚不证明唯一根因或普通队列公平性。收件仍不授予共识/价值权利。

[真实完整 Runtime 保管检查](operations/evidence/regional-native-bft-bounded-phase-runtime-custody-reproduction-20261003.json)在三个独立新无价值目录通过：[可复现工具](../tools/check_regional_bft_phase_custody.py)实际执行同轮 Prepare/Commit；在 Commit pending 落盘前注入失败时原生仅一条准备记录，冷开后才正常首次提交；已提交响应的 outbox 保留失败时另存 head/响应保留，冷开不重复签署。各自最终恰两条原生记录、完整本地准备/提交信封、另存 head 相符，pending/outbox 清空，再次冷开不增签。控制器仅搬运诊断准备票，没有运行普通运输、形成三份 Commit/高度 1、完整付款、SIGKILL、掉电或独立保管；不能替代上面的失败完整演练。

[停止后纯查询扫描计时](operations/evidence/regional-native-bft-role-bounded-phase-signed-scans-20261003.json)测量确切 Runtime 的 32 轮证书搜索中的正文筛选：208–212 份保留消息时各载体约 0.520–0.560 秒。没有计入原生 quorum 验证、完整 tick、状态落盘或 TCP，不能把该组件认定为全部晚到原因或据此取消完整验证。下一本地验收应针对新票的排队/传播/普通消费完整节奏，用新目录复现；已签原包、所有历史证据、四 transit/十六 receipt 批次、独立 head 和原时限均保留。

## 2026-10-03 收据独立轮转与严格只读候选：小范围检查通过，普通付款待新冻结验收

新的私有身份/状态显式绑定 `RLD-CONTACT-RECEIPT-SCHEDULER-V1`，每个固定邻居各自保留有界轮转位置。一次发送至多 16 条完整收据；在 TCP 连接或 spool 写入之前先持久化所选批次的推进。其他邻居、普通 tick 或未发布的交换构造不能推进该邻居的收据轮转。旧状态不转换，所有历史收据仍保留，收到所选收据后仍完整重构/认证归档并同步共享载荷和包装；接收 256 上限、四条 transit、Mesh V3/TCP V4、Native/Core 和原容量不变。十项调度回归覆盖 5/15/64/256 收据、四邻居加普通 tick、冷打开、重复失败、推进持久化失败、独立邻居、旧状态拒绝，以及实际字节批次进位、spool 原活动步幅保持和篡改/同步失败不授予托管。

[原批次真实本机 TLS 组件测量](operations/evidence/interstellar-receipt-tls-baseline-profile-20261003.json)在每端 128 份 64-KiB 不透明归档与一份新包下，单次 tick 完整重构 129 份归档、同步 258 个保留文件，耗时 0.824928 秒；[独立轮转批次的新目录测量](operations/evidence/interstellar-receipt-tls-peer-batch-profile-20261003.json)分别为 16/32 和 0.401513 秒，两次均真实获得新包目的地托管与源收据且无 tick 错误。搭建阶段为每包单独选取已认证收据，测量阶段走完整普通固定 TLS 1.3 交换；两次均为新纯运输目录，没有打开失败现场或原生账本/钱包。时间只解释该组件的重复工作量，不能证明高度 10 停滞的唯一原因或普通共识活性。

另以独立 `MeshInspection` 替换新角色周期终局冷验收的普通 Node 构造。它只打开已有只读描述符和锁，从可信新 fixture 创建阶段独立保留的公开锚检查完整状态和全部已索引归档；不读取私有身份、不签名、不创建/修复文件。配置漂移、缺失、损坏、未索引残留明确拒绝并保留。冷验收同时对照原生认证的初始准入与两份时代成员陈述检查每个密钥/载体/当地保管槽；仅摘要一致不能替代成员权威。13 项合成禁止读私钥/写入检查和四项配置/原生成员替换拒绝通过；连同调度与恶意对端回归，实际 26 项专项检查通过。第一份 291 文件候选集合 `b3693b0d24cd485cd8e2b2f36da164c31ac3b7e9ed33e33951d8552d16cc61ec` 已实际构建；在付款演练前发现草稿多次推进 spool 活动游标，须恢复原每完整 tick 一次的步幅，其源与构建/检查日志保持。新修改另行冻结，不执行该草稿付款演练；附加二次交接后普通 Service 接收、新签票/已签未入账提交与同正文变化证明回归仍待实际执行，不把辅助准备阶段计为通过。修正版另行冻结 292 文件，集合 `2bbdf13eaa3280c4b23b35fb560e3af7a251ff6435af48e875673af0c8ca0e8d`。[新冻结构建与 176 项实际进程检查](operations/evidence/regional-native-bft-role-receipt-scheduler-retry1-checks-20261003.json)通过，包含 128 项传输、39 项角色伴随、5 项观察器和 4 项冷成员映射检查；原生 165 项和严格检查沿用确切相同 Native/Core，明确未重跑。新增二次交接接收用例首次实际通过：显式控制器构造 fixture 后从冷 Service 普通接收路径处理新 EpochSigned、实际已签未入账 EpochSubmission、同正文但新增完整认证依赖的信封和坏证明，保持原正文/当地标记、另存 caller heads 及原生账本不变。该小用例的交接准备不是普通自动交接演练，也没有付款入账/成熟资格。[全新三时代普通付款](operations/evidence/regional-native-bft-role-receipt-scheduler-retry1-payment-campaign-20261003.json)失败，实际 771.403 秒；原 600 秒的第三时代签署前关卡到期，五节点在高度 10/时代 2，第三钱包和首次签名不存在。15 次普通启动观察通过，最长 10.933 秒；零号/第一代签署前高度关卡分别为 38.319/62.793 秒，两次交接原生激活。控制器共识权威调用为零，所有归属进程已停止；成功后的全周期冷验收和新全故障配置均未运行。所有旧现场保持，独立/跨设备/物理与 I1–I12 仍开放。

[停止后的失败范围冷核验](operations/evidence/regional-native-bft-role-receipt-scheduler-retry1-failed-cold-observations-20261003.json)完整重放五个高度 10/时代 2 原生前缀，核对 11 投票者和八份批准的另存 head；前两钱包原生入账且预留零，第三钱包不存在。新的严格只读入口完整认证 2,506 份运输归档，五节点归档约 40.7–43.4 MiB，全部已索引且没有未索引残留；另完整原生认证 140 份当前父块信封。所有私有文件字节/属主/权限/链接数保持，文件摘要核对不使用私钥签名；这不是全部历史原生信封、最终高度 14 或第三笔收款成熟的成功验收。

当前轮次 0/2 提案已原生保留在全部五个载体，各有三份完整认证 Prepare，但只有一份 Commit；轮次 4 的提案和两份 Prepare 只在载体 3/4。[确切提案运输核验](operations/evidence/regional-native-bft-role-receipt-scheduler-retry1-failed-proposal-carriage-20261003.json)认证载体 3 的轮次 4 原提案：载体 4 已取得目的地收据；载体 2 只托管了发往已退出投票的载体 1 的一份中转，没有其自身目的地包，载体 0/1 亦没有原提案。早轮提案送达较上一失败改善，但 Native 提交阈值仍未形成，后轮还有运输缺口。不能由此断定唯一原因、放松签名/阈值/期限或改判原失败；下一本地工作检查当前 Prepare-QC 可用后的阶段推进延迟和活动包按邻居的轮转公平性。旧源、日志、失败报告和全部私有现场保持，本候选未发布或采用，完整目标继续进行。

## 2026-10-03 共享归档载荷候选：存储检查通过，普通付款在高度 10 失败

针对上一失败现场约 167 MiB 的确切重复载荷，实现 `RLD-CONTACT-ARCHIVE-SHARED-FRAME-V1` 私有存储包装。存储/网络/节点作用域内的完整确切 canonical frame 字符串只保存一份；每份原包、签名、路由、跳链和收据保持各自包装及原完整字节摘要/长度。读取时先检查包装和共享对象的完整确切字节与作用域，在构造前限制展开长度，再完整认证重构后的原包与收据；摘要和存储引用不替代原生价值认证。Mesh V3 / TCP V4、线上完整签名正文、Native/Core 与所有原上限保持。

一对对象在写入前共同计入原 4,096 文件/256 MiB 容量；所有残留/孤儿都计入，原包/状态仍至多 64 MiB。共享载荷先持久化，包装随后持久化，最后才发布索引并移出活动队列；重复托管在重新认证后再次同步载荷、包装和目录。32 完成高水位、16 条归档批次、256 活动消息、512 transit 见证及 4 MiB 不可变索引见证保持。旧私有身份和状态明确缺少新存储绑定时拒绝，不转换，不重新签署历史包，不迁移账本、余额或签名保管。

实际 101 项传输检查通过，其中新增 11 项共享存储回归覆盖同载荷多原包的确切重构、热索引下损坏/缺失拒绝、自有签名的恶意展开承诺拒绝、外来共享对象拒绝、存储摘要全部匹配仍不能绕过原包签名、展开前容量拒绝、双对象共同准入、包装写入失败保留载荷孤儿和原活动状态、旧私有身份/状态拒绝，以及重复托管同步顺序/失败拒绝。原索引写入失败回归改为核对两个完整对象残留并保持原字节。注入写入/fsync 失败不是实际进程 SIGKILL 或掉电验收。

运行候选已冻结 285 文件，集合 `4b4a1ab23a96aafdff2a146b100e9a9e0c90070939a0a7efb52e6ff1cf34d7ff`；[从冻结路径重新构建及实际 144 项检查](operations/evidence/regional-native-bft-role-shared-frame-checks-20261003.json)通过，包含 101 项传输、38 项角色伴随和 5 项观察器检查。原生 165 项与严格检查明确沿用完全相同的 Native/Core 源而非重跑。构建开启溢出检查和调试断言，使用全新私有根目录、身份、TLS 与固定邻居 pins，没有读取或迁移旧失败账本/钱包/签名者。

[单独存储边界验证](operations/evidence/interstellar-shared-frame-process-boundaries-20261003.json)实际执行三次 OS SIGKILL：载荷已持久化、包装已持久化、索引已持久化。新进程冷打开分别保留 1/2/2 个原对象；未发布索引时由完整认证的原活动包/收据完成纯运输归档恢复，孤儿不授予采用资格。所有原对象字节与 inode 不变，随后完整原包/收据冷认证通过，付款资格仍为 false。这使用单个不透明无价值运输包、诊断高水位 1、同主机选定存储边界，没有原生账本/钱包、socket 或完整普通节点，不替代全故障、Native 签名保管或掉电资格。第一次诊断因 fixture 源链与目的链相同而在归档前拒绝，旧失败源码/日志/私有目录及[失败报告](operations/evidence/interstellar-shared-frame-process-boundaries-initial-failed-20261003.json)保持；改正后另用新目录验证，没有改判或续用旧目录。

额外附带诊断工具的发布候选冻结 286 文件，集合 `fb22484bff7887854cabe38e258015e89d37a7bdbe4069b6c43f73d4cbdc5c6b`，只比运行源增加该确切验证器；运行源与二进制不变。[全新普通付款周期](operations/evidence/regional-native-bft-role-shared-frame-payment-campaign-20261003.json)已失败，实际运行 783.056 秒；第三笔签署前的原 600 秒高度关卡到期，五载体停在高度 10/时代 2。15 次启动观察通过，最长 9.442 秒；前两笔实际付款已纳入且预留为零，第三笔没有钱包或首次签署。两次交接已原生激活，没有归档容量拒绝；归属进程已停止，控制器共识权威调用为零，完整成功后的停机冷验收没有运行。上一失败源、全部报告、第三笔预留与每个旧残留保持；本候选尚未发布、采用或取得完整付款/故障通过，独立保管、长期历史、物理连接和 I1–I12 仍开放。

[停止后原生观察](operations/evidence/regional-native-bft-role-shared-frame-failed-cold-observations-20261003.json)完整重放五个高度 10 前缀并核对所有独立投票/批准 head，保留付款和失败结论不变；这只完整认证当前父块相关信封，不是全部历史终局冷验收。[选定提案运输观察](operations/evidence/regional-native-bft-role-shared-frame-failed-proposal-carriage-20261003.json)确认载体 4 的高度 11/轮次 2 完整提案通过原生检查，四个目的地包仍只访问过源载体，没有目的地收据。该缺口在选定包首次运输送达之前；[停止组件计时](operations/evidence/regional-native-bft-role-shared-frame-stopped-component-profile-20261003.json)没有测完整 TCP/tick，不能确定唯一停滞原因。所有旧私有文件保持不变，没有补签、重启或续跑。

失败运行后发现归档临时硬链接与最终名字共存的瞬时峰值未预留。新的本地修改在共同准入时另预留一个目录项和最大缺失对象字节，删除临时名字后同步目录，所有残留继续计入原界限。15 项共享归档检查通过，其中四项新增检查覆盖最终容量恰好容纳两个对象时提前拒绝、真实硬链接峰值计数、既有孤儿的字节预留及包装硬链接后实际 OS SIGKILL。最后一项冷打开保留三个原名字/字节/inode，依靠原完整活动证据归档恢复且完整认证；运输恢复不授予价值。本修改尚未另行冻结或完成新的普通付款周期，不属于上述失败运行源。

## 2026-10-02 启动观察候选：二十次启动通过，第三笔付款因容量与进展关卡失败

新候选将旧 PID/缺失状态保持为未知，超时诊断保留真正的观察期限错误；缺失高度不补零。冷启动观察明确单列为 300 秒地面窗口，原 600 秒高度关卡、20 秒轮次、原生完整认证及全部容量保持。冻结 284 文件，集合 `b4efe9902ce03b509295e9885c21b226c807c8f6ec6986c92722f17a9ca1ba9a`。只改变观察器、五项观察回归和冻结时状态文档；[实际发布构建与 44 项进程检查](operations/evidence/regional-native-bft-role-observation-checks-20261002.json)通过。Native/Core 精确不变，165 项原生、严格检查及 89 项传输检查明确复用而非重跑。发布构建开启溢出检查和调试断言；运行源与旧失败源保持。

[全新普通付款周期](operations/evidence/regional-native-bft-role-observation-payment-campaign-20261002.json)仍为失败，完整运行耗时 1,338.810 秒。五载体共 20 次普通启动观察通过，最长 39.157 秒，说明本轮实际完整启动观察确实超过旧 30 秒窗口；不能据此确定此前失败的唯一原因。两次交接已原生激活，三笔钱包付款分别在时代 0/1/2 的高度 3/7/11 实际签署。最后原 600 秒付款入账与成熟关卡到期，节点仍在高度 11，并观察到两个中继的 `archive capacity reached; retain active evidence`。没有提高容量、降低阈值、删除归档、释放输入、续跑或改判旧失败。控制器共识签名/证明安装为零，归属进程干净停止；未运行要求完整成功的终局冷验收。

[停止后只读核验及归档剖析](operations/evidence/regional-native-bft-role-observation-failed-cold-profile-20261002.json)独立重放五份原生创世前缀，均为高度 11/时代 2、发行 300=可流通 300、无出口或导入；三个钱包均绑定另存确切 head，前两笔已纳入且预留零，第三笔待纳入、预留 20。全部私有字节、权限、属主和链接数保持不变。只读完整认证容量受限载体的 973 份已索引归档；实际保留 974 文件、267,949,194 字节，未索引残留也计入原 4,096 文件/256 MiB 容量且不授予进展。已认证归档中的确切 canonical frame 字符串总计 264,077,302 字节，其中 298 种不同字符串共 88,735,420 字节，重复部分 175,341,882 字节。测量没有修改或共享旧归档，也不是所有载体的全部信封/运输终局冷验收。

下一本地实现需在全新运输目录内验证完整确切载荷的有界共享存储：保留每份原包、签名、路由、收据及原始完整字节承诺，读取时重构并完整认证；全部对象、残留和索引仍计入原容量。共享摘要不授予托管、账本或签名资格；旧私有格式拒绝且不转换，原失败源码、报告、付款及所有残留保持。共享实现、损坏/容量/持久化中断/冷重启，以及随后全新完整付款与故障演练尚未完成。本候选未发布、未被网络采用，I1–I12 与独立/跨设备/物理资格仍开放。

## 2026-10-02 归档索引验证开销：已实现有界见证，第三笔签署后启动观察失败

中继每次打开状态仍验证活动消息、广告、peer inventory 和实际文件清单。增加一个进程内归档索引见证：仅在完整签名、结构和收据验证之后，保留整个确切 canonical 索引字节、存储/网络/节点/版本/验证限制绑定及不可变文件元组；保留编码总量上限 4 MiB。变化、驱逐、限制收紧及新进程重新认证；每次打开仍检查全部文件存在性、大小、容量和活动/归档重叠，每次正文读取或托管确认仍验证完整归档字节与 transit。没有写入持久缓存或改变账本、签名资格及原有归档容量。

冻结运行源码 282 文件，集合 `2af3ea73509a666f40b3889de12ecfbe06e86d757307cc449f12ec9f5268e1fb`；额外重叠回归加入的 283 文件发布候选集合为 `ef718c32ea4b32532f7950419377cd00b1b717008e02fc346b6a25eb60d7b2fc`。冻结 127 项检查通过（89 传输、38 交接/节点），额外热索引活动/归档重叠拒绝回归通过。Native 与 Core 字节和上一修复版完全相同，165 项原生测试及严格检查明确复用，没有重跑或重计。见[冻结检查](operations/evidence/regional-native-bft-role-archive-index-checks-20261002.json)。停止失败现场的只读测量中，691 条归档的重复打开由约 0.50 秒降至约 0.11 秒；见[性能观察](operations/evidence/regional-native-bft-role-archive-index-profile-20261002.json)，该测量不证明普通付款或完整故障通过。

全新私有根目录的[普通付款周期](operations/evidence/regional-native-bft-role-archive-index-payment-campaign-20261002.json)未通过，耗时 508.861 秒：前两笔入账，第三笔在原生高度 11、时代 2 实际签署，但最终阶段首次重启未在原 30 秒窗口发布当前进程观察。超时诊断又因旧 PID 覆盖了真正的观察期限错误。没有达到最终高度 14 或收款成熟，不能计为完整周期通过。停止后[独立原生只读核验](operations/evidence/regional-native-bft-role-archive-index-failed-startup-cold-20261002.json)确认五账本均为高度 11/时代 2、前两钱包已纳入且预留为零、第三钱包仍待纳入并预留 20；全部私有文件不变。没有续跑、补签、释放或迁移失败现场。

只读隔离计时完整认证该载体的 188 份保留信封耗时 11.686 秒，重新打包并认证 21 份保留原生签名响应耗时 6.223 秒；[信封测量](operations/evidence/regional-native-bft-role-cold-start-profile-20261002.json)、[响应测量](operations/evidence/regional-native-bft-role-retained-start-profile-20261002.json)均未重启进程或改变私有文件。这两项不是完整启动计时，也不确定唯一原因。观察器候选现在将旧 PID/缺失状态记录为未知并保留实际期限错误，不虚构高度零；冷启动观察另设明确 300 秒地面窗口，原 600 秒高度关卡、20 秒轮次以及原生全部认证和容量保持。五项观察器回归通过，需另冻源码并从全新目录执行完整付款，再单独停止冷认证。旧失败源码、报告和状态保持原样；候选未发布、未被采用，独立运营、物理连接及 I1–I12 资格仍未完成。

## 2026-10-02 普通节点付款：交接证明变体拒绝已修复，后续中继进展仍未通过

新增五载体普通付款流程，明确配置高度 4、8 两次交接；在原生高度 3、7、11 分别由实际钱包所有者签署三个时代的付款，最终等待高度 14 的收款成熟。钱包 caller-head 在原生签署前记录完整待审目的，签署后先持久保存新 head，再排队提交；排队不扣款。控制器只管理测试钱包和进程，不构造共识投票、交接批准或安装证明。

首次冻结付款演练**未通过完整流程**：五份原生账本冷核验均停在高度 8，已激活第二次交接；前两笔付款原生收录且预留清零，第三笔没有签署，`300 = 300 + 0` 守恒。载体 0、3 的新投票日志拒绝创建：其完整就绪证明与实际激活证明绑定同一完整时代声明、选择区块、关闭声明和头链，但关闭证书采用不同有效签名组合。停止了重复拒绝的演练，保留原源码、报告、日志、所有私有状态和失败结论；没有续跑或迁移。证据见[失败原因冷核验](operations/evidence/regional-native-bft-role-payment-failed-witness-analysis-20261002.json)和[保留付款观察](operations/evidence/regional-native-bft-role-payment-failed-cold-observations-20261002.json)。

原生修复分别完整认证就绪与激活证明，再比较完整时代声明；保留两个确切证明，不要求有效关闭证书字节相同，不以 hash/声明匹配替代认证。新原生回归验证四签名与三签名关闭组合可交接、篡改任一完整证明仍拒绝、旧投票日志不变及完整创世重放。冻结源码上的严格检查、165 项原生测试和 38 项进程测试全部通过；全新无价值付款复现已经完成观察，未通过完整流程。验证报告见[修复版冻结检查](operations/evidence/regional-native-bft-role-witness-checks-20261002.json)。新原生实现 `472fc8bfcf6e2ccb969c3f795072140cd179bb6f3adbad4df016e0083cb3437f`，282 文件源码集合 `243b2d1064703820f9114c032f3f5d9f9d47640fe07ddd5b45225a155ad8f879`；Core 仍为 `8f507b0eda0dc6d5a5ce6469fd8cfda75f41d4eec6fad05e85271ef5fb3a5eae`。候选未发布、未被采用，完整付款、完整故障、独立运营和实际星际资格尚未完成。

修复版使用全新币种 `b1556dd39617c7caf41112992a17c5d38b6d776d2f502a0ad0130dc95d115644` 和私有根目录，未迁移旧状态。它已创建全部配置的新投票日志、完成两次交接并在第二时代继续普通出块，但等待第三笔付款签署高度的 600 秒观察到期，整轮耗时 804.057 秒，**仍是失败演练**。独立停机核验确认五份原生账本均为高度 9、时代 2、`300 = 300 + 0`，11 份配置投票日志及 8 份就绪日志的独立 head 均一致；前两笔付款原生收录、预留清零，第三笔没有签署。此处只读核验并未逐一冷认证全部保留信封和传输归档，不能称为完整冷验收或故障通过。见[失败付款报告](operations/evidence/regional-native-bft-role-witness-payment-campaign-20261002.json)、[停机保管核验及原生耗时](operations/evidence/regional-native-bft-role-witness-failed-cold-profile-20261002.json)和[调度扫描耗时](operations/evidence/regional-native-bft-role-witness-scheduler-profile-20261002.json)。完整源码、失败报告、日志与私有状态均保留；下一阶段针对实际中继/验证开销优化，仍须全新普通付款及完整故障复现，不延长失败演练或补写通过。

## 2026-10-02 本地普通节点：两次分角色交接及独立冷验收通过

新显式 `RLD-REGIONAL-BFT-NODE-JOINT-ROLES-V1` 配置接入普通启动：每个时代的本地保管槽可为空，加入、继续和退出载体分别处理；配置一至十六次递增高度的四成员交接，以及完整钉住的密钥/载体映射。继续密钥保留原载体和旧日志；批准和投票各有独立 caller-head、pending/outbox 与初始化记录，所有调用方目录位于全部原生/运行目录之外。只加入和退出载体不伪造当前签名身份，向明确配置的载体中继证据不授予签名资格；旧 V1 配置和不重叠规则保持。

原生预览完整空保管日志及确切创建观察、head 和批准目的。节点先持久记录初始化意图，再创建原生日志；恢复接口只可 fsync/提升已保留的确切未批准或空投票日志，不能创建缺失日志、重置已用日志或首次签名。真实接口检查覆盖只加入载体、初始化写入失败、签名响应丢失、修改恢复目的、创建响应丢失后移除私钥的精确恢复。额外回归修复已激活关闭检查点被误当成下次待交接方案的问题：只有当前实际原生激活证明的完整陈述相等才返回普通运行。初始冻结源码和检查结果保留；不改写失败或历史范围。

[首份 280 文件冻结检查](operations/evidence/regional-native-bft-role-lifecycle-checks-20261002.json)实际执行 **164 项原生、37 项进程检查**、严格检查及开启溢出检查/调试断言的发布构建。[最终运行冻结源码检查](operations/evidence/regional-native-bft-role-lifecycle-active-closing-checks-20261002.json)仅改动新角色 Python 调度和新增对应回归；重新构建以固定普通启动的确切 Python 源路径，并实际通过 **38 项进程检查**。完整 Native/Core 字节不变，164 项原生和严格检查明确沿用，不重复计为新的原生执行。

[普通启动演练](operations/evidence/regional-native-bft-role-lifecycle-campaign-20261002.json)五个钉住 TLS 的同主机载体在 88.699 秒完成两次实际原生时代激活，到达高度 4。零号载体没有旧投票槽，四号载体仅加入第二个新集合；一号载体退出后继续中继，二/三号连续参与。初始领导者没有签名槽，换轮由正常节点完成。控制器共识票、法定人数、旧/新批准、时代激活及检查点安装调用均为零。全部归属进程正常退出。

[单独停止冷验收](operations/evidence/regional-native-bft-role-lifecycle-cold-20261002.json)从创世验证五份原生账本、11 份投票保管日志及其另存 head，逐份验证八份新集合批准日志的目的和独立 head；旧日志保留确切下一时代封锁。完整原生认证 309 份保留信封，冷认证 784 份运输档案，五副本一致、300=300+0，所有私有文件字节/属主/权限/链接数保持。检查没有首次签名、初始化恢复、安装证据或运行节点启动。

[最终 281 文件源码范围](operations/evidence/regional-native-bft-role-lifecycle-release-scope-20261002.json)只向实际运行源补入独立冷验证器；全部运行、Native/Core 字节一致。最终集合 `71bcb80cbdc2c7862125bf0ce2cd65c0d91bfeb1262a0cffc129e5eee85347e6`，运行集合 `d5048e0bca0039488b4995b484c7b2549d3d1d6dc5952962942c21784c250231`，原生实现 `d1f519335dff8da5f08c62f314ca3d88395b7a750784afcc830e399fdaf840aa`，新无价值 fixture 货币 `7f97164d5d7afc79fb02ff4c301c64775d80673df664ed142e70e45520929a2b`。不迁移修订 33 或前轮任何状态、余额、密钥和调用方 head。Core 源仍精确相同；本地候选尚未发布。

这次普通演练只含无价值区块奖励和交接，没有普通节点所有者钱包付款、跨区付款、分区或新全故障配置。原生用例中的实际付款/出口及模拟持久化边界不替代这些资格。下一步以新目录完成交接前后钱包付款、缺失当前领导者/批准、断联、重启、收款成熟及暂停签名，并逐份停止冷验证。真实进程中断、掉电、跨设备/独立运营、任意成员/权重、长期历史/密码、物理路线与 I1–I12 仍开放；目标继续进行。下方原生初轮和历史检查点按各自范围保留。

## 2026-10-02 本地原生候选：分角色的重叠成员交接

[十二项实现契约](research/REGIONAL_BFT_ROLE_SCOPED_HANDOFF_REQUIREMENTS.md)已推进为独立的新原生候选。显式签署的 `RLD-REGIONAL-BFT-JOINT-ROLES-FIXTURE-V1` 将 Old/New 批准绑定不同完整签名消息；旧 V1 准入保留不重叠成员和原签名含义。新集合批准使用独立、绑定确切交接目的的原生日志。继续成员创建新投票目录必须出示实际锁住的原旧日志、确切另存 head、该方案的持久旧封锁，以及独立新批准和 head；完整原生保管来源固定进新日志，冷验证重新认证，不能用摘要重置保管。加入成员须原生验证无旧成员身份；未参与当地封锁的继续成员不能创建新日志，也不能用旧日志首次签署新时代消息。所有旧证据和容量界限保留；原生时代上限既有 16，未提高。

[277 文件冻结源码全套检查](operations/evidence/regional-native-bft-joint-roles-checks-20261002.json)实际完成 **162 项原生检查、32 项进程检查**、严格检查，以及开启溢出检查和调试断言的发布构建。新增四个原生用例覆盖 0/1/2/3 个继续成员、各两次连续交接、实际所有者付款和跨区出口、完整创世重放、旧/新签名替换拒绝、历史退出密钥再加入拒绝、无当地封锁的旧日志在读私钥前拒绝，以及保留原响应的中断续写。中断续写用例构造确切持久化边界文件，不计为真实进程 SIGKILL 或掉电验证。

[最终源码和独立保留旧 head 的实际 CLI 样例](operations/evidence/regional-native-bft-joint-roles-retained-head-checks-20261002.json)仅补充 Python 测试中的独立旧 head 文件，并重新运行该单项接口检查。初轮其余 31 项进程源码与完整 Native/Core 精确不变，162 项原生、严格检查和构建未重复计为新执行；本检查点合计 33 次进程测试执行，最终源码的不同检查仍为 32 项。接口样例在新集合共识后核对原旧日志及另存 head 的字节、属主、权限和链接数保持。

最终源码集合 `e0cd43b2cfee6d55c4e64acede0caf42f925d63b8868f7324a2623d7ab977895`，原生实现 `235cd19fe379827fcb2a4dbf7f55ea1221d2b85ac1e975f26753118194fd608c`。所有用例均新签署无价值 fixture 创世；接口 fixture 货币为 `c6963996afaafcfa11438cda3bd1c79cffcd3eec71e25680fb8b7468d9408143`，不迁移任何历史或旧候选状态/价值/保管。Core 源仍精确沿用修订 33。此前 [V1 原生角色边界 19 项检查](operations/evidence/regional-native-bft-role-boundary-regressions-20261002.json)仅保留为修改前历史证据。

本候选仍只在本地，尚未发布或被网络采用。普通 Python 节点仍使用公开 V1 不重叠交接流程；新角色的自动启动、加入/继续/退出载体配置、连续交接的独立 caller-head/pending 初始化恢复、真实进程中断、全故障演练及单独停止冷验收尚待实现。原生单测和控制器携带的 CLI 共识样例不替代这些验收；四成员之外、历史密钥重新加入、独立运营/跨设备保管、长期历史/密码、物理路线及 I1–I12 仍开放，整体目标继续推进。

## 2026-10-02 接收调度候选：普通闭环、完整故障演练及各自冷核验通过

[修订 32 停止现场的运输取证](operations/evidence/regional-native-bft-active-proof-failed-carriage-20261002.json)认证三份当前提交票及目的地收据：两个在线副本的另一份缺失提交票已经到达运输层，却未进原生共识处理；每份队列另有 98–104 条原周期已完整保留的信封。第三副本的两份缺票尚无目的地收据；不能把接收调度当作唯一原因，也不能把运输收据计作确认。

新接收候选在原四条批次内，给尚未完整保留的 BFT 信封及历史/普通运输各保留两条公平轮转名额；某类不足时由另一类使用空余。不按正文去重或跳过原生认证，改变证明的同一正文仍按新完整信封处理，历史记录不删除。实际原生回归构造十二份历史信封、一份新签名和一份同正文篡改证明，首批完整认证四份、新签名保留且篡改拒绝，随后所有历史信封完成处理，账本/另存头未变。Native/Core 源不变；冻结前全套进程检查、新目录普通周期、冷验收及完整新故障配置尚待执行，后续实际结果见下一段，不继承修订 32 的失败为通过。

该候选已冻结 273 文件，集合 `435065e420fdeae78ae8e8280ded4d61f17da693e8144c1630752210354caa22`，[源码范围审阅](operations/evidence/regional-native-bft-fair-receive-source-review-20261002.json)只变更接收调度、实际回归及冻结时状态文档。[重新构建及实际 86 项进程检查](operations/evidence/regional-native-bft-fair-receive-checks-20261002.json)已通过；158 项原生和严格检查沿用修订 32 的完全相同 Native/Core 源，不计作本轮重跑。新十二节点普通周期已在新私有目录启动，尚待终局、停机冷核验及随后完整新故障配置。冻结源码及此前失败现场均保持，后续本地状态文档更新不属于运行源字节。

该源码的新[普通周期](operations/evidence/regional-native-bft-fair-receive-cycle-20261002.json)已终止并保留为失败，归属进程清理通过。控制器在交接后错误要求高度 4 的快照恰好一份；[停止后原生核查](operations/evidence/regional-native-bft-fair-receive-selection-diagnostic-20261002.json)确认四个副本实际均已选定原方案、激活新时代并至高度 7，其中两份保留两条相同关闭检查点陈述，另两份一条，均带原生认证的 Reconfigure。故障发生在观察条件，跨区付款尚未进行；不能计完整周期通过。

控制器已改为核对当前原生活跃证明、精确有序新集合和原生按关闭检查点查询的确切方案，不计算 Python 检查点身份、不删重复证据。真实原生回归确认精确方案可观察，错误货币/地区/集合/高度/时代分别拒绝；[原失败四副本的独立只读回归](operations/evidence/regional-native-bft-fair-receive-selection-regression-20261002.json)通过并保持所有私有文件不变，没有重启或续跑翻案。新控制器源码需另行冻结并从新目录完整重跑，Native/Core 及原界限不变。

修正控制器的 273 文件已另行冻结为 `55b923889a476710ef5927482e0dc1efc363c4e0b36ec3cd3fe6f5ad634ab2c9`，[范围审阅](operations/evidence/regional-native-bft-fair-receive-selection-source-review-20261002.json)只新增观察器及真实原生回归，普通节点运行源与失败的接收候选完全一致。[实际 87 项进程检查](operations/evidence/regional-native-bft-fair-receive-selection-checks-20261002.json)通过；Native/Core 源和二进制与前次构建精确相同，构建、158 项原生及严格检查沿用而非本轮重跑。新十二节点[普通支付闭环](operations/evidence/regional-native-bft-fair-receive-selection-cycle-20261002.json)通过，四副本终局高度一致为地球 11、比邻星 4、仙女座 4；地球全停期间远端继续导入、成熟、再出口及新返程，返程原输出 86 在高度 9 导入、11 成熟可花。控制器生成共识票、交接批准/激活、携带付款证明及安装检查点均为零。停止后[单独冷核验](operations/evidence/regional-native-bft-fair-receive-selection-cycle-cold-20261002.json)完成十二账本、十二原输出、四份交接保管及 2,114 档案认证，全部私有文件保持不变且归属进程清理通过。完整新故障配置已从该停止周期另建新私有目录启动；当前运行观察已通过三名新投票者在领导者缺席后的高度 13 确认，以及两处隔离远端继续当地确认。离线节点已通过固定 TLS 邻居追赶检查；恢复固定链路后原笔新出口的唯一导入和成熟、暂停签名后的完整证书收敛关卡均已通过。[新完整故障演练正式报告](operations/evidence/regional-native-bft-fair-receive-selection-fault-fresh-20261002.json)已通过，耗时 1,282.25 秒，四副本终局高度一致为地球 16、比邻星 21、仙女座 22；缺席领导者关卡 470.55 秒、恢复后的付款导入及成熟观察 451.621 秒，均在原 600 秒界限内。停止后十二份原生前缀保持 300=300+0、四份唯一出口对应四份导入，无未解决出口。归属进程清理和原停止周期不变检查通过；[成功后的单独冷核验](operations/evidence/regional-native-bft-fair-receive-selection-fault-cold-20261002.json)已通过：十二份原生账本、四份原笔收款、四份交接保管和 6,144 档案认证，四副本各地一致、原笔 9 在 19 导入且 21 成熟可花，全部私有文件保持不变。正式报告的有限同主机范围不等于持续活性或独立资格，不能将阶段观察计作完整通过。原失败周期不重启，不迁移值，不改为通过；原 600 秒关卡和全部容量界限保持。

[修订 33 的精确源码、复现工具和终局证据](https://github.com/RunlaiDeng/rldcoin-genesis/tree/12f96085e68fddfe8a04c1b15708c4867ea18b65/research/2026-10-02/regional-native-bft-fair-receive-v33)已公开；[74 个远端文件](operations/evidence/regional-native-bft-fair-receive-v33-publication-verification-20261002.json)逐字节一致，main 指向该提交，公开工作区干净。两份 273 文件归档和完整包清单均核验，保留旧失败结论，生成的私有钥匙、账本、钱包、签名者/调用者头和运输/TLS 状态不公开。官网与论坛未改动。长期历史/密码、任意成员重配置、跨设备/掉电、独立运营/保管、安全及物理路线资格继续开放，I1–I12 与整体目标未完成。

## 2026-10-02 当前候选：原生活跃交接证明观察

273 文件冻结源码集合 `0be0a01f00b6b04c11a7cb4b3012c3b8a2d1857904f1ac921ade72890d49e049`，新原生实现 `dd1a55df717c0b31cc736cbe6b3aa94efbf31ee9e8395e4e875727901af217d2`，使用新签署无价值 fixture 创世，不迁移任何旧状态、余额或保管。实际完成新构建、158 项原生、85 项进程、格式及严格检查；[检查记录](operations/evidence/regional-native-bft-active-proof-frozen-checks-20261002.json)。

原生仅报告按完整本地事件重放实际激活的精确证明，已知证据不能代替激活。普通接收仍先完整原生验证每份信封、同步新认证依赖，再按完整规范字节比对当前活跃证明，避免重复安装；不同有效证明仍走原生安装，篡改后续信封拒绝且不改账本/调用者头。原边界不提高，签名证据不删减。

[新十二节点往返](operations/evidence/regional-native-bft-active-proof-frozen-cycle-20261002.json)已完成，地球全停时远端继续导入、成熟、转出和返回；终局四副本一致 11/4/4，净额 96/91 的原输出已续转，返回原输出 86 在 9 导入、11 成熟。控制器共识票、交接批准/激活、携带付款证明及安装检查点为零，进程清理通过。[单独冷核验](operations/evidence/regional-native-bft-active-proof-frozen-cold-20261002.json)认证十二账本/十二原输出/四份交接保管、968 条完整 BFT 信封和 2,107 档案，私有字节/权限/属主/链接保持不变。各高度关卡均未超原 600 秒；这不构成持续活性或吞吐基准。

[十二份停止后原生活跃证明观察](operations/evidence/regional-native-bft-active-proof-cold-observation-20261002.json)通过：地球四份返回精确已安装证明，另两地区八份初始时代返回空值，私有文件保持不变，零号新投票目录没有创建。

该新源码的[有限完整故障演练](operations/evidence/regional-native-bft-active-proof-fault-fresh-20261002.json)已从停止且冷核验后的周期另建私有目录执行，**未通过**：原 600 秒观察界限内，三名新投票者未完成缺席主节点后的高度 13 确认，实际停在高度 12、轮次 2。总运行及失败取证清理耗时 763.285 秒；停止后十二份兼容原生前缀高度为地球 11/12/12/12、比邻星 18/18/18/18、仙女座 16/16/15/15，发行 300=可流通 290+在途 10，原出口仍扣除且未导入。归属进程清理及原停止周期状态不变检查通过；失败现场、报告与精确源码保留，不运行要求完整成功的故障冷验收，不将额外取证时间算作新的放宽界限。

[停止后诊断](operations/evidence/regional-native-bft-active-proof-fault-diagnostic-20261002.json)逐份原生认证三个在线地球副本的 35 份当前父块信封：各副本均有三份准备票，只有一至两份提交票，另存头精确匹配。诊断没有重启、首次签名、恢复响应、采纳头或改动私有文件；顺序停机读取计时不是运行吞吐，也未确定唯一原因。

[修订 32 精确源码、通过周期及失败报告](https://github.com/RunlaiDeng/rldcoin-genesis/tree/6629bbe05a7df18f5c84ccd543ed68645fa85720/research/2026-10-02/regional-native-bft-active-epoch-proof-v32)已公开；[80 个远端文件](operations/evidence/regional-native-bft-active-epoch-proof-v32-publication-verification-20261002.json)逐字节一致，main 指向该提交。三份 273 文件源码归档和完整清单均核验，失败如实标注，不公开生成私有状态。本地状态文档的后续更新不属于已冻结运行源字节。

旧两轮故障仍为失败，后一次原输出在 18 导入、20 才成熟、实际停在 19；没有续跑翻案、提限或迁移。官网/论坛未改动。接下来核查当前父块提交票传播、锁竞争与证据处理调度。任意成员重配置、独立运营/保管、跨设备、掉电、长期历史/密码、物理路线与 I1–I12 仍未完成，整体目标保持进行。下方旧检查点按各自历史范围保留。


## 最新本地实现检查点：修订 31（2026-10-02）

已补齐普通节点交接后的三地区无价值付款循环。十二个节点正常启动，地球旧集合在高度 4 自主选定一个预配置、不重叠的新集合，以三份旧持久封锁和三份新批准激活新时代，再出口第一笔实际所有者签名的测试款。全部地球进程停止期间，比邻星与仙女座自行导入、成熟、再出口并发起新的返程；地球恢复后在高度 9 导入、11 成熟。返程原输出 86 当前可花，初始出口扣除保留，三笔出口/导入身份各不相同；各地区四副本高度一致为 11/4/4，16 次守恒观察通过，最终 300=300+0。控制器生成共识票/法定人数、交接批准/激活、携带付款证明、安装检查点和远端阶段地球调用均为零。

[269 文件实际运行源码检查](operations/evidence/regional-native-bft-joint-cycle-frozen-checks-20261002.json)本轮通过 **72 项进程检查**，含 12 项交接恢复/冷保留检查；[完整循环](operations/evidence/regional-native-bft-joint-cycle-frozen-campaign-20261002.json)正常退出且所有归属节点已停止。运行源码集合为 `d6d299244832fcecf4f9e4b36c24f5b81055a8bf30341852b43967c9a5eb0026`。最终 270 文件发布源增加前版原设计文档、只修正冷验证器模块说明，验证器可执行 AST 及所有普通节点/Native/Core 源字节与运行源一致；[范围核验及重新构建](operations/evidence/regional-native-bft-joint-cycle-release-checks-20261002.json)和两套精确源码归档均保留。发布源集合 `bf7c247ae5023497df005ea54d98d740edfede475aa118b486999ec44a2432ec`，原生身份仍为 `dee623baa0d39c625a142fa04a6f792342a553cac7d30042997a624c962836e6`。沿用修订 30 相同 Native/Core 源的 158 项原生及严格检查，未重跑且不计为本轮新增。

[单独停止后验收](operations/evidence/regional-native-bft-joint-cycle-frozen-cold-20261002.json)用最终重新构建的原生程序逐份完成十二份账本、十二份历史原输出检查，980 条完整 BFT 信封和 2,282 份运输档案认证。地球旧封锁、候选批准和新投票日志的另存 head 分别精确匹配；零号载体旧/新私钥输入始终未配置，没有旧/候选签名及新投票目录。检查没有首次签名、恢复响应、安装状态或改动私有文件的字节、用户所有者、权限和硬链接计数。

[修订 31 公开源码与复现](https://github.com/RunlaiDeng/rldcoin-genesis/tree/99c8e5373053f158fe0380e11cb88af38e68460d/research/2026-10-02/regional-native-bft-joint-offline-cycle-v31)已发布；[63 个远端文件](operations/evidence/regional-native-bft-joint-offline-cycle-v31-publication-verification-20261002.json)逐字节核验一致，main 指向该提交，公开工作区干净。所有生成私有状态留在本地；官网和论坛本轮未改动。

本轮没有新的完整故障配置通过结果。地球最慢高度关卡为高度 11 的 381.55 秒，仍在原 600 秒观察界限内；有锁竞争、保管拒绝和正常换轮，不是持续活性或吞吐资格。下一步需以正确的新投票保管槽和高度重新实现交接后的有限断联/离线领导者演练，并检查重复时代处理的 CPU 成本，保留每份信封的完整原生认证。旧故障脚本只适用 7/4/4 旧配置，不能直接继承为当前 11/4/4 交接循环的通过证据。独立运营/保管、跨主机、长期历史与密码、物理路线和 I1–I12 仍未完成，整体目标继续推进；以下旧检查点按历史范围保留。

## 最新本地实现检查点：修订 30（2026-10-02）

[普通启动流程的预配置交接候选](research/REGIONAL_BFT_AUTONOMOUS_JOINT_EPOCH_CANDIDATE.md)已实现：旧集合正常共识选定确切方案，节点通过钉住身份的 TLS 接触中继交换三份原生旧封锁与三份新批准，再安装新时代并继续共识。消息携带完整时代授权；每份信封和不同有效三签证书变体均先原生认证，原日志/证据字节保留。旧全参与者和旧规则不降低门槛。

[268 文件冻结检查](operations/evidence/regional-native-bft-autonomous-epoch-wallet-frozen-checks-20261002.json)完成带溢出检查及调试断言的发布构建、严格检查、**158 项原生 / 71 项进程检查**，含 11 项实际原生恢复回归。源码集合 `d14db018bcd42cba1aad629f076c2db9397de0953b7d4689e69f15425cc28e43`，原生实现 `dee623baa0d39c625a142fa04a6f792342a553cac7d30042997a624c962836e6`；检查及运行全过程冻结源码未改动。钱包签名高度按原生区块、终局和显式时代事件的顺序从创世重放，复用普通账本的事件执行内核。

[正常节点验收](operations/evidence/regional-native-bft-autonomous-epoch-wallet-frozen-campaign-20261002.json)由三个在线节点自行选定高度 4 的交接方案并推进至高度 7，第四节点以明确不配置旧/新私钥的方式冷追赶，不创建新投票日志。全体重启后完成实际所有者签名的 30 单位测试付款，四份账本高度均为 9，发行仍为 300，收款人余额 30、原生钱包预留为零。控制器生成共识票/法定人数、交接批准/激活、安装检查点均为零；仍为同主机、同控制者和公开 fixture 密钥。

旧投票、新候选批准、新投票日志和 caller head 分开保管；先精确恢复已保留响应再核对最新 head，不能首次签名。新日志创建必须已有本机原生候选日志认证的确切交接批准和另存 head，且在原生激活边界预先保留创建观察；未标记的已有目录拒绝，迟到的非参与者保持只读。响应丢失、初始化失败、旧备份等拒绝/恢复已回归；共同回滚、复制密钥并发、跨设备保管仍未资格化。

[修订 30 源码与证据](https://github.com/RunlaiDeng/rldcoin-genesis/tree/bb89e3abfbe9aff6fba31883228c4c7767124422/research/2026-10-02/regional-native-bft-autonomous-joint-epochs-v30)已公开，[76 个远端文件](operations/evidence/regional-native-bft-autonomous-joint-epochs-v30-publication-verification-20261002.json)逐字节匹配已审阅本地包；六份源码归档包含最终源码及独立保留的失败源码。失败的编译、控制器字段/路径、迟到空日志和钱包时代重放记录分开保留，五个失败验收私有目录未迁移；早期失败单测临时目录由测试器清理，只有源码和日志保留，不能宣称其私有状态保全。生成钥匙、账本、签名/钱包/caller、接触/TLS 状态及恢复镜像不公开。官网与论坛本轮未改动。

这只是一个预配置、不重叠的新集合在新签名无价值创世下的有限地面样本。不迁移旧资产；没有继承或重新运行十二节点完整故障配置，不证明任意成员重配置、持续拜占庭/网络活性、独立保管/复核、长期历史或物理星际路线。I1–I12 和整体目标继续进行；以下旧检查点和统计属于历史证据。

## 最新本地实现检查点：修订 29（2026-10-02）

独立签名准入的 [BFT 交接候选](research/REGIONAL_BFT_JOINT_EPOCH_CANDIDATE.md)先由旧集合正常共识选定确切方案，再收集原签名日志中持久封锁的三份旧批准与三份新批准。旧时代后继与超时签名、竞争方案、缺少批准、改动证据及无效新区块均有拒绝回归；原全参与者时代交接和旧规则不降低门槛。

[263 文件冻结检查](operations/evidence/regional-native-bft-joint-frozen-checks-20261002.json)完成发布构建、严格检查、155 项原生和 60 项进程回归；精确源码集合 `5ce8aa65cc3dd41ca27dab46c83a35b3454c7c5019f7b65c6cd978be257247cc`、原生实现 `a62625a12ee8039c600513fe3cf7ca40d5930552febc7abc99462937cd01d155`。[实际 CLI 交接](operations/evidence/regional-native-bft-joint-cli-campaign-20261002.json)在四份独立本地账本中保持一旧、一新签名者缺席，通过三票视图切换和三旧/三新批准，完成两笔实际所有者签名前后付款；终局高度均为 6，发行 300，激活不改变余额。缺席范围仅为签名者，四份账本仍由控制器投递完整证书；同主机、同控制者，未重新运行十二节点完整故障配置。

[修订 29 源码与证据](https://github.com/RunlaiDeng/rldcoin-genesis/tree/f7bc928e41fda6d6dfdc82ad0315b5d94d1048d2/research/2026-10-02/regional-native-bft-joint-epochs-v29)已公开，[59 个远端文件](operations/evidence/regional-native-bft-joint-epochs-v29-publication-verification-20261002.json)全部与已审阅本地字节一致。初始编译和测试辅助器失败、精确源及私有失败目录保留；源码包不含生成钥匙、账本、签名/钱包/caller 日志或恢复镜像。本轮未更新官网。

这仍是新创世、无价值候选；不迁移旧资产，不证明自主时代配置、任意集合重配置、拜占庭/网络故障活性、独立保管、跨主机、长期历史或物理路线资格。整体目标继续进行。以下旧阶段的“当前”表述及统计是历史检查点，不替代上述精确绑定，也不继承到本轮的完整故障结果。



当前本地候选使用 229 文件冻结源码 `daf6710c8170b994990bbcf96251023fd9d72ffc968de17a51a186c6e4c9843f`；重新构建通过，84 项运输检查、34 项进程/控制器检查通过。发送前完成本地证据准备，再绑定新 TLS 挑战；单次认证中避免重复处理同一已检查帧；已完成运输在活动记录达到 32 时有界归档。活动准入仍为 256、归档仍为每节点 4096 文件/256 MiB、每次最多 16 条，不删除待转发证据或原生账本记录。三秒套接字时限不表示整次迭代或密码验证 CPU 上限。

[保留付款恢复阶段](operations/evidence/regional-native-bft-retained-maturity-20261001.json)已完成，耗时 589.121 秒：从上一轮失败目录的隔离副本启动十二个普通节点，不新签或入队用户付款，原笔净额 9 在高度 10 导入、到高度 12 成熟。成熟观察耗时 144.786 秒，暂停新签名后已有完整证书在 12.163 秒内收敛；停止后每地区四副本高度一致为地球 15、比邻星 12、仙女座 12，发行 300 = 可流通 300 + 在途 0，原出口扣除与导入墓碑保留。4,256 条档案载荷重新认证通过，原失败目录和精确冻结源码保持不变，十二个节点已停止。另行[四份原生收款重放](operations/evidence/regional-bft-retained-cold-recipient-20261001.json)均确认原输出 9 可花、终局覆盖且未隔离；只读重放未改变私有文件。

恢复阶段不是完整故障配置的通过结果。前一轮 [956.535 秒故障演练](operations/evidence/regional-native-bft-preconnect-sustained-20261001.json)虽已完成导入，但未在 600 秒内成熟，失败记录继续保留；完整故障冷验证器实际拒绝把新恢复阶段当作完整通过。相同新冻结源码的[完整新故障配置](operations/evidence/regional-native-bft-early-archive-fresh-20261001.json)已在 863.055 秒内完成：从原高度 7/4/4 起步，地球验证者 0 离线、地球与比邻星双向连接切断；在线验证者在 107.403 秒内通过高度 9 关卡，重启节点在 34.281 秒内追赶，连接于 248.496 秒恢复。原净额 9 在高度 11 唯一导入、13 成熟，恢复后成熟关卡用时 488.991 秒，停签后证书收敛用时 26.455 秒。停止后四副本各自一致为地球 15、比邻星 13、仙女座 16，发行 300 = 可流通 300 + 在途 0。[单独冷验证](operations/evidence/regional-native-bft-early-archive-fresh-cold-20261001.json)完成十二份原生重放、四份原输出成熟检查及 4,506 份归档载荷完整认证，私有文件、原密封起点和冻结源码保持不变，控制器生成共识消息/搬运价值证明/安装检查点均为零。所有观察关卡在记录时限内完成；这是一次同主机、同控制者、有限高度地面配置通过，不能宣称持续 BFT 活性或独立资格。[修订 17 精确源码与报告](https://github.com/RunlaiDeng/rldcoin-genesis/tree/fcb05fea38ccf83913a83f7fd263d27c1bf284d5/research/2026-10-01/regional-native-bft-fault-recovery-v17)已公开；[53 个远端文件校验](operations/evidence/regional-native-bft-v17-publication-verification-20261001.json)全部与本地一致。此前修订 16 和四轮失败保持原样。[官网修订 17 入口](https://rldcoin.com/developers#reproduce-v17)已上线；生产构建、六项状态检查、五个实际页面、精确源码链接和桌面/手机显示均验证通过，旧入口保留，退役主网 API 仍为 410。

当前新增原生前缀重放候选：只复用本进程在同一完整信任绑定下已完整验证的精确前驱状态，冷启动仍从创世验证全部保留区块，新尾块仍完整验签/执行，拒绝时不推进终局。去除每块整链复制和时代准备时整份证据复制，为分层历史保存减少重复工作；256 块/64 检查点容量仍保持，20 万块时代与长期恢复尚未完成。[230 文件精确冻结源码检查](operations/evidence/regional-native-prefix-frozen-checks-20261001.json)已完成，源码集合 `47b07d586f58914881c98e32dd7abc93b8cdbfb449b7d6f15538594dd95ecd62`、原生实现 `d268bd83be7f87afa2db26603ae4597d711aa85eaaf265bccdce8d1426b2e971`；86 项原生、84 项运输、34 项进程/控制器检查及严格静态检查通过。[64 检查点样本](operations/evidence/regional-native-prefix-replay-sample-20261001.json)的冷验证执行 64 块，从创世逐份重放的对照执行 2,080 块，所有账本字段和根一致；两个计时工作负载的证书检查范围不同，不能宣称端到端吞吐按同比例提高。[新创世往返](operations/evidence/regional-native-prefix-fresh-cycle-20261001.json)完成 15 次守恒检查，四副本高度一致为 7/4/4，净收款 96/91/86；[停止后冷验证](operations/evidence/regional-native-prefix-fresh-cycle-cold-20261001.json)完成十二份原生重放、十二份历史原输出核查和 1,472 份档案认证，首笔/续转原输出已花、返程原输出 86 可花，私有文件保持不变。[完整新故障配置](operations/evidence/regional-native-prefix-fresh-fault-20261001.json)在 1,059.417 秒后失败：恢复后 600 秒成熟观察超时，部分 BFT 持久状态达到 32 MiB 容量。停止后十二份重放高度为 16/16/17，各地区四副本高度相等；原净额 9 在比邻星高度 15 导入、须高度 17 成熟，当前高度 16 尚不可花。[单独诊断](operations/evidence/regional-native-prefix-failed-fault-diagnostic-20261001.json)确认四份原输出均保留且未隔离，私有文件保持不变；完整故障冷验证器实际拒绝失败报告。重复快照约 32 MB、不同完整快照不足 0.6 MB，仅为字节诊断，不能证明是唯一失败原因；另有锁竞争和 TCP 保管拒绝。下一步实现有界共享证据存储，不能增加上限或删证据取得通过。公开修订 17 及其旧原生实现保持不变。[分层历史义务](research/REGIONAL_HISTORY_RETENTION_V1.md)另列真正长期容量、永久去重与恢复要求。 [修订 18 源码与成功/失败报告](https://github.com/RunlaiDeng/rldcoin-genesis/tree/0ef4c9395f66cd3f4821c581c3fd6eff47e05fa6/research/2026-10-01/regional-native-prefix-replay-v18)已公开，[44 个远端文件](operations/evidence/regional-native-prefix-v18-publication-verification-20261001.json)均匹配；[官网修订 18](https://rldcoin.com/developers#reproduce-v18)已上线，五个页面、六项状态检查、精确链接及桌面/手机显示验证通过。完整故障失败在官网明确展示，旧入口和修订 17 历史链接保留；主网 API 仍为 410。

新增本地共享证据存储候选：按完整规范快照字节共享，保留每份信封的有序/重复引用、原始正文、价值/本地标记和完整字节摘要。组合状态仍为 32 MiB，上限 512 消息、每信封 64 引用、载荷 3 MiB 不变；完整原生验证仍在收到和重启时执行，旧私有格式拒绝且不改写。13 项存储/真实原生恢复检查与原有 11 项 BFT、5 项控制器检查通过；签名响应在替换前写入失败或成功原子替换后的响应确认丢失注入中，仍由另存 head 精确恢复，不能首次签名；未注入实际 fsync 失败或断电。[2,259 份旧失败消息的字节往返](operations/evidence/regional-bft-shared-evidence-byte-sample-20261001.json)保持正文、完整证据与标记一致，最大状态由 33,529,748 字节表示为 1,628,727 字节；这仅为字节核查，旧私有目录未迁移，不能替代完整故障通过。首份 234 文件冻结源码 `24fb58eda0a3fcea0744b12e6b2587656a1d740ede5c93b25b6a4291133f6042` 已重建并通过 84 项运输、46 项进程/存储检查；完整往返因控制器仍读取旧状态布局而受控中断，实际命令已到达四个地球验证者。正常清理完成，十二份停止后原生读取和 128 份保留控制信封原生认证通过，私有文件未改变；不能计完整往返通过。读取器已改为新格式的有界只读查询，随后另行冻结的最终候选结果见下一段。


最终 234 文件冻结源码 `5ab9e125172125c34ecd81d811c2f00097a59801d7b326afa017559476c52bc0` 已重建并通过 47 项进程/控制器/存储检查；原生和运输源码字节相同，保留先前 86/84 项检查而未重跑。[新往返](operations/evidence/regional-bft-shared-retention-observer-fresh-cycle-20261001.json)完成净额 96/91/86、15 次守恒和四副本高度 7/4/4；[冷验证](operations/evidence/regional-bft-shared-retention-observer-cycle-cold-20261001.json)完成十二份账本、十二份历史原输出、627 条控制消息与 1,408 份档案认证。[完整新故障](operations/evidence/regional-bft-shared-retention-fresh-fault-20261001.json)在 653.438 秒内通过，原净额 9 在高度 12 唯一导入、14 成熟；最终地区高度 15/14/15。[故障冷验证](operations/evidence/regional-bft-shared-retention-fresh-fault-cold-20261001.json)完成十二份账本、四份原输出、1,898 条控制消息与 4,324 份档案认证，300 = 300 + 0，私有文件未变，最大状态 1,378,543 字节。旧失败和首份受控中断均保留；这仅是一次有限同主机配置通过，不能计持续活性、长期历史或独立资格。下一步实现原生分页历史、永久去重和恢复承诺。[修订 19 精确源码和报告](https://github.com/RunlaiDeng/rldcoin-genesis/tree/195678658a7684f4aea81c5f1f6896f9e8665bf5/research/2026-10-01/regional-native-bft-shared-evidence-v19)已公开，[47 个远端文件核验](operations/evidence/regional-bft-shared-v19-publication-verification-20261001.json)全部一致。[官网修订 19](https://rldcoin.com/developers#reproduce-v19)已上线，生产构建、六项状态检查、五个实际页面、六份远端源码、手机菜单及精确链接核查通过；主网 API 仍为 410。截图工具卡住，未完成本轮图片视觉检查，限制保留在[官网核验](operations/evidence/regional-bft-shared-v19-website-verification-20261001.json)中。

## 当前网络

开发与验证使用无货币价值的公开 fixture 测试网。正式网络尚待完成验收和精确签名采用；测试资产与密钥不得进入正式网络。

[测试网验收与缺口](operations/EARTH_FRESH_TESTNET.md)。

## 强制目标进度

| 条件 | 当前可确认范围 | 未完成的强制验收 |
| --- | --- | --- |
| I1 货币与地区身份 | 固定创世/源绑定，mesh 身份与权限分开；通用 fixture 候选离线验证签名准入和精确源码根。 | 正式通用准入、多源信任时代与独立审查。 |
| I2 当地断联自治 | 固定源候选及通用 CLI 在无远程 HTTP 下出块、付款、成熟、重放与安装接触证据。 | 长期/跨设备、故障恢复和正式采用；长期自治仍需新版本实际验收。 |
| I3 发行守恒 | 三地区原生候选已检查多金额/多所有者、拆分合并、找零、两地费用、多来源和循环。 | 通道 E、完整故障恢复及独立发行守恒资格。 |
| I4 任意地区转移 | 三个原生候选账本已通过默认中继启动、自动证据验收/导入、多来源付款、再出口和新返程；目录与实际 TCP 两种地面演练分别通过 31 次守恒检查。 | 跨设备持续原生网络、完整地区共识与独立资格；正式采用仍待验收。 |
| I5 再出口与终局组合 | 候选 Export 验证输入创建的当地已准入终局覆盖（旧配置四签；新容错配置准备/提交各三签），并保留祖先依赖。 | 跨重组/故障模型、BFT/独立签名服务资格与正式采用。 |
| I6 真正价值返程 | 候选执行新出口/返程新导入、持久去重和循环重复拒绝；没有释放初始扣除。 | 外部防回滚、完整故障与长期独立验收。 |
| I7 地区终局与信任演进 | 通用候选已有事故保全/隔离、持久签名 Agent、另存 head 的旧备份拒绝、旧新四签共同交接与时代故障保全。明确准入的容错地面配置新增三签准备/提交、持久准备证书锁、认证换轮和区块/终局原子安装；一位初始领导者离线的真实 CLI 演练推进并完成跨区/再出口。 修订 14 已接入显式准入验证者的自动调度和 TLS 控制帧代码；8 项真实原生 companion 检查覆盖另存 head、签前落盘、无私钥恢复、付款队列验收、迟到旧轮证书安装和新投票发送名额；普通启动的四节点 TLS 自主投票/换轮/追赶/重启/当地付款在工作区与冻结源码均完成。 | 跨区自主候选的持续可用性及完整 BFT 活性/故障/重配置、独立资格、恢复授权和独立保管。 |
| I8 原生发现与因果运输 | fixture 普通启动默认目录与固定 TLS 1.3 的 IPv4 中继；59 项运输/套接字检查、8 项中继进程集成保持通过，增量入网、备用路径、连接认证/拒绝降级及无共享运输目录的三原生进程 TLS 价值演练已验证。 | 正式节点集成及精确发布、N1–N10 完整资格、跨设备/物理适配、独立加密审查与对抗资源/可用性；物理路线另证。 |
| I9 付款状态 | 通用原生钱包命令已分开当前可花/未成熟/隔离/可再出口金额；签名复核已审阅金额/收件人/精确地区与当前账本/事故；收款独立验出口、净额、导入/成熟及原输出已花。持久命令/输入预留与另存 head 已加入；共同付款已支持各方独立审阅、持久部分签名、仅本人输入预留与完整授权组合；本机界面接入付款审阅、显式签名/入块、共同批准文件与独立收款核验；交互提案构造固定绝对有效高度，各方在不同高度仍可审阅同一付款；原生随机加密密钥与完整 Journal 备份/新目录恢复已加入，保留预留且要求另存最新 head；界面可保存加密备份。26 项钱包 Rust 检查及 16 项真实钱包进程/HTTP 检查通过。 | 完整钱包产品（硬件保管、加密保管独立安全资格等）、跨设备多所有者资格、重组下预留/恢复、跨设备与外部防回滚及独立资格。 |
| I10 长期存储与恢复 | 短期归档候选；原生 Journal/事故索引重放、缺失/损坏/超额拒绝和精确修复。 | 外部单调根防旧备份回滚、长期独立档案/容量、去重承诺与升级采用。 |
| I11 长期密码与撤销 | 白皮书定义长期验证义务；候选已验证同算法验证者键时代交接；地面 TLS 已验证固定证书/连接认证、拒绝降级与当地有效期，尚无账本算法迁移。 | 实际算法时代、在途撤销/续认证、星际降级防护/验证期限和独立复核；90 天地面证书不是长期资格。 |
| I12 独立资格与持续服务 | 同控制者跨平台检查及原生地面候选；没有独立完成证据。 | 独立运营/保管和安全复核、持续服务、跨设备钱包恢复/防回滚、费用资源及真实路线。 |

**以上全部为部分实现或未实现，I1–I12 没有一项达到完整资格。** 这张表不得以文档修订、测试数量或运营者网页遥测替代。

## 下一步与完成语义


上述新源码的完整故障配置和停止后原生冷验证已通过，精确源码、真实负载/故障/恢复观察及未完成资格已发布。继续本地有界负载、故障/长期恢复与剩余原生义务的实现，独立与物理资格另行验收。现有四轮失败及其准确源码和检查记录保留在[后续验收顺序](operations/INTERSTELLAR_ACCEPTANCE_QUEUE.md)，不得被恢复阶段覆盖或计为通过。相同正文的新证明仍完整验证后才去重，进度不可用保留为未知，不用较低副本的零在途数抹去较高已认证历史中的扣除。

用户确认目前没有第二台测试主机或独立运营者，继续可验证的本地实现；跨主机、独立保管、完整 BFT 活性/重配置、通道、完整钱包、长期存储/密码与实际物理路线均保持为未完成要求。正式主网另须新签名零发行创世，旧网络和测试余额不得迁移。

[修订 15 三地区自主往返](operations/evidence/regional-native-bft-multiregion-campaign-20260930.json)与[冻结源码复现和失败记录](operations/evidence/regional-native-bft-multiregion-verification-20260930.json)现已完成：十二个普通原生进程使用相邻固定 TLS 接触，自动发现三地区；全部地球进程停止期间，比邻星与仙女座自行导入、成熟、再出口并发起新返程。地球恢复后唯一导入返程并成熟；净收款分别为 96、91、86，最终四副本高度一致为地球 7、比邻星 4、仙女座 4，15 次 I=U+T 检查全部守恒。控制器生成投票、携带价值证明、安装检查点与远端阶段地球调用均为零。保留的工作区版本与 226 文件精确冻结源码的完整结果相同，实际观察耗时、只读重试调用数和三份收款时的完整本地 Journal 观察哈希允许不同；两次运行的 24 个原生目录重新验证通过，账本投影、事件、事故及时代证据一致，观察哈希不是余额根；原 167 个采用源码字节不变。81 项原生、36 项进程/HTTP、70 项运输与严格静态检查记录对应这个 V2/TCP-V3 版本。此前失败及中断演练保留，不计通过。完整 I1–I12、持续 BFT 活性、独立保管及物理路线仍未完成。

当前工作区另有未纳入修订 15 的 V3/TCP-V4 归档改动，2026-10-01 的 78 项运输与 36 项进程/HTTP 检查通过；该新版本的工作区完整三地区往返也已完成，15 次守恒检查通过，并在原进程退出后逐份重新读取验证保留档案；[归档候选报告](operations/evidence/regional-native-archive-workspace-checks-20261001.json)保留精确文件哈希与各节点容量观察。该 V3/TCP-V4 版本的 226 文件冻结源码也已独立重新构建并完成完整往返，78 项运输、36 项进程/HTTP 检查通过；两次运行的 24 个原生目录完整重放一致，冻结运行的 416 条归档载荷在原进程退出后逐份重新认证。[精确复现报告](operations/evidence/regional-native-archive-frozen-verification-20261001.json)和[三个真实 SIGKILL 边界](operations/evidence/regional-native-archive-crash-20261001.json)分别保留源码哈希、容量和恢复观察。进程崩溃演练不证明掉电或跨设备资格；[修订 16 精确源码与报告](https://github.com/RunlaiDeng/rldcoin-genesis/tree/dd02da67a8945cc7c953810ab39bb6949d8e518a/research/2026-10-01/regional-native-archive-v16)已公开，36 个新增/更新文件的远端哈希均验证一致；历史包保留。持续负载/故障仍待完成，新版本证据与修订 15 分开，不升级已采用网络。[后续验收顺序](operations/INTERSTELLAR_ACCEPTANCE_QUEUE.md)要求先冻结新源码，完成有界归档、持续负载/故障和跨设备验证，再推进独立保管、通道、完整钱包及长期密码/档案。

[通用地区候选](research/REGIONAL_LEDGER_CANDIDATE_V1.md)的[持久签名与时代修订](research/REGIONAL_SIGNER_EPOCHS_V1.md)通过 35 项原生检查与 128 次 CLI campaign；[当前报告](operations/evidence/regional-native-epochs-campaign-20260930.json)覆盖同机公开 fixture 的四签锁/交接、离线转移/新返程、事故隔离和守恒。签名先落盘，再返回；旧签名目录加保留的最新外部 head 拒签。共同交接保持币根与余额，缺任何签名则停顿，不等于 BFT 或完整防回滚。[默认中继与自动原生导入报告](operations/evidence/regional-native-default-relay-campaign-20260930.json)已补齐候选同一启动流程和三地区自动交付/价值返程；这是无货币价值的目录接触实现，不修改已采用节点。[原生钱包验证](operations/evidence/regional-native-wallet-verification-20260930.json)已补齐命令层的签前核对与独立收件；[持久预留与恢复](operations/evidence/regional-native-wallet-reservations-verification-20260930.json)已补齐单所有者命令层的未包含预算和响应恢复；[实际 TCP 地面适配与验收](operations/evidence/regional-native-tcp-verification-20260930.json)已补齐普通启动的本机 IPv4、多跳保管与断线恢复，三账本演练不使用共享运输目录；[默认 TLS 与连接认证](operations/evidence/regional-native-tls-verification-20260930.json)又补齐独立证书固定、拒绝降级/跨连接重放与地面有效期检查；[独立多所有者签名与组合](operations/evidence/regional-native-group-wallet-verification-20260930.json)又补齐共同付款的单方持久批准、本人输入预留、完整组合与实际跨区收款；[本机钱包界面与恢复边界](operations/evidence/regional-native-wallet-app-verification-20260930.json)进一步接入实际付款、预算与收款阶段；[交互共同提案与固定有效高度](operations/evidence/regional-native-group-proposal-verification-20260930.json)补齐不同高度的同一付款构造/独立批准；[加密密钥与完整备份恢复](operations/evidence/regional-native-encrypted-custody-verification-20260930.json)进一步补齐同机地面保管、预留保持、旧备份拒绝与恢复密钥再次付款；下一步完成跨设备/物理适配与独立加密审查、完整钱包产品及跨设备共同付款/重组恢复；BFT、通道、长期存储/密码和独立资格仍是强制条件。安全取消、流动性垫付和压缩证明可另立提案，但不能替代上述强制功能。

当前文档满足目标对齐（DOC_ALIGNED）。协议资格（PROTOCOL_QUALIFIED）、新地球主网正式采用（EARTH_RELEASE_AUTHORIZED）和具体物理路线资格（PHYSICAL_ROUTE_QUALIFIED）均未完成。各阶段必须记录精确版本、范围、故障假设和期限；不承诺超光速、无限档案寿命或百万年密码安全。

[修订 13 地区容错地面演练](operations/evidence/regional-native-bft-campaign-20260930.json)使用每地区四个账本/签名目录、三名实际 CLI 投票者。初始领导者不投票，三方认证换轮后推进，离线副本逐个认证块追赶；原生钱包完成净额 95 的比邻星收款和净额 93 的仙女座再出口，远端执行期间无地球调用。12 次守恒检查只计算每地区一份规范历史。该修订的控制器携带投票消息，当时普通中继不会自动投票/调度；运输证据保管不能当作当地导入提交。完整自动共识网络、容错时代交接、独立运营/保管及持续故障资格仍未完成，I7 仍为部分实现。

[修订 14 自动 TLS 演练](operations/evidence/regional-native-bft-autonomous-campaign-20260930.json)与[完整验证及失败记录](operations/evidence/regional-native-bft-autonomous-verification-20260930.json)记录普通原生启动的四验证者网络：初始领导者离线时其余三名实际投票者推进到第三块，离线副本经固定 TLS 多跳证据追赶；已审阅签名付款先入队/传播而未扣账；四节点带另存签名 head 重启后自行认证到第五块，副本余额一致、收款净额 30、待入块输入预留为零。控制器生成共识消息和安装检查点次数均为零；逐跳证据验证实际两跳承载。工作区与冻结的 225 文件源码重建分别完成相同语义结果，差异只在声明的阶段实际耗时；每个主要观察阶段上限 300 地面秒，重启/付款阶段分别约 98.391/189.186 秒，均不是星际时效承诺。原有 167 个采用源码字节保持不变。

80 项原生、34 项进程/HTTP、61 项运输测试与严格静态检查在工作区/冻结源码分别通过。新的 8 项自动运行检查覆盖 caller head 精确恢复、签前保存失败、旧备份拒绝、控制帧域、原生付款 JSON/篡改、无私钥旧轮完整证书验收及新投票发送名额。此前超时或控制器字段错误的 8 次初步运行没有计为通过；修复点和观察耗时在验证报告保留。三个地区的原生控制器携带价值回归另保留 12 次守恒检查，旧配置三进程 TLS 另保留 31 次；它们不等于三地区全自动网络。跨地区自治持续服务、完整容错活性/重配置、独立运营/保管、外部单调锚、通道/完整钱包、长期存储/密码与真实物理路线仍未资格化；I1–I12 仍没有一项完整达标。

## 原生分页磁盘存储候选

### 私有账本档案与新目录恢复候选

新增 `history-archive` / `history-restore`，在原生锁内核对另存最新头和完整原生重放。
档案保留全部分页对象、认证事故与损坏事故残留；摘要只核对字节，不授权价值。
目标必须是新私有目录，复制并同步后再次完整核验才移除 `RESTORING`；中断目录
保留不重写，普通启动、钱包入口及事故恢复均拒绝。签名者、钱包、调用者头与待
审核状态、密钥、TLS 和运输档案不在账本恢复范围，也不得公开生成的档案。
十项新增原生测试及严格检查通过；五项真实命令测试通过，包含实际 SIGKILL、
已消费导入的永久记录、旧头/跨域/既有目标拒绝。首轮一项测试的错误文本断言失败
已保留日志与初始源码；改为完整长度伪签名后验证原生密码核验拒绝。当前源码
尚待精确冻结、新 fixture 创世往返与完整有限故障配置，不能沿用修订 20 的通过。
逻辑 8 MiB/256 块/64 检查点与档案边界不变；真正长期历史、独立最新锚、掉电和
跨设备保管仍未完成。

默认节点创建/重启已接入 `RLD-NATIVE-HISTORY-MANIFEST-V1`：完整快照、时代与接触记录保存为不可变规范对象，十六事件页绑定顺序、当地高度区间和前页摘要；紧凑清单承诺完整重建日志，再执行原生币种、终局、所有者、守恒、永久导入和事故核验。旧尾页和失败残留不删除、不作为新价值授权。4,096 文件/256 MiB 的地面档案准入计入所有残留；逻辑 8 MiB、256 块/64 检查点及账本索引上限不变。

调用者另存最新 `history-head` 后，`history-check` 在原生锁内拒绝旧清单，并在原生重放前拒绝待恢复事故；当前查询不代表独立新鲜度，全状态与头一起回滚仍未获资格。首批 12 项新增分页/原生拒绝检查和原有 86 项原生检查通过，严格静态检查通过；原接触记录损坏检查改为摘要自洽的损坏分页对象，并明确验证原生“缺少已认证源检查点”的拒绝，避免只因旧布局被拒而通过。源码改变需要新 fixture 创世/币种，旧私有目录拒绝且保留，不能复用修订 19 的通过报告。后续最终冻结源码已完成真实进程和新签付款往返/停机冷验证，详见本节新增结果；20 万块历史、紧凑远程价值证明和新目录档案恢复仍未完成。

首份 237 文件冻结源码 `b0df4102859ee85f1101ef94b8626446bab4bd5ed7d4c10303ba665f8d218e6f` 已重建，98 项原生检查和严格静态检查通过；52 项进程检查有一项错误，因为测试未显式选取 100 的实际输入，原生守恒正确拒绝，未开始完整往返。第一份源码与日志保留。另用真实认证事故证明复现了历史头未承诺未索引事故的缺口；当前锁内检查已要求全部保留认证事故与清单索引完全一致，拒绝时不重写事故、清单或保管头。追加回归需在新源码下重新完整核验。

最终 237 文件源码 `1756c85e876dbca24275c77e7d035673d2b3fd4a90c5c67b0cbbbf99cd0d445b`、新原生实现 `55342fdef7568fadbd9d0c6d529a081e3ccd490b62b37b3d10e28b900ca773f8` 已从冻结目录重建并通过 99 项原生、52 项进程/存储/历史和严格静态检查；先前 84 项运输检查来自精确相同字节，未重跑。[新往返](operations/evidence/regional-native-history-pinned-fresh-cycle-20261001.json)完成净额 96/91/86、十五次守恒和四副本高度 7/4/4 一致。[冷验证](operations/evidence/regional-native-history-pinned-cycle-cold-20261001.json)认证十二份原生重放、十二份历史原输出、639 条保留控制信封和 1,424 份运输档案；[原生分页核查](operations/evidence/regional-native-history-pinned-cycle-storage-audit-20261001.json)完成十二次新进程完整重放和精确另存头匹配，最大清单 4,522 字节、最大逻辑日志 165,304 字节，私有文件与冻结源码不变。短往返每副本仅一事件页，不能认证长期执行。[完整新故障配置](operations/evidence/regional-native-history-pinned-fresh-fault-20261001.json)已在 723.342 秒内通过并正常退出，原净额 9 在比邻星高度 12 唯一导入、14 成熟，最终地区四副本高度 14/14/16；[单独故障冷验证](operations/evidence/regional-native-history-pinned-fault-cold-20261001.json)认证十二份原生重放、四份原输出、1,922 条控制消息和 4,359 份运输档案，300 = 300 + 0；[分页核查](operations/evidence/regional-native-history-pinned-fault-storage-audit-20261001.json)完成十二次完整重放和精确另存头匹配，每副本两事件页、最大清单 6,791 字节、最大逻辑日志 434,232 字节，私有文件和源码不变。[首份附加核查的工具失败](operations/evidence/regional-native-history-pinned-audit-tool-failure-20261001.json)在首次原生调用前发生，缺失的顶层报告币种字段现由精确 bootstrap/报告绑定替代；修复后通过，原生源码未变。逻辑上限和残留准入不变，既往失败源码/记录保留；这是一次有限同主机配置观察，仍不认证长期历史、独立最新锚、完整 BFT 或物理路线。

[修订 20 精确源码、通过/失败记录及复现命令](https://github.com/RunlaiDeng/rldcoin-genesis/tree/ed51f597bc7242ae15bb615ab007d63e69f974f7/research/2026-10-01/regional-native-paged-history-v20)已公开，[54 个远端文件核验](operations/evidence/regional-native-history-v20-publication-verification-20261001.json)全部逐字节匹配。独立英文[官网修订 20](https://rldcoin.com/developers#reproduce-v20)已上线，提交 `679911eabc6ee14733a5150669db23b15558e184`、生产部署 `dpl_5FPGFgtnSgHbe7LdtcEGXCvMuvyJ` 为 READY；[官网核验](operations/evidence/regional-native-history-v20-website-verification-20261001.json)完成生产构建、六项状态检查、五个线上页面、六份精确远端源码、桌面/手机实际画面及菜单/跳转核查，未见横向溢出或浏览器错误。命令行截图超时，诊断后改用应用内浏览器成功保存和检查画面；本轮视觉记录已完成。旧复现锚及修订 19 通过、18 失败、17 历史直达链接保留；原主网 API 仍为 410，余额不迁移、新主网未上线。本轮临时浏览器/本地网站服务和演练节点均已正常关闭，私有状态保留，论坛未发消息。下一步继续真正长期原生执行、独立最新锚和带中断标记的新目录恢复，而不是提高现有上限或宣称跨主机/物理资格。

新私有账本恢复候选的 241 文件精确源码 `4af70053f541a67f967bbcfca3d647c46af663343c34e76d7c2e5d63cee6d258`、原生实现 `d713c6afc275d743b50059250815617b4a88bc97eef201c4d6ee18ab9cf80e6d` 已冻结重建，109 项原生、57 项进程/历史检查和严格静态检查通过。新签 fixture 往返完成 96/91/86、十五次守恒与四副本高度 7/4/4；[单独冷验证](operations/evidence/regional-native-history-image-cycle-cold-20261002.json)认证十二份原生和原输出、607 条 BFT 信封、1392 份运输档案，私有文件不变。[十二份新目录恢复](operations/evidence/regional-native-history-image-cycle-fresh-target-audit-20261002.json)全部完整原生重放、另存头、状态/永久导入/事故及所有保留字节匹配，源文件和冻结源码不变，档案私有且不包含签名者、钱包或调用者保管状态。完整新有限故障配置已启动，但尚无终端通过结果；未公开修订 21，也未将修订 20 报告计作新源码资格。长期历史、独立最新锚、掉电和跨设备资格仍未完成。

当前原生档案恢复源码的[完整新有限故障配置](operations/evidence/regional-native-history-image-fresh-fault-20261002.json)已在 583.24 秒通过并正常退出，原净额 9 在比邻星高度 11 唯一导入、13 成熟；最终地区四副本高度 {'earth': 14, 'proxima': 13, 'andromeda': 14}。所有演练进程已停止，原封存周期目录不变。[单独故障冷验证](operations/evidence/regional-native-history-image-fault-cold-20261002.json)认证十二份原生、四份原输出、1688 条 BFT 信封和 3844 份运输档案，原私有文件不变；[十二份故障账本新目录恢复](operations/evidence/regional-native-history-image-fault-fresh-target-audit-20261002.json)全部原生完整重放、另存头、状态/永久导入/事故和保留字节精确匹配，源文件与冻结源码不变。加上周期共 24 份私有账本档案/恢复已通过，但不恢复签名者、钱包或调用者保管状态，不公开生成档案。一次同机有限配置和真实进程中断不等于掉电、独立最新锚、跨设备保管、长期历史或全部 I1–I12 资格。

[修订 21 私有账本恢复精确源码与验收记录](https://github.com/RunlaiDeng/rldcoin-genesis/tree/dbb9930eb74819b8b2403010baa530eb3b4d6e20/research/2026-10-02/regional-native-history-recovery-v21)现已公开，提交 `dbb9930eb74819b8b2403010baa530eb3b4d6e20`，50 个远端文件逐字节匹配。独立英文[官网修订 21](https://rldcoin.com/developers#reproduce-v21)已上线，提交 `56f5ccd4614a69e36d3b883bb18c651290a50134`，生产部署 `dpl_7zErQPk49YHuA3cGwV4V9xUsxUuX` READY；五个线上页面、六份远端源码、六项状态检查、桌面与手机实际画面及导航核验通过，没有横向溢出或浏览器错误。生产域名确实服务新固定源码版本，旧 14–20 复现入口与 v20/19/18/17 历史证据直达链接保留。Vercel 连接器读取团队时返回 403，现有项目 CLI 授权可正常读取并核对准确部署、提交和域名；没有扩展权限或重新配置账号。首个远端文件核验发生瞬时 Broken pipe，保留失败记录后按原 TLS 核验重试，完整 50 文件核验通过。临时浏览器已关闭、视口恢复；原主网 API 仍 HTTP 410/RETIRED，余额不迁移、新主网未启动，论坛未发消息。继续真正长期原生执行、紧凑远程依赖证明和永久索引扩展；独立锚、掉电、跨设备保管与物理资格保持未完成。


继续推进长期历史的结构性限制：原生存储 V2 以准确的已列前置检查点对象复用磁盘前缀，后续对象只保存新增块及完整证书/时代信息。读取时拒绝前向、孤立、跨域、长度/高度不符的引用，限制展开字节并重建完整原生日志后核验。完整签名运输快照及价值规则不变；源码承诺变化仍要求全新签署的无价值 fixture。旧 V1 私有目录和所有历史记录保留，不能自动升级或迁移余额。逻辑 8 MiB/256 块/64 检查点与 4096 文件/256 MiB 档案准入均不提高；这是重复磁盘历史的改进，不是长期历史或紧凑远程证明完成。新增六项原生测试正在核验，最终冻结、新 fixture 往返与故障资格尚待本轮结果。

The first frozen disk-prefix candidate exposed an unintended duplicate-checkpoint refusal in complete regression. Exact repeats and independently authenticated equivalent BFT quorum encodings remain valid native evidence. Storage now retains every listed proof and selects the earliest exact predecessor object for deterministic prefix sharing; it does not normalize away native authorization checks. The first full frozen source and failed logs are retained; a seventh focused regression covers exact repeats and forged duplicate rejection. Final frozen qualification is pending.


最终磁盘前缀候选的 242 文件源码 `a108ec7da7e8707d0c46093e33af64ae6893fb2529ea22eb5a773e0a23a1d928`、原生实现 `64c09ec0696918b42f0c91fe82cb66c9ea833e1e205d873f89d9174bad24a2a6` 已冻结重建，116 项原生、57 项进程/历史检查与严格静态检查通过。[64 检查点样本](operations/evidence/regional-native-history-prefix-final-storage-sample-20261002.json)将准确相同快照的 V2 对象字节从 1314584 降至 149192，约减少 88.65%；完整原生日志及新目录档案恢复精确一致。这不表示运输/内存或全部残留同幅减少。新签 fixture 往返完成 96/91/86、十五次守恒和地区各四副本 7/4/4；[停机冷验证](operations/evidence/regional-native-history-prefix-final-cycle-cold-20261002.json)与[十二份新目录恢复](operations/evidence/regional-native-history-prefix-final-cycle-fresh-target-audit-20261002.json)通过，私有原件和冻结源码不变。完整新有限故障配置已启动，尚无终端通过结果；首份源码与 87 通过/28 失败日志另存，不沿用修订 21 的资格，未公开修订 22。所有原边界及长期历史/紧凑远程证明/独立最新锚/掉电/跨设备资格仍未完成。


当前最终磁盘前缀源码的[完整新有限故障配置](operations/evidence/regional-native-history-prefix-final-fresh-fault-20261002.json)在 705.36 秒通过并正常退出，原净额 9 在比邻星高度 12 唯一导入、14 成熟，最终地区各四副本高度为地球 15、比邻星 14、仙女座 15。所有演练节点停止，封存周期原件不变。[单独故障冷验证](operations/evidence/regional-native-history-prefix-final-fault-cold-20261002.json)完成十二份原生和四份原输出核验，认证 1918 条 BFT 信封与 4352 份运输档案，私有原件不变；[十二份故障账本新目录恢复](operations/evidence/regional-native-history-prefix-final-fault-fresh-target-audit-20261002.json)完整原生重放、准确另存头、状态/永久导入/事故及每份保留字节一致。加上周期，24 份私有账本档案与恢复通过；不含签名者、钱包或调用者保管状态，生成档案不公开。第一次冻结的 87 通过/28 失败与准确源码保留；修正后最终 116 项原生、57 项进程检查通过。V2 减少重复磁盘历史，完整运输与内存、原边界保持；长期历史、20 万块时代、独立最新锚、掉电、跨设备及物理/独立资格仍未完成，目标继续。


[修订 22 准确源码与通过/失败证据](https://github.com/RunlaiDeng/rldcoin-genesis/tree/3decd2ac98a52945395de0774cec42240cc91cfb/research/2026-10-02/regional-native-history-prefix-v22)已公开，提交 `3decd2ac98a52945395de0774cec42240cc91cfb`；[远端核验](operations/evidence/regional-native-history-v22-publication-verification-20261002.json)确认 52 个远端文件逐字节一致、main 指向该提交，公开工作区干净。包包含最终 242 文件源码及第一次失败的完整 242 文件源码/日志/说明，没有生成的私有账本、密钥、钱包、签名者、调用者、TLS 或运输保管状态。独立英文官网当前保留修订 21 的准确固定版本入口，本轮集中于本地实现与公开源码；没有发论坛消息。所有演练节点已停止，源/档案/恢复原件保留。继续紧凑远程证明、完整内存/永久索引扩展和超越 256 块/64 检查点的长期原生执行；未认证跨主机、独立最新锚、掉电、跨设备保管、物理路线或全部 I1–I12，目标保持进行中。


下一阶段已接入原生接触 V2 与 BFT 网络 V2 的消息内检查点前缀共享：只引用同一消息中已出现的准确前置检查点，重建完整 Evidence 后继续原生签名、终局、时代、所有者、守恒和永久导入核验。完整本地 Evidence/Journal 序列化与签名消息不变；BFT 提案/终局消息体仍完整。原生打包命令先核验逻辑信封，接收/冷启动核验返回完整原生证据供 Python 同步，排队命令不扣款。3 MiB 物理载荷和 8 MiB/256 块/64 检查点逻辑边界不提高，旧 V1 载荷拒绝且无回退，需要新签无价值 fixture。首轮接触测试 8 通过/1 失败是测试重投递仍编码旧格式；源码片段与日志保留后改用真实当前载荷。首轮完整原生回归 121 通过/1 失败，是新 BFT 成本测试未经测量地要求至少减半；改为验证准确前缀、完整冷核验和实际字节减少，并记录真实成本，不作任意倍数承诺。最终冻结/进程/新签往返与完整故障资格尚待结果；真正长期执行、永久索引/紧凑状态证明、独立最新锚和物理资格仍未完成。

The first complete 244-file carriage freeze passes all 122 native tests but strict clippy rejects an explicit loop counter in the expansion-limit test. The full frozen source and logs remain retained; the test now uses an explicit height range without relaxing bounds or warnings. Final source qualification is pending, with no process/cycle/fault pass transferred from the first freeze.


最终紧凑证据运输候选的 244 文件源码 `b49b62072387b63720c64edc324788884ca117c45147166f69f2a9583ca692f0`、原生实现 `e213d670da01c99ea34706a15b1f241d3bf5bbd137ca95d107f5a9b5841d6918` 已冻结重建，122 项原生、57 项进程、85 项重新运行的运输检查及严格静态检查通过。新签无价值 fixture 的完整三地区往返通过，净额 96/91/86、十五次守恒和地区四副本高度 7/4/4；单独周期冷核验与十二份账本新目录恢复通过，私有原件和冻结源码不变。完整新有限故障配置正在运行，尚无终端结果；修订 23 未发布，不能沿用修订 22 或首份冻结源码的资格。首份完整冻结的严格检查失败和两份较早原生源码片段/测试失败日志都保留。3 MiB 物理载荷、8 MiB/256 块/64 检查点原生逻辑边界及签名消息体不改变；真正长期执行、紧凑状态证明、永久索引、独立最新锚、掉电/跨设备和物理资格保持未完成。


最终紧凑证据运输源码的[完整新有限故障配置](operations/evidence/regional-native-carriage-final-fresh-fault-20261002.json)在 560.168 秒通过并正常退出，原净额 9 在比邻星高度 10 唯一导入、12 成熟；最终地区各四副本高度地球 13、比邻星 12、仙女座 13，所有自建节点已停止，封存周期原件不变。[单独故障冷核验](operations/evidence/regional-native-carriage-final-fault-cold-20261002.json)完成十二份原生与四份原输出核验，认证 1,674 条 BFT 信封及 3,827 份运输档案，私有文件不变。[故障账本新目录恢复](operations/evidence/regional-native-carriage-final-fault-fresh-target-audit-20261002.json)十二份完整原生重放、准确另存头、状态/永久导入/事故及每份保留字节一致；加上周期共 24 份私有账本档案与恢复通过，源文件与冻结源码不变。不恢复签名者、钱包或调用者保管状态，生成档案不公开。最终 122 项原生、57 项进程、85 项运输重新运行及严格检查通过，旧失败来源/日志保留。消息内前缀共享减少重复载荷，原生完整认证、签名消息体及原边界保持；真正长期执行、紧凑状态证明、永久索引扩展、独立最新锚、掉电/跨设备及物理资格仍未完成。修订 23 公开复现包正在整理，尚未宣称远端发布。


[修订 23 准确源码与复现证据](https://github.com/RunlaiDeng/rldcoin-genesis/tree/1ed5cc11598b11e2d5d38b12fedff33b39ba0a4b/research/2026-10-02/regional-native-proof-carriage-v23)已公开，提交 `1ed5cc11598b11e2d5d38b12fedff33b39ba0a4b`；[远端核验](operations/evidence/regional-native-carriage-v23-publication-verification-20261002.json)确认 main 指向该提交、全部 58 个变更文件逐字节相同。57 文件复现包含完整最终及首份失败的 244 文件源码、两份原生源码片段、失败日志与准确检查/周期/故障/恢复报告。全部四个归档仅包含已审查源码，生成私有账本/密钥/钱包/签名者/调用者/TLS/运输保管材料未公开。独立英文官网仍固定修订 21 的历史复现入口，本轮未修改网站或发论坛消息。演练进程已全部停止，私有原件保留，目标继续推进长期原生执行和紧凑状态证明；跨主机、独立最新锚、掉电、跨设备保管、真实物理路线及全部 I1–I12 仍未完成。


新状态证明候选已将原生块/检查点状态根接入有序输出、导出和永久导入索引及发行/收到总量承诺。成员证明绑定准确记录和位置；不存在证明要求完整认证的相邻键或准确首尾边界。原生命令必须先完整重放调用者指定的认证检查点，并绑定记录类别与键；历史成员不表示当前可花，证明不导入、不签名、不扣款。六项新增回归验证篡改、范围/路径/类别/计数/容量拒绝以及真实所有者导出、已消费导入和冷重放。第一份候选全套 128 原生测试通过，但严格检查拒绝两项代码问题；准确原生源码片段和日志保留，已修正为间接分配的证明成员及原生整除检查，严格检查通过。4,096 条合成记录的不存在证明样本为 2,683 字节，对比完整合成状态 860,228 字节；这是索引形状/字节成本观察，不是发行或长期历史资格。源码改变后需要全新 fixture 创世/币种，最终冻结、真实进程、新签往返和完整故障核验仍待完成。当前生成证明仍重建有界整表，完整 Evidence 和原生历史仍必需；未提高 4,096 索引及 256 块/64 检查点/8 MiB 等边界，不宣称增量永久索引、紧凑完整远程价值授权或长期执行完成。


最终状态证明候选的 247 文件源码 `f0586e230a2f6f3b3cd13187d214c9c3a0c9acc5aa396ce2036e8ad7e51472ab`、新原生实现 `df0a2c8f1faf93273a9be0212021575879a1f01cc39b0c614ae1031600b4281f` 已冻结重建；[最终检查](operations/evidence/regional-native-state-proof-final-frozen-checks-20261002.json)确认 128 项原生、59 项真实进程/历史/状态证明检查与严格静态检查通过。两项新增真实命令验证指定检查点/键/类别、篡改与未知检查点拒绝，以及真实所有者跨区付款的已消费原输出不存在证明、永久导入成员证明、新私有档案恢复后完整原生核验和再次导入拒绝；查询/拒绝不改变原私有文件。85 项运输检查来自修订 23 精确未变的运输字节，本轮未重跑，不冒称新运行。当前全新签署的 fixture 三地区往返已启动，完整终端结果、单独冷核验、新目录恢复及完整新故障配置仍待完成；状态证明候选未公开，修订 23 资格不沿用。原生完整历史/Evidence 和原边界不变，增量永久索引、紧凑完整远程授权及真正长期执行仍未完成。


最终状态证明源码的[全新 fixture 三地区往返](operations/evidence/regional-native-state-proof-final-fresh-cycle-20261002.json)已正常通过：净额 96/91/86、十五次守恒、地区各四副本高度 7/4/4，远端继续转出与返回时全部地球节点停机，控制器投票/携带付款证明/安装检查点均为零。[单独周期冷核验](operations/evidence/regional-native-state-proof-final-cycle-cold-20261002.json)及[十二份新目录账本恢复](operations/evidence/regional-native-state-proof-final-cycle-fresh-target-audit-20261002.json)通过，私有原件和冻结源码不变。当前独立私有复制目录的完整新有限故障配置已开始；尚无最终故障资格或修订 24 公开发布结果。签名者、钱包、调用者和运输/TLS 保管状态不随账本恢复，生成档案不公开；真正长期执行、增量永久索引、完整紧凑远程授权、独立最新锚、掉电/跨设备及物理路线仍未完成。


最终状态证明源码的[完整新有限故障配置](operations/evidence/regional-native-state-proof-final-fresh-fault-20261002.json)已在 539.07 秒正常通过：原净额 9 在比邻星高度 11 唯一导入、13 成熟；最终地区四副本高度地球 13、比邻星 13、仙女座 14，所有自建节点停止，封存原周期不变。[单独故障冷核验](operations/evidence/regional-native-state-proof-final-fault-cold-20261002.json)认证十二份原生状态、四份原输出、1,699 条 BFT 信封和 3,861 份运输档案，私有文件不变；[十二份故障账本新目录恢复](operations/evidence/regional-native-state-proof-final-fault-fresh-target-audit-20261002.json)完整原生重放、准确另存头、全部状态/永久导入/事故及保留字节一致，源文件与冻结源码不变。加上周期共 24 份私有账本档案/恢复通过；不恢复签名者、钱包、调用者及运输/TLS 保管状态，生成档案不公开。最终 128 原生/59 进程及严格检查通过，85 运输来自准确未变字节的既有运行、本轮未重跑。首次 128 原生通过但严格检查失败的原生源码片段/日志保留，准确 scope 不冒称完整 workspace 冻结。只读诊断曾观察到单个比邻星副本的导入和锁占用未知状态；诊断未改变演练参数或构建共识/付款证明，完整结果来自正常终端通过及单独冷核验。公开复现包正在核查，修订 24 尚未宣称远端发布；真正长期执行、增量永久索引、完整紧凑远程授权、独立最新锚、掉电/跨设备与物理资格仍未完成。


[修订 24 原生状态记录证明准确源码与复现证据](https://github.com/RunlaiDeng/rldcoin-genesis/tree/e4cebd7e3d60c2e1edd4ed06ada6abeb69db9800/research/2026-10-02/regional-native-state-proofs-v24)已公开，提交 `e4cebd7e3d60c2e1edd4ed06ada6abeb69db9800`；[远端核验](operations/evidence/regional-native-state-proofs-v24-publication-verification-20261002.json)确认 main 指向该提交、全部 56 个变更文件逐字节相同，公开工作区干净。包包含准确 247 文件源码、31 文件原生源码片段、保留日志和最终 128 原生/59 进程/完整新往返/539.07 秒故障/冷核验/24 份私有恢复记录。两份原始测试日志保留末尾空行，引起通用空白检查提示；准确核对原日志（仅声明的工作区路径脱敏）后，源码与文档范围检查通过，没有删改日志字节或放宽原生严格检查。全部生成的私有账本档案、密钥、钱包、签名者、调用者、mesh/TLS 和运输保管状态均未公开，全部演练进程停止。独立英文官网仍保留修订 21 固定历史入口，本轮未改网站或发论坛消息。新状态根及成员/不存在证明是长期历史的基础，完整原生 Evidence 与历史仍必需；下一步推进有界活动历史与增量永久索引，不能仅提高 256 块/64 检查点/4,096 索引边界。20 万块时代、完整紧凑远程价值授权、独立最新锚、掉电、跨设备保管、独立运营及真实物理路线保持未完成，目标继续。


已加入单独的原生档案流式重放候选：从调用者固定的新签 fixture 创世逐块执行，普通节点与游标共用所有者/守恒/导入/发行内核，不能从序列化缓存余额启动。初步五项聚焦检查中，1,032 块、1,024 次真实签名付款、净额 59 的延迟返回导入和重复导入拒绝样本已在冷重放得到相同结果，最多保留 256 个历史观察；最终冻结与命令行/完整回归仍待完成。命令只读核验私有档案和另存准确头，不采用账本或恢复签名，明确不处理事故隔离；初始一致 PoW 之外的 BFT/本地时代切换拒绝。普通存储/钱包/签名者/检查点的 256 块/64 快照、4,096 索引、8 MiB 逻辑及 256 MiB 档案边界不提高。首轮测试编译因不可用 uuid 测试引用失败，准确原生源码片段和日志保留，改用既有唯一测试目录生成器后通过原四项测试。真正普通节点长期运行、增量永久索引、20 万块时代和独立资格仍未完成。

五项流式聚焦检查通过，额外验证私有权限/链接、损坏格式、8 MiB 记录和 256 MiB 档案容量拒绝，拒绝保留原字节。严格检查发现新 Record 的较大枚举字段，准确源码片段与日志保留后改为间接分配 Block；序列化和原生规则不变，严格检查通过。最终源码冻结、全部原生回归、真实命令行核验和新签无价值三地区往返即将运行，不沿用旧源码资格。


最终流式档案重放候选的 250 文件源码 `1593d355e4bf94514ce596c06aaaae0c58b0464fe1e8ecb788f646d594073b53`、原生实现 `601b7153fe673292ede3c23ced9f765d0e4cd572532f0e9563f3cf01664cafe8` 已冻结重建。[133 项原生和 59 项进程检查](operations/evidence/regional-native-stream-replay-final-frozen-checks-20261002.json)与严格检查通过；[长档案样本](operations/evidence/regional-native-stream-replay-final-stream-sample-20261002.json)重放 1,032 块、1,024 次真实所有者签名付款，私有档案 1,338,021 字节，只保留 256 个历史观察，延迟返回导入净额 59、永久重复导入拒绝与冷重放一致，真实命令行入口亦通过。[规则正文对照](operations/evidence/regional-native-stream-replay-final-kernel-review-20261002.json)确认共用执行规则仅替换已推导上下文字段。原生测试终端通过后，汇总控制器变量出错；[恢复记录](operations/evidence/regional-native-stream-replay-final-controller-resume-20261002.json)绑定成功日志和保留脚本，源码不变且已通过测试不重复。

[新签 fixture 三地区往返](operations/evidence/regional-native-stream-replay-final-fresh-cycle-20261002.json)正常通过净额 96/91/86、十五次守恒、地区各四副本高度 7/4/4；远端继续转出与返回时地球全停，控制器投票/携带证明/安装检查点均为零。[单独冷核验](operations/evidence/regional-native-stream-replay-final-cycle-cold-20261002.json)及[十二份私有账本新目录恢复](operations/evidence/regional-native-stream-replay-final-cycle-fresh-target-audit-20261002.json)通过，全部演练进程停止，私有原件和冻结源码不变。本源码未重跑完整故障配置，不沿用修订 24 故障资格；85 项运输检查来自精确未变源码的既有记录，本轮未重跑。当前长重放是只读初始一致 PoW 档案核验，不处理事故隔离、不采用账本、不恢复签名，普通节点/快照/BFT/钱包仍保留原历史边界。公开修订 25 复现包正在核验，尚未宣称远端发布；普通节点有界长期运行、新长期终局、增量永久索引、20 万块时代、独立最新锚/档案及物理资格仍未完成。


[修订 25 有界原生档案重放源码与复现记录](https://github.com/RunlaiDeng/rldcoin-genesis/tree/362fa5f70f3424f3c4006dd93e9d25523eeefae4/research/2026-10-02/regional-native-stream-replay-v25)已公开，提交 `362fa5f70f3424f3c4006dd93e9d25523eeefae4`；[远端核验](operations/evidence/regional-native-stream-replay-v25-publication-verification-20261002.json)确认 main 指向该提交、全部 53 文件逐字节一致，公开工作区干净。[发布清单审查](operations/evidence/regional-native-stream-replay-final-package-review-20261002.json)确认完整 250 文件源码和两个原生源码片段归档均按明确清单提交，校验和/暂存字节/空白检查通过；原始失败日志保留在审查归档内，仅替换工作区路径。133 原生/59 进程与严格检查、1,032 块/1,024 次实际所有者付款长重放及真实 CLI、新 fixture 往返和十二份私有恢复通过；冷核验认证十二份原生/十二份原输出、647 条 BFT 信封和 1,456 运输档案。源码与私有原件不变，演练节点全部停止，生成私有档案/密钥/签名者/钱包/调用者/mesh/TLS/运输保管状态未公开。完整故障配置本源码未重跑，不沿用修订 24 结果；85 运输检查亦未在本轮重跑。独立英文官网仍固定修订 21 历史入口，论坛未发消息。本轮长重放只读、不处理事故隔离、不采用账本或恢复签名，普通节点历史/BFT/快照及原边界保持。下一步继续普通节点有界活动历史、新长期终局和永久索引；20 万块时代、独立最新锚/档案、跨主机、掉电/跨设备与真实物理/独立资格仍未完成，目标继续。


继续处理实际长期原生运行的检查点依赖：新增明确签署的分段一致 profile，四名验证者一致批准，Snapshot.base 只能等于已签署的 previous；从已完整原生执行的前置证书复制状态后逐块核验新段，初段必须从创世重放，没有发送者余额/缓存状态入口。普通 Chain 可在认证后清空有界活动段，完整签名块与证明仍在原生日志保留；旧一致/BFT 门槛和完整前缀/256 块边界不改变，新 profile 不做时代切换。签名者持久锁检查准确前置头/首块高度父级，钱包/收据用完整原生日志查历史高度，避免活动向量短缩导致越界；事故按相同绝对高度比较，不能将不重叠的兼容段误报冲突。当前两项聚焦测试通过认证 1,032 高度/1,024 次真实付款、超 256 高度新建资金导出和继续转出/返回净额 78/59/49，创世冷核验一致，重复导入拒绝。135 项完整原生与严格检查、59 项既有进程检查通过；新真实普通节点测试已达到 275 高度，最终新目录恢复测试正在运行。测试最初固定到期高度 100、错误要求重复接触投递失败以及误用归档选项，准确源码/失败测试/日志/私有目录保留后修正，不放宽任何原生价值规则。总日志事件/8 MiB、64 快照、4,096 索引和 4,096 文件/256 MiB 总档案仍限制；尚未解决完整持久日志、BFT 长历史、增量永久索引或 20 万块发行时代资格。候选未冻结发布，不沿用修订 25 的新源码资格，目标继续。


Current segmented candidate verification completes 135 native tests, 59 existing process tests and one new ordinary-store process test, with strict clippy and checked release build. The new test passes at ordinary native height 275 after 267 real signed local payments, native persisted signer/wallet operations, post-256 newly created funds export/return (net 98), idempotent contact re-delivery, explicit duplicate-import refusal and exact private fresh-target ledger image recovery. The separate native value test passes 1,032 height / 1,024 signed payments and full cold genesis verification. Failed expiry/idempotence/archive-option fixture sources, logs and private directories remain retained. These results are current workspace checks, not a frozen-rebuild, autonomous twelve-node or new full-fault qualification; the candidate is not publicly published. Journal/evidence/archive bounds and whole persistent/BFT/beyond-era/independent/physical obligations remain open.


## 2026-10-02: active-epoch observation candidate and retained joint fault failures

The original V31 cycle remains qualified only within its published finite ground
scope. The first post-handoff full profile reached recipient maturity, then
failed on a controller native custody-read lock refusal. Its stopped source and
private stores remain unchanged. Explicit read-only exact-lock retries passed
13 controller boundary checks and a real native OS-lock release regression.
A separate fresh full profile passed the missing-leader successor at height 13
and native catchup, but timed out recipient maturity. Four cold native recipient
checks bind import height 18, required maturity 20 and terminal height 19; the
original net-9 output is retained but immature. Twelve compatible cold prefixes
conserve issued 300 = liquid 300 + transit 0. Neither failed profile is a pass,
and no resumed payment or raised bound can replace fresh full-profile evidence.

The active-epoch candidate exposes the exact native journal proof for the current
fully replayed chain epoch, distinct from merely verified known epoch evidence.
The companion still native-authenticates every complete incoming envelope and
synchronizes certified dependencies before any deduplication. Only exact complete
canonical bytes matching the native active proof can avoid redundant activation;
valid different quorum proof bytes retain the native activation path. This
changes native implementation identity and requires fresh signed no-value
fixtures, never migration of V31/failed state or value. Fresh full-cycle/fault,
independent custody/operations, physical links, long history and I1–I12 remain
open for this candidate. Website and forum remain unchanged in this work.
