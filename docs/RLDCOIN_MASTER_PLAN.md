# Rldcoin 主计划：人类跨星际点对点支付

最终目标与强制验收契约 · 对应 2026-10-04 已独立审查并冻结的最终白皮书（不显示文档版本号）。

**最终目标：让人类在地球、空间栖息地、飞船和遥远恒星地区持有同一种守恒货币，依靠所在地区的节点自行验证、收款和付款；远方长期断联时当地经济仍可运行；物理接触恢复后，价值能通过相邻地区渐进中继，到达任意已获授权的地区，再次支付、继续转出或返回起点。任何步骤都不以地球常在线、地球目录或地球逐笔批准为前提。**

**启动即中继：每个正常启动的完整网络节点必须在同一启动流程中默认启用发现、持久保管和有界转发，无需另起中继进程、中央登记或逐个配置远端节点；钱包客户端不等于完整网络节点。存在实际接触时，新节点可延伸可达地区、增加可用替代路径和独立提供的承载资源。节点数量本身不证明共识更安全、吞吐量增加或必然送达。**

这是一份约束未来实现的主计划。文档符合目标、候选代码通过地面检查、正式协议获得资格以及真实星际路线可用，是四种不同结论。**完成 A–G 地面阶段不足以完成本计划；I1–I12 全部是最终目标的强制条件，不能降为可选远景。**

**当前任务执行目标（2026-10-04 用户授权，最终定稿已冻结）：** 准确任务 `01a100ac-5340-7b13-b661-eedc397b003a` 按最终白皮书完成项目。以 I1–I12、S1–S18、R1–R24、正文内 A–G/N1–N10 与 P1–P8 形成可验证里程碑；优先当前已测关键路径，源码/fixture 单一负责人，复用仍有效精确绑定证据，按既有预算停止无效重试。不得把活动、测试数量、守恒但未成熟进口或文档完善当成完成；科学、独立保管、物理与资金约束按实际状态披露。官网出版不启动账本或主网。

**规范权威与冻结：** 英文[最终白皮书](https://rldcoin.com/whitepaper)为未上主网项目的设计权威；正文 SHA-256 `2ba62421583c60d0d35d295ff859eef558f2d372ea191d2a2dc828bb3e0b477b`，PDF SHA-256 `c59f9fe8e09e972b25c88626a1468298d9a16fc2343387412973df1829447e14`，审计提交 `5bf11e4b3637cd99b3a6ebbb8e9e90f7e3edd402`。本主计划及[实施验收映射](WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md)为可更新实施记录，不能修改冻结正文或降级验收。[冻结记录](WHITEPAPER_FREEZE_RECEIPT.json)及[公开记录](https://rldcoin.com/documents/rldcoin-whitepaper-freeze.json)绑定内容。未来缺陷另记、报告用户并停止相关不安全操作；正文修订须用户明确决定。协议/算法/密钥/时代升级、续证和重新资格仍必须实施。无编号的白皮书不等于无技术版本。

**一亿年连续性目标：** 支持未来人类跨星际点对点支付的一亿年愿景，表示持续跨代维护、算法迁移、媒体/档案更新、独立治理和重新资格的方向，不表示任一固定算法、密钥、设备或机构能保证一亿年安全。每个采用、路线及档案策略声明有限验证期限，失去真实性、授权、档案或永久接触可能使资产不可用；不因此增发、重置所有权或超时退款。当前 Ed25519 授权尚未实现后量子迁移。

## 1. 范围与实施状态

本文定义目标协议、实施顺序和强制验收。实现进度与部署资格单独维护在[当前状态](PLAN_STATUS.md)，不以计划或白皮书代替实际验收。

## 2. 支付含义与不可消除的约束

“点对点”表示所有者自己授权、收款人可独立验证，中继与目录不能代签、发币或裁定余额；它不排除当地矿工、验证者和异步中继。新地区先发现物理可接触邻居，再逐步了解远端网络；发现身份与货币准入分开。地球—比邻星—仙女座是三地区拓扑示例，绝非已建成路线或不受距离影响的连接。

“断联自治”是当地仍有满足其共识假设的通信、验证和安全资源，而远方地区完全不可达。它不表示同一区域内互不联系的两个收款人可以无条件接受同一可复制凭证。当地故障、签名者失联或安全预算不足必须如实阻止相关操作，不能制造终局。

当地分区与远方断联不同。缺少采用规则要求的终局 quorum 时，节点必须停止新终局以及依赖它的新导入和再出口，保留已有余额、请求与证据；未终局付款只能按披露的分叉风险呈现。恢复取决于实际当地通信、诚实参与和保管假设，不承诺所有分区中均可继续支付。白皮书第 5–9 节的 PoW、四签一致及六后继块成熟属于参考 profile；当前三取四 BFT 候选和未来地区采用各自精确签署规则，不自动转换阈值或继承该参数。

新价值证据不会超越因果光时到达；接触、容量与当地进度决定交付。安全不依赖一个有限远程延迟上界，活性则有条件：证据最终到达、授权仍可验证、当地账本能推进。永久隔离的出口可永久待处理。收款人验证来源后按当地规则取得可花余额，不等待返程回执或地球在线确认。任何贷款、垫付均为独立信用风险。

现有短握手、短 socket 等待及本地证书有效期的 pinned-TLS IPv4 实现仅是地面适配器。年级星际运输需要异步认证、真实接触及持久保管的独立实现和实测，不依赖即时应答、持续会话或全宇宙同步时钟；密钥/证书超出资格期限只阻止依赖它的新接受，不退款或删去已扣除价值证据。BPv7 名称和运输摘要不提供货币终局。

密码、硬件和档案只能在公开、可测试的资格期限内作保证。仙女座标签不能证明百万年密码安全或媒体寿命；超出验证期限的资产必须保留并显示“无法按现有策略验证”，不可假装成功或自动退款。

## 3. 同一货币、地区准入与守恒

货币身份由未来新签名起源创世及采用规则绑定，地区创世、地区节点身份和运输消息 ID 各有独立用途。默认目标保持 1 RLD = 10^24 runlai、总量上限 1000 亿 RLD、创世初始分配为零；起源发行参数须在新采用中精确签署，不能以软件安装或节点标签替代发行授权。

无常在线地球目录仍需要明确的离线信任。地区准入、验证者时代和规则变更必须从当地已采用货币根、准入权与终局策略携带有序认证授权链，绑定关闭历史及 Old/New 角色，保留历史终局、永久导入记录和独立签署/调用者锁。缺票、旧头、不完整过渡或未知策略时停止依赖操作；不得重置锁、降低阈值或另造创世处置已有价值。撤销和冲突只能随证据传播到达；未来独立治理及事故恢复授权仍需审查规格和对抗资格。

发行只发生在获授权的起源账本。所有新地区原生发行额度为零；导入不是挖出第二份 RLD。另行分配发行权必须先有版本化、互不重叠且全局守恒的额度协议，本计划不依赖该扩展。地区加入不要求联系地球在线服务器，但必须携带可离线验证的货币根、地区创世、规则、准入授权及终局信任链。自签名字和发现通告不能获得这些权力。

对同一货币的兼容已选历史，逐步核对 **I = U + E + T，I ≤ 总量上限**：I 是唯一发行量，U 是未花费输出（含未成熟/隔离输出，但排除已计入 E 或 T 的金额），E 是通道及明确费用储备，T 是选定源历史中所有已扣除、尚未在指定目的历史唯一入账的出口（包含未终局 pending debit）。三桶互斥，费用一次归属；只有终局覆盖的扣款可导入，未终局扣款孤立时由原子重放撤销该转换并恢复源输入，普通重组不能撤销已终局扣款。不可用或证据丢失不抹掉负债。已完成导入的历史出口、收据、祖先证明和永久去重记录不得重复计入余额。这是验证者对证据集合的守恒检验，不要求实时查询全宇宙余额。

## 4. 强制目标条件 I1–I12

下列编号与英文白皮书逐项对应。每项必须有版本化规则、适用故障模型、实际节点证据和独立复核；当前状态见第五节。没有实现、没有证据或超出证据范围，均不得标为完成。

| 编号 | 必须具备的能力 | 必须保留的验收证据 |
| --- | --- | --- |
| I1 货币与地区身份 | 同一货币根；地区创世、规则、授权及验证者时代可离线核验；无必需地球目录或在线逐笔批准；发现不授予账本、终局或发行权限。 | 未授权地区、自签标签、错货币根、错创世、旧规则和伪造准入全部拒绝；新地区从公开授权包启动。 |
| I2 当地断联自治 | 远方离线时已验证当地余额仍能收付、推进及重启；已持有且被有效终局覆盖的出口可按规则导入；缺失新证据只阻止依赖它的操作。 | 撤去所有远程源服务后，原生节点完整启动、实际签名付款、挖矿、重放恢复及新增证据安全安装；不用“最近 5 秒访问源端点”代替此条件。 |
| I3 发行守恒 | 任意地区、任意转移路径保持唯一发行上限与精确整数账；新地区零原生发行；金额拆分、合并、费用、找零、通道与待转移金额守恒。 | 每个状态转换及恢复点核对 I=U+E+T；拒绝复制储备、历史记录双计和多区重复发行。 |
| I4 任意已授权地区转移 | 每个地区均能作为源和目的；所有者授权、当地扣除、源出口终局、目标唯一导入依次执行；出口绑定准确目的创世、金额、收款人与规则版本。 | 至少三个实际原生地区账本、多个所有者、双向/多跳及多来源导入；错区、改金额/收款人、重复、乱序和不完整证明拒绝。 |
| I5 再出口与终局组合 | 导入可当地支付，亦可再次出口；出口必须终局覆盖其输入来源、导入及本地扣除；概率成熟不能冒充不可冲突的出口终局。 | 导入后重组、成熟前再出口、尚未终局出口、来源冲突及分叉恢复；资产谱系/依赖图可验证而不重复发行。 |
| I6 真正价值返程 | 返回起点是从当前持有地区发起的新出口与起点新导入；每一段 ID 和永久导入去重独立。源最初扣除不因收据或资产返程重新释放。 | 地球→比邻星→仙女座→地球的真实资产轨迹和循环重复攻击；收件回执对余额无效；丢失回执/到期绝不退款。 |
| I7 地区终局与信任演进 | 地区在当地完成终局，无跨恒星统一实时投票；明确容错、锁、视图、验证者时代、重配置和接触恢复规则；独立保管、冲突传播及依赖冻结。 | 独立参与者的少数故障/缺签、矛盾签名、分区、密钥轮换及恢复；保留已支付敞口。四把同控制者密钥不是独立 BFT，改阈值不是协议证明。 |
| I8 原生默认中继与因果运输 | 每个完整网络节点在正常启动的同一生命周期内默认启用认证发现、有界持久转交他人支付证据和重启续传，无需另起进程或中央登记；逐步加入有用节点扩展可达地区与替代路径；保管、删除、容量准入及正反向路由分开。 | N1–N10；原生默认启用及真实适配；逐个加入节点扩展可达地区、断掉原路径后替代路线实际交付、满载拒收保全已接管证据；停机、重启、非对称接触、乱序和恶意邻居。节点数不等于安全，真实航路另证。 |
| I9 可独立判断的付款状态 | 身份发现、候选路由、接触观测、运输收件、账本导入、成熟可花、出口终局及源获知回执分别呈现；收款人用当地节点和签名校验。 | 钱包/节点一致显示精确身份、金额、依赖、等待与未知冲突状态；过期显示数据不作为签名前资格；伪造回执不能记账。 |
| I10 长期存储与恢复 | 有界活动历史/归档、可验证快照或证明、永久去重承诺、终局及签名锁防回滚、多份独立档案和可量化恢复成本。 | 超过首个 20 万块发行时代及声明容量的实际恢复；损坏/缺档、旧备份、快照伪造、去重遗失及磁盘满载均不能创造可花资产。 |
| I11 长期密码与撤销 | 认证并版本化算法/参数套件、规范编码、用途域、密钥角色/时代及有限验证期限；独立审查后量子授权与运输迁移，防降级、双签过渡/退役、历史续证、信任锚恢复及在途出口策略。 | 在旧授权仍可信时迁移余额和通道；双签策略必须同时验证同一意图，旧或新任一可通过仍保留弱路径。测试迟到撤销、失联、旧备份、丢钥/丢档和冲突升级；在旧签名/hash 失效前续证，必要时重新哈希原始对象，事后补签不能修复真实性。保留守恒、终局、调用者锁及永久导入去重。超期限证据保留但停止新接受；当前实现未满足此项，不宣称百万年或一亿年密码保证。 |
| I12 独立资格与持续服务 | 独立运营/密钥保管和外部安全复核；默认中继的存储/带宽、准入/保留及费用预算，启动节点不自动获得奖励或发币权；地区矿工、终局、中继、档案的资源与费用预算；普通用户支付/恢复体验与精确发布采用。 | 独立实测报告、负载/攻击及恢复记录、未解决出口与亏空、跨设备钱包恢复、防回滚；物理路线能力/寿命只按其实际验证范围宣传。 |

## 5. 目标协议的数据与状态机

每个地区采用包必须绑定货币根、地区创世、规则与实现承诺、当地终局协议/验证者时代、准入授权及升级历史；能从本地已信任根和携带证据验证，不依赖常在线中央目录。目录与中继最多提供候选资料，错误资料可被任何完整验证者拒绝。

每个目标出口必须绑定版本与域、货币根、源/目的创世、源规则及终局时代、输入及其起源/依赖、当地扣除、输出金额/收款人、费用/找零规则和不可碰撞唯一 ID。证明包含或可重建有效源历史、出口归属与终局；接收方在自己的已采用信任范围内验证全部依赖。不完整、未知时代或矛盾证据只进入待验证/隔离区。具体编码、谱系压缩和接触更新安装须先形成版本化规格与可执行反例检查，再改变共识。

```text
当地可花资产
  → 所有者签署出口 → 本地扣除 → 当地终局覆盖输入与扣除
  → 异步运输历史/证明 → 指定目的完整验证 → 唯一导入
  → 当地成熟可花 → 当地付款，或新的当地扣除与终局出口
  → 下一个地区；返回起点也执行一次新的出口/导入
```

源出口终局尚未形成时，目的不得导入。导入后仅达到六块概率成熟时，可按当地规则支付，但对外出口需要认可的当地终局保护依赖历史；不能用目的普通确认把源保护资产转成可回滚的对外新资产。已认可终局必须持久约束选链、恢复与后继终局，签名锁同样持久。

**禁止超时退款。** 出口被源扣除后，失去收件/账本回执、队列到期或永久断联都不解锁。取消不是本目标的必要功能，默认禁用；若未来加入，必须先有目的区永久消耗出口 ID、排除已有和未来导入的已认可终局，再由源区验证并采用。查询未导入、旧的不包含证明、重发或运营者承诺均不足。

终局故障不能靠“停止所有星系”修复。发现有效矛盾时保留证据，按来源依赖范围隔离已有本地余额及支付、找零、费用、通道、拆分/合并的全部后代，禁止它们新的本地支出/进口/再出口并传播；已经断联的地区可能尚未知情，已有支出不能保证追回。事故处置须披露敞口、隔离范围和补偿依据，不得偷偷增发。协议需明确何种证据允许恢复及谁有授权。



**必须落地的关键规则：** §6 整数 era 预算、商/余数分配与末期1 runlai；§7 强制挑战储备、c+W截止和同序号冲突；S2 事前签明每种authority/quorum/scope/conflict/failclosed；S7 根化有限因果DAG（拒自证环并界定解压、depth/fanout、重复祖先、签名/CPU/RAM/disk/恢复索引）；S8/S9 混合输出全污染隔离；S11 存活独立单调新鲜度见证，缺证据旧备份只读拒签/拒支出；S13 接纳期限/合法副本回收与owner/archive货币证据保留分开；§11–12旧算法历史重放与新授权分开并在真实性丧失前迁移/续证；S17两独立验证实现、崩溃原子性及供应链审查。A–G/N1–N10以冻结白皮书§20内定义为准，外部研究计划不得改变其义务。详见逐条实施验收映射。

## 6. 实施顺序与退出条件

1. **冻结规格。** 发布上述身份、守恒、终局、任意地区价值状态机与升级规则，建立多金额/多所有者的可执行模型，验证循环、分叉与延迟撤销反例。退出条件：I1/I3–I7 的规则没有未定义状态，独立审查能重现反例与结论。
2. **实现通用地区账本。** 多来源验证、目的区本地终局/再出口、价值返程与离线启动；接触更新验证/安装和冲突依赖隔离；每次恢复重算状态与永久去重。退出条件：三个实际原生账本完成第七节，无远程新鲜度替代自治。
3. **原生节点与钱包集成。** 渐进邻居发现、可替换真实接触承载、持久队列自动向验证器提交候选；钱包从当地证据显示支付阶段。退出条件：I8/I9 与 N1–N10 全部通过集成及资源拒绝测试。
4. **长期与密码资格。** 活动/归档分层、独立恢复、防回滚、版本化算法/参数和用途域、后量子授权与运输迁移、双签/退役、历史证据失效前续认证、信任锚恢复及时代轮换；量化可支持期限、容量、验证时间与资金预算。退出条件：I10/I11 的声明范围有实测与独立复核，超范围安全失败。
5. **独立运营与新主网采用。** 精确新签名零发行创世、公开源码和可复现包；独立节点/密钥保管与钱包持续支付、资源攻击和事故恢复验收。退出条件：当前版本达到 A–G 与 I1–I12 的地面协议资格；再按实际物理路线逐条开展运行资格。

各地区的块间隔、成熟和挑战窗口按当地传播、验证、持久化与攻击模型选定并版本化签署；不得把跨恒星光时、加速逻辑时间或单次地面收据时延直接作为全地区承诺。当地通道的参与者/监护需在当地挑战窗口内可接触账本，不能把短通道争议期用于多年星际运输。

## 7. 最低端到端验收矩阵

| 场景 | 实际操作与通过标准 |
| --- | --- |
| 三地区无地球中心 | 三个独立原生地区账本、至少两个所有者，仅配置相邻接触。远端从公开授权包启动；撤去地球目录与在线批准后发现、中继和已验证当地付款继续。 |
| 多年逻辑断联 | 完全停止远程源/地球服务；完整 CLI 启动、实际本地出块、成熟余额收付和重启一致；固定证据覆盖的新进口可处理，未覆盖的保持待验证。加速逻辑时间不冒充多年物理老化。 |
| 再出口与真正返程 | 地球→比邻星→仙女座→地球；地球断联时当地付款和前两段向前流转继续，返回地球的第三段等待接触；地球恢复后精确一次导入新出口，初始扣除永不重新解锁。 |
| 多输入/金额/来源 | 金额拆分、合并、找零、费用、通道、多个源和多条循环；逐步守恒，错货币根/收款人/目的地区/依赖或重复祖先不制造余额。 |
| 重组与终局故障 | 导入前/后、成熟后/再出口前的重组；无终局出口拒绝；深分叉不得越过锁；认证冲突、少数故障、时代更替、旧锁恢复与缺签有明确安全/停顿结果。 |
| 运输与永久隔离 | 正反向接触非对称、短接触、满载、重复/乱序、掉电/损坏、恶意邻居与永不返回回执；容量拒绝可恢复，所有失败均不退款或增发。 |
| 长期密钥/历史 | 在途轮换、撤销延迟、验证期限外证据、密码降级、旧钱包备份和永久去重遗失；独立档案恢复相同根，未知或损坏证据不能通过。 |
| 独立运行与真实范围 | 分属独立控制者的节点与终局保管；声明规模下持续负载、外部复核、跨设备用户恢复和成本预算；真实承载/航路的接触、延迟、容量、故障、期限单独记录。 |

报告须列出具体创世/规则/源码、硬件、所有者、联系轨迹、负载、故障、持续时间和失败样本；分别报告当地可花时间与源获知到账时间，记录未解决出口数量/年龄和已经支付敞口。通过有限测试不构成所有执行的数学安全证明。

## 8. A–G 与最终完成判定

| 地面基础阶段 | 保留的必需验收 |
| --- | --- |
| A 授权与身份 | 创世、签名规则、零初始发行、货币根与源码承诺一致；测试资产和密钥不能获得正式价值或授权。 |
| B 工作与金额 | 跨平台重算采用共识下的实际出块/终局资格（PoW时核算实际工作）、精确整数发行、费用、成熟、普通付款、防双花、重组和恢复。 |
| C 节点与参与者 | 可复现公开节点包、持久同步、重启一致、受限 API 与参与者实际运行；控制者如实披露。 |
| D 发布切换 | 精确签名源码/工件、密钥与锁独立恢复、公开哈希、服务/钱包身份核对；不复用旧授权。 |
| E 区域内支付 | 当地成熟币及已注资通道、单方退出/挑战、实际结算、断网/重组/恢复、普通用户持续收付；速度指标只适用声明当地环境。 |
| F 跨区异步结算 | 源扣除终局、完整证明、唯一导入及成熟、双向重放与状态区分；断联、乱序、锁恢复和冲突处置不制造资产。 |
| G 开放与长期运行 | 独立运营/保管、外部审查、容量/归档/资源攻击和长期恢复；物理路线的证据与地面协议资格分开。 |

**文档目标对齐（DOC_ALIGNED）：** 主计划与白皮书完整包含同一组 I1–I12，不把强制能力写为任选研究，验收及限制无冲突。

**协议资格（PROTOCOL_QUALIFIED）：** 某个精确版本通过 A–G 与全部 I1–I12 的适用地面/独立验收，并发布其故障假设、容量、密码/归档期限和剩余风险。仅一跳进口、抽象模型、原型运输或同控制者测试不能达标。

**地球正式发布（EARTH_RELEASE_AUTHORIZED）：** 精确签名零初始发行创世与发布采用可独立核验，且实际服务与钱包核验通过。文档不能替代规则采用或密钥授权。

**真实路线资格（PHYSICAL_ROUTE_QUALIFIED）：** 每条所宣传航路有真实承载、接触、控制者、容量、故障和运行期限证据。地面协议资格可以先取得，但不可据此称跨星际服务已上线；任意未来航路和无限年代的可用性不能从有限资格外推。

最终目标始终是持续、守恒、当地自治、任意已授权地区之间可再次转移的支付网络。某版本与某真实路线可在其公开资格范围内达到该目标；无限空间、无限时间和未知未来密码不能以勾选清单宣称已经证明。

**用户授权的正文编辑修订（2026-10-04）：** 白皮书写需要实现的能力，开发和发布状态移至独立记录；全部 I/S/R/A–G/N/P 验收要求保持。此次编辑不授予协议、物理路线或主网资格，不因正文编辑重跑已有有效证据或打断当前故障范围。旧冻结记录由官网 Git 前驱及新记录内 predecessor 哈希保留。

## 2026-10-05 新目录继续转出验收检查点

原线程goal已恢复active，项目命令显式新workdir；持久cwd仍旧。新驱动
`d8c2af0d...` 默认入口实际执行当前companion，Native87/Python153/Core来源未改。
一次180秒/1次的全新范围在136.378秒完整通过：Native准备E4/P3；普通P
使用原99输入在4认证gross98出口、5停止；四新A在4进口net97、6成熟可花。
494完整信封逐份Native检查、独立caller/owner头及9个正常退出核验；
I=U=10^30、E=T=0。[准确终态/源绑定/下一返程](operations/evidence/regional-native-paged-onward-fresh-outcome-20261005.json)。
这证明当前来源的有限继续转出行为；初始E到P仍为controller准备，完整ordinary
循环/返程/完整fault/2016/long-history/独立保管/PQ/physical仍OPEN。旧180.529秒
失败原件保留且未打开；旧价值strict仍独立OPEN，不由本范围替代。
下一一次300秒/1次验证原A97→return96→原E净95、真实导入成熟和全cold，保留
原E100扣款及全部负债；起源实际发行/不同高度兼容前缀须按完整Native重放计数。
旧goal正文前继哈希已在本原线程报告；实施按当前AGENTS/冻结receipt，不自主改
goal目标正文、白皮书/PDF/官网。

## 2026-10-05 返程驱动反例与封存检查点

原返程300秒一次范围在14.512秒失败，原97首次签96并typed入队时无debit；
源驱动将固定attempt3秒误改为6秒而拒绝正常观察。四Service −15/0/0/0，已无
活动自有节点；目的阶段未启动、实际后续出口/成熟/full cold未证明。原currency及
1783私有文件完整封存，不打开其Native/Runtime，不重签/退款/恢复/替代请求。
[准确失败与下一行为判别](operations/evidence/regional-native-paged-return-outcome-20261005.json)。
独立固定传输约束将2worker/3秒attempt/0.2秒lock与高度改写分离；一次20秒反例
实际0.456秒，两项回归exit0，三真实停止观察旧断言拒绝、新合同接受；改变/缺字段/
错误类型拒绝。私有字节不变、无Native调用/网络，不能提供返程或fault资格。
下一范围须先审查六阶段驱动，使用全新零分配货币及全部新保管；空E3仅前缀准备，
三个出口均普通Runtime，完整E100→P99→A97→原E95及所有头/信封/实际发行cold。
一次原600秒/1次，六阶段27Service启动、最高5，原60秒轮/每区全范围24新增高度
（E27/P24/A24绝对上限）/成熟/三取四/全部容量保持；首实际失败/完整判别/预算
退出，不延长失败300或恢复旧余额。旧136.378秒历史onward仍有效，旧失败及
VALUE-STRICT-01/完整fault/2016/source66/post64/独立/PQ/physical保持OPEN。
旧goal正文前继哈希继续待父线程修正引用；规范按AGENTS/receipt当前哈希和全部
S1–S18/R1–R24/I1–I12/A–G/N1–N10/P1–P8，冻结正文/PDF/官网不改。

## 2026-10-05 普通全闭环600秒失败与停止谓词反例

一次原600秒scope实际600.666秒预算终止，**整范围未通过**。全新零分配currency，
E空3仅准备；普通E100→P99在85.598秒完整成熟/cold，四P5；普通P98→A97在
259.833秒完整成熟/cold，四A7。原A97只签96，四A9实际认证原输入消费及返程出口，
356完整信封/full Native/owner/caller cold。前五阶段累计1368完整信封Native核验；
最后原E live观察为11且import/spendable true（原import8/mature10）；这不是最终
停止高度、完整cold或三地区最终守恒证明。末段仍等待所有允许运输错误同时为空；
600秒耗尽，前22Service clean exit、最后5为−9，当前自有进程0。准确wholecurrency
5722私有文件封存，不打开Native/Runtime、不重签/退款/恢复或替代请求。
[准确终态/源绑定/下一成本判别](operations/evidence/regional-paged-ordinary-cycle-contract-v2-outcome-20261005.json)。

0.012秒semantic AST/兼容前缀review通过；最初静态substring guard把
`recovered_exact_retry=False`误作recover call而失败，原件保留，未启动fixture。
一次20秒只读停止反例实际2.815秒：原Service日志约553.691秒已观察四目的成熟/
无pending及原source只读，但允许运输重试非空；旧全局silent谓词仍false，新
模块只允许请求干净停止并保留全部错误，不能通过账本/签署/保管或跳过full cold。
三回归exit0：Native/未知错误拒绝，未知观察/pending/未成熟/错intent/隔离不可停止。
独立候选将预算后的近零wait改为原bounded总5秒cleanup，先signal已知Service、
超时才kill其owned group；qualification仍严格600秒。失败helper字节不改、候选
未启动；已证明多余silent条件，但不是唯一超时原因或下一600秒可完成证明。
[真实停止反例与严格拒绝](operations/evidence/regional-paged-cycle-stop-counter-20261005.json)。

已测stop→fullcold段分别3.298/9.618/13.177/18.702/27.758秒，最后是四A9，
共356信封；这些是阶段总wall，不是逐Native调用CPU分类。约553.7秒首次暖观察
仅余46.3秒，还需干净停止/五份完整cold/最终12Native及owner/receipt审计；不能
据controller谓词修复假设预算必够。下一完整cycle/fault预算当前0，先一次120秒/
1次无网络fresh Native成本判别，最短E6→P5→A3→E1并真实成熟，E7/P4/A4；
测完整local replay/open、独立头/owner/proof及四单份对原4-envelope/8MiB cold，
后置坏certificate/dependency必须拒绝。旧失败/全部bounds/原费用成熟票数不变。
若重复open成本实质成立，再实现explicit只读有界cold stream/aggregate：一次
Native OS锁/准确caller head/full genesis replay，每完整信封仍独立认证，原每帧
4/8MiB与512总数不变；无serialized cache authority。否则改独立原生成熟停止栅栏
或更小typed timing模型。首次失败/完成/120秒退出，不原样复跑、加预算或免认证。
VALUE-STRICT-01/完整cycle/完整fault/2016/source66/post64/独立/PQ/physical仍OPEN。


## 2026-10-05 原生因果冷核验成本与驱动读取修复

离线驱动读取首26.347秒失败封存；独立严格Native JSON读取修复及三回归后，
全新120秒范围27.816秒exit0：E7/P4/A4、三ledger/12voter-caller/三原owner，
完整因果进口成熟及I=U、坏后证书/缺依赖/第五份越界拒绝、私有字节未变。
四单份0.318651秒对原四份批量0.078273秒；小controller样本不替代普通完整周期、
故障、旧600.666秒失败或唯一成本诊断。下一explicit只读cold plan需独立最新头/
Native锁/full-genesis、每完整信封认证及incident拒绝；原4/8MiB/wire3MiB/总512
不变，一次300秒focused源码strict+一次120秒新来源fresh CLI，网络budget0。
goal active/持久旧cwd待修/显式新workdir；当前freeze及全部验收目标保持，旧goal
哈希引用已在本线程/动态记录报告，父线程传达未确认。VALUE-STRICT-01仍OPEN。
[详细结果和退出标准](operations/evidence/regional-native-causal-cold-cost-outcome-20261005.json)。


## 2026-10-05 固定头原生只读冷核验入口

来源89408f5a/implementation8a361699新增独立固定head只读cold plan；
六边界/四原batch/地区strict30.142秒及release build23.806秒通过。
首19.164秒类型编译、3.421秒驱动身份排序、121.752秒dev-budget失败均保持。
release全新120秒scope32.956秒完成E7/P4/A4因果成熟、原heads/owner字节检查；
八批32份0.388514秒对八次调用0.682524秒，512份完整重复信封5.181516秒，
后置坏证明/缺依赖/旧头/越界/变更输入拒绝。pending/坏incident CLI与真实已认证
未索引incident unit分别记录，不能互替；普通Runtime未采用、旧来源网络结果
不继承，全部完整目标和旧价值strict保持OPEN。下一明确外部head的停止适配器
一次120秒、网络budget0，不恢复失败currency。freeze/全部规范/active goal不变。
[完整范围及失败原件](operations/evidence/regional-native-cold-plan-outcome-20261005.json)。


## 2026-10-05 明确固定头的停止适配器

明确传入单独保留的latest head，先原生完整历史检查，再完整有序信封的pinned
计划；无head采样/adopt、Runtime构造、恢复或新签署。一次120秒2.961秒通过
8新+12原回归及5真实完整信封/59引用/12准确共享快照，坏后证书、缺依赖、
错误retained value、旧/零头及超前高度拒绝，原208文件/所有旧失败/freeze保持。
原生Source89/release未变；普通启动路径未采用pinned模式。新六阶段驱动0.038秒
静态审查通过、未启动；下一一次原600秒/60轮/每区24新增高度/成熟票数容量保持的
全新普通完整周期，仅明确保留的本机头观察，不宣称独立最新保护，fault budget0。
首失败/完整判别/预算退出；旧失败及旧价值strict和完整规范资格仍OPEN。
[准确scope和驱动审查](operations/evidence/regional-pinned-stopped-adapter-outcome-20261005.json)。


## 2026-10-05 来源89普通完整闭环有限通过

一次原600秒、全新签署零分配currency/all custody普通六阶段范围，实际510.455秒
exit0。E原100→P净99、P原98→A净97、A原96→E净95全部实际导入/两块成熟/
完整停止cold；最终四E9/四P6/四A8，全12Native兼容认证前缀、原独立voter/caller
及3owner原输入/头检查，旧收款准确消费，返程95仍可花。27Services全部exit0，
自有活动进程0。共1606份完整信封全认证（阶段合计，非1606 distinct负载资格）；
四E最终审计I=U=2.25×10^30、E=T=0，3出口/3永久进口/零pending。

Native89408f5a/implementation8a361699/release binarya45387fa，driver5e267b95/
outerf12f6bb7绑定；普通Runtime启动cold路径未改，停止后明确保存并读回本机head，
传入pinned完整计划。这仅为本机完整性观察，未证明独立最新保护/保管/物理链路。
原600/60/每区24新增高度/成熟票数容量不变；5050私有文件停止封存，旧全部失败及
成功私有pins/freeze/旧价值基线均未变。旧600.666/完整fault失败仍失败，不能替换。

只读旧fault入口反例一次20秒、实际0.009秒：准确旧driver条件要求E7/P4/A4及
旧格式/平面配置，当前E9/P6/A8及独立phase配置不满足；未执行Native/Runtime、
复制或恢复保管。禁止改报告高度/标签或legacy/joint recovery绕过。下一一次120秒
network0显式paged fault-scope模型，绑定本次完整源/保留head/原owner及12保管路径，
从实际height/ordered membership导出缺席leader gate，错source/head/profile/layout/
cap必须拒绝。首不符/完整判别/120秒退出；通过合同与反例之后才准备新的网络预算。
当前完整fault/2016/source66/长期/独立/PQ/physical及完整规范仍OPEN；
VALUE-STRICT-01两告警/120.019秒未通过，原触发/120诊断或300修复/无豁免标准保留，
本次未触旧库或实际构建阻塞，不重复已有strict。
[准确来源、终态、反例和下一判别](operations/evidence/regional-paged-ordinary-cycle-pinned-cold-v4-outcome-20261005.json)。


## 2026-10-05 停止范围模型及固定头原生预检接入

新增显式只读paged fault scope与preflight。模型一次120秒实际4.396秒exit0，
五机械边界/当前真实5050文件全清单与Native/Core171/Python/实际CLI/12头/原
3owner绑定；28错误源/头/成员/保管布局/旧profile/预算上限/pending/owner等拒绝。
缺席leader gate按原四成员key序，从E9/P6/A8推导分别13,10,11,12 /9,10,7,8 /
9,10,11,12，均是实际未来parent leader的后继，不是旧7/4/4固定门槛。

独立接入范围一次120秒实际6.060秒exit0：3新IO/拒绝/期限回归，12Native完整
固定头genesis replay与1真实旧非零头拒绝；只允许history-check --expected-head，
明确新project cwd/无私有stdin/单call<=30秒且总预算120。最后一份Native响应的
height/region/head/currency/fullreplay/独立最新/fixture/live错误均不释放部分成功。
从未调用status/bft-status/wallet-view/init/recovery，Native未打开signer/wallet
保管，未启动网络/复制/first-sign。原1606信封/custody/owner有效证据只在整5050
文件/全部源完全相同下复用，不重复长测。所有旧封存/freeze/旧价值基线未变。

这只完成范围选择及实际只读预检；普通Runtime/Native源码未改，新模块未替代
普通启动或故障驱动，保留本机头不是独立最新保护。原600/60/24新增高度/E27-P24-
A24/成熟票数/容量不变；完整fault/2016/source66/长期/独立/physical/PQ仍OPEN。
下一一次120秒network0/native0不可变fault launch-spec和错误权限/头/路径/配置
反例：明确新无价值setup与只读旧成功观察的边界，不复制或推进原停止保管作模板。
新genesis/custody须独立setup/Native验收后才准备网络预算；首不符/完整判别/预算退出。
不为Finder结案展开清理或测试。goal active/显式新workdir/冻结规范及旧goal哈希引用
待协调保持；VALUE-STRICT-01独立OPEN，原120诊断/300修复/无豁免标准不改。
[实现、接入验收及下一范围](operations/evidence/regional-paged-fault-preflight-outcome-20261005.json)。


## 2026-10-05 完整故障启动配置与实际资金前置反例

新增不可变四阶段48配置：缺席Earth0且双向E/P断联（11节点）、原离线节点追赶、
恢复后原export唯一导入/成熟、无钥排空及全cold（均12节点）。完整scope保留当地
付款、非零轮缺席leader证书、离线Native/voter/caller字节不变、真实TLS拒绝尝试、
原请求/debit/import/终态守恒；只描述新无价值setup，不复制旧5050文件或失败货币。
两个透明故障relay端口保留邻居身份/端到端TLS pin；无钥用不存在的key路径，
实际钥匙文件/独立保管和头不改。原600stage/60round/24新增/E27-P24-A24/成熟票数/
容量/5秒cleanup保持；当前配置字节本身不授予Native/network/signing权限。

首次once120审查3.406秒失败，现有venv Python标准leaf symlink被路径规则拒绝；
Native/fixture/network0，五机械回归通过但整范围未通过。原source/test确切字节
已按原stage SHA恢复保留到独立私有source-only目录，原helper/controller/报告不改。
窄修正固定实际解释器SHA、保留venv执行路径，不放宽parent/custody/config/fixture
symlink规则；新once120实际4.177秒exit0：6回归与真实旧source审查，48配置完整，
各phase11/12/12/12，synthetic plannedE8/P5/A5及gate9明确不代表实际Native准备。

另已反证旧fault owner20奖励输入假设：Native只有origin发行，旧ordinary收款owner
11/12/13及远端fee miner keys2..5，远端20未有准备资金，不能据旧height/owner名付款。
下一一次180秒network0全新12Native/12voter/caller准备：从零分配genesis，仅原生
发行，原owner10 local95给source13及两个gross3出口给remote20/net2，各真实成熟；
证明source13>=11与两remote20>=2的明确实际input IDs/fullNative/conservation/保管，
实际新mesh/TLS公钥/cert/endpoint pins及fresh-root来源后再绑定配置。控制器准备
证书/接触不计普通网络或完整fault通过，不盲用synthetic blueprint；首失败/完成/
180退出，整失败currency封存，不恢复/重签/退款/替换/原样重跑。计划8/5/5不是authority。
Native89/defaultRuntime未改，旧全部失败/成功/freeze/旧价值基线保持；当前fault及
2016/source66/长期/独立/PQ/physical和全部规范资格仍OPEN。VALUE-STRICT-01仍
独立OPEN，原触发/120诊断或300修复/无豁免标准不变，本次未触旧库或实际构建阻塞。
[实际配置、失败修复与下一原生准备](operations/evidence/regional-paged-full-fault-launch-outcome-20261005.json)。


Fresh Source89 offline full-fault preparation passed35.548s/once180 after three
separately preserved controller/test failures:33-byte origin label1.804s, missing
safe wallet parent5.433s and default macOS/var test symlink2.101s. Keep their exact
sources/reports and entire2/203/2-file currencies sealed; never reopen Native or
Runtime/recover/re-sign/refund them. Narrow label28/32 validation, exclusive0700
owner parents and project-tmp test setup do not weaken Native or symlink rules.
The new12Native/12voter-caller sample reachedE8/P5/A5, from zero-allocation signed
genesis only. One preparation owner signed three actual payments:local95/source13
and two gross3/net2 imported payments to remote20. All12fixed-head histories,
original signer/caller heads,8recipient maturity checks/conservation and3unsigned
fault-owner reviews passed. Actual source95 and remote2/2 inputs are mature; no
fault-owner first-sign.12fresh mesh/TLS identities retain exact private bytes on
reopen. Preserve668stopped files.473Native calls and18controller certificates
are setup-only, not Runtime/network/full-fault rights. Native89/default Runtime
unchanged; all old5050files/failures/freeze unchanged. Next once120s network0/
first-sign0/recovery0 explicit prepared-source binding must authenticate complete
creation/provenance/checks/inventory,12retained Native heads,3unsigned reviews and
real TLS/endpoints before emitting all48full-fault configs in a separate fresh
output. Never bypass generic absent-root guard, adopt sampled heads or launch
synthetic parameters. Actual missing leader derives fromE8/key0 at9. Original
600stage/60round/24heights/E27-P24-A24/maturity2/3of4/capacities remain. Full fault,
Source66/2016/long-history/independent/physical and legacy value strict stay OPEN.
See regional-paged-fault-native-preparation-outcome-20261005.json.


Hybrid workflow adopted locally: original source-smoke controller7f3d6e39 and
three fixed33eb1c364public implementation-source files/archive973c10c8 match the
coordinator's prior Mac/Linux2test observations0.070/0.115seconds. Reuse them only
for transfer/stdlib compatibility; no Rust/heavy speed or protocol qualification.
CI adds two public dependency/compiled-output caches and existing regional tmp
parent. Keys include fixed1.98/OS/arch/job/workspace/debug/locks plus full Core
identity/regional rule files; all original checks/triggers/read-only permissions
remain. No normal CI run,push,SSH,server install/service change or cleanup this
turn. Mac keeps current Native89fault main line and existing target per workspace/
profile; actual qualifying CLI/source/controller/evidence bind separately. The
extra local_incremental_check proposal is deferred: its source snapshot omits
Native non-Rust rules/Core identity inputs and some probes omit explicit migrated
cwd. Continue existing bounded check entries, not a weaker stability claim. All
old sealed/stopped inventories and current668prepared files/freeze unchanged.
Full fault and legacy value strict remainOPEN. See HYBRID_BUILD_TEST_WORKFLOW.md
and hybrid-workflow-local-adoption-20261005.json.


Prepared-source binding passed once120seconds in3.248seconds/exit0. The separate
regional_paged_fault_prepared gate authenticated12complete Native fixed-head
replays,12actual retained mesh/TLS identities and3unsigned owner reviews against
successful Source89E8/P5/A5preparation and its exact668-file inventory. All48configs
(96files plus2observation markers) were written only in a new private output;
original heads/custody/files and every old seal remain unchanged. Nine provenance/
endpoint/later-response counterexamples refused, including a bad twelfth Native
response returning no Bound. Two unit tests passed. No Runtime/socket/first-sign/
recover/head adoption occurred. Explicit E8/key0 missing-leader gate derives9;
phase active slots11/12/12/12, remote recipients15/16 and keyless paths remain
absent. This gate grants no launch/port/fault qualification. Next implement the
actual prepared-config fault controller, finite driver counterexample, then only
one justified600stage/60round/24height/E27-P24-A24/maturity2/3of4complete fault scope.
All capacity limits and prior failures remain unchanged; fullfault,VALUE-STRICT-01,
long-history/independent/physical and whole goal stayOPEN. See
operations/evidence/regional-paged-fault-prepared-binding-outcome-20261005.json.


Paged fault driver implemented on separate source: online replica1 receives the
three original unsigned owner approvals/queues; only ordinary nodes vote/relay/
install. Missing Earth0 stays stopped through certified gate9 and both directed
TLS cuts; catchup occurs before restoration, then original recipient maturity,
keyless restart/drain and all12fixed-head Native/envelope/mesh/owner checks.
Total once600seconds (including stages/cold) and60round/24newheights/originalcaps/
maturity2/quorum3/capacities remain unchanged. Native init/recovery/votes/direct
acceptance are forbidden controller commands; missing optional telemetry is
unknown, only exact OS-lock read refusals retry. Prelaunch public mesh anchors
are retained separately rather than adopted from final private identity.
Seven driver/pending/certified-prefix counterexamples passed2.155seconds/once120;
all actual Native/socket/Runtime/first-sign calls0. They use fake observation
backends and grant no real fullfault/custody qualification. Exact668prepared,
98bound-config,old sealed inventories/source/freeze unchanged. Real fullfault has
not started. Before it, add explicit preservation of old immutable voter pages
and qualify the changed driver boundary; then final bound launch preflight and
one justified original600scope. See regional-paged-fault-driver-model-outcome-
20261005.json. VALUE-STRICT-01/long-history/independent/physical/allgoal remainOPEN.


Driver now explicitly retains every original Native ledger and voter immutable
header/page/residue byte. Only the exact ledger-events/stream.json and
bft-records/stream.json manifests may advance; full Native replay and separate
current caller/native heads still authenticate all actual execution/custody.
A deleted or replaced old page (even another authenticated variant) refuses.
Changed driver/source8counterexamples passed2.184seconds/once120exit0; prior
7-test source/reports remain bound and separately retained. Fake backends only,
actual Native/socket/Runtime/first-sign0; no real fault/custody qualification.
All old/current668/98private inventories and source/freeze unchanged. Full fault
remains unstarted; next finish once-only terminal/owned-process wrapper plus
source/Native/port preflight, then one justified original600total full scope.
Failed currency never reopens/signs/refunds/replaces. Independent/physical/
long-history/Source66/2016/VALUE-STRICT-01/allgoal remainOPEN. See
operations/evidence/regional-paged-fault-driver-retention-outcome-20261005.json.


Full-fault terminal helper now refuses successful bodies with cleanup failures,
remaining owned processes/relays, expired whole-body/cold deadline or missing/
duplicate actual12cold slots. Only sanitized qualified counts leave the private
raw identity/custody report. Four terminal counterexamples passed2.073seconds/
once120exit0, with Native/socket/Runtime/first-sign0 and old/current668/98private
inventories/source/freeze unchanged. Read-only process probe found no eligible
active fixture (unrelated nonUTF8argv required tolerant decoding; no restart).
Next exact one justified Source89fresh-preparation fullfault under original
600total/60round/24heights/E27-P24-A24/maturity2/quorum3/allcapacities: offline
Earth0through actual gate9, both directed Earth/Proxima cuts, isolated actual
payments, offline catchup, restoration/9net original maturity, keyless restart/
all12fixed-head/full-envelope/mesh/owner/custody/conservation. Every earlier
failure remainsfailed; failure seals attempted fresh currency with no reopen/
re-sign/recovery/refund/replacement. No fullfaultstarted at this checkpoint.
See operations/evidence/regional-paged-fault-terminal-outcome-20261005.json;
VALUE-STRICT-01/independent/long-history/physical/allgoal remainOPEN.


Latest actual complete paged fault attempt FAILED213.822seconds/once600(exit1,
not budget exhaustion). Offline Earth0original native/voter/caller bytes stayed
unchanged, online3passed certified missing-leader9with view-change>round0, two
isolated original local payments were included, and original Earth0caught up9
before both contacts restored. First fresh Native receipt query at Proxima0
then returned exact no-evidence-yet refusal; the old controller aborted. All12
owned ordinary nodes exited0 and both opaque relays stopped, no forced kill.
Three original owner responses/heads and3492stopped files/source remain sealed.
Last live9/9/8observations are not final cold authority; no failed Native/Runtime
reopen/recover/cold/sign/refund/replacement. FullfaultremainsFAILED/OPEN.

The measured controller observation gap is fixed separately: only wallet-receipt,
exit1and the exact whole no-evidence diagnostic is unknown, with fresh replica
rotation/unchanged totaldeadline. Native wallet.rs589domain/source check followed
by absence in both authenticated contact records and imports confirms this
branch. All other proof/domain/command/code/combined refusals remainfatal.
Read entire bounded64KiBstderr before display truncation; a later bad-proof
suffix beyond2048bytes cannot be hidden. Changed driver11counterexamples passed
2.452seconds/once120exit0, Native/socket/Runtime/first-sign0; initial10test2.709
source/report retained independently. Native89/release CLI unchanged; all old,
new failed3492files/source/freeze unchanged. Next genuinely fresh zero-allocation
genesis/currency and separate12Native/voter/caller/owner/mesh/TLS custody once180,
then corrected driver/terminal/source/binary/controller binding before one
necessary original600/60/24/E27-P24-A24/maturity2/quorum3/full-capacity fault scope.
Never reopen the prior failed currency or reuse its signed payment. See
operations/evidence/regional-paged-full-fault-outcome-20261005.json and
regional-paged-fault-receipt-observation-fix-outcome-20261005.json. VALUE-STRICT-01/
Source66/2016/long-history/independent/physical/allgoal remainOPEN.


Latest second paged full fault FAILED163.892seconds/once600(exit1, not budget
exhaustion): actual Native status Earth1returned exact std1.98WouldBlock diagnostic
which the old controller substring classifier missed. All11ordinary nodes exited0,
both opaque relays stopped;2954files and exact driver0cc272/helper/controller
source remain sealed. Three original owner responses/heads retained. No restored
recipient maturity or fullcold was reached; no first-receipt fix real-fault pass.
The earlier213.822failure/3492files stays failed and untouched. Fresh receipt-v5
preparation33.872/once180was a historical setup pass only; that currency now stays
closed with this failure. Never reopen/recover/re-sign/refund/replace either.

Exact lock observation fix3a266c40passed13counterexamples plus actual independent
installed Rust1.98OS-lock reproducer4.374seconds/once120exit0. Only exact known
whole diagnostic/integer1/readonly commands can become unknown; signing/queue,
later bad proof/domain, combined or permission errors remainfatal. No Native
ledger/runtime/socket/firstsign/recoverycalls; original Native89/CLIunchanged.
All failed/private/source/freeze bindings unchanged. Next genuinely fresh signed
zero-allocation genesis/currency/custody once180, then one justified original
600total/60round/24heights/E27-P24-A24/maturity2/quorum3/full-capacity scope.
Exit first error/deadline or all12actual Native/custody/value/cold complete; failed
currency seals forever. VALUE-STRICT-01/Source66/2016/long-history/independent/
physical/allgoal remainOPEN. Evidence: operations/evidence/regional-paged-full-
fault-receipt-v2-outcome-20261005.json and regional-paged-fault-lock-observation-
fix-outcome-20261005.json.


Latest third paged full fault FAILED184.744seconds/once600(exit1, not budget
exhaustion): Runtime status wrapped the exact native OS-lock diagnostic as a
Service error. The controller observation classifier aborted, with no completed
isolation/restoration/recipient/fullcold phase discriminator. All11nodes exited0,
both relays stopped,3157files and exact3a266failed source retained. Three original
owner responses/heads remain. Prior163.892/2954and213.822/3492failures stay failed;
new lock-v6setup38.542pass is historical only and that currency now stays sealed.
No Native/Runtime/recovery/re-sign/refund/replacement reopening is permitted.

Measured Runtime observation repair56e313ccnow treats only exact wrapped native
OS-lock errors, with no received rejections, as whole-observation unknown even
with a retained height. Runtime diagnostics lack command/exit, so cannot prove a
read or write action or grant progress/signing. All received rejections/later bad
proof/domain/permission/persistence/TLS errors remainfatal. Actual retained P1
status makes old driver refuse and new observation returnNone;15counterexamples
passed3.285seconds/once120exit0. Prior actual installedRust1.98lock reproduction
is reused without rebuild/rerun. Native89/CLIunchanged; actual Native/runtime/
socket/firstsign/recovery0. Old/private/source/freeze remain unchanged.

No further full attempt in this stage. Next hypothesis is that both exact direct
read and runtime-observation lock paths no longer falsely abort ordinary
contention; restored original9net maturity and all12fullcold must still actually
complete. Next fresh signed zero-allocation/custody once180, then only after
current15model/terminal/source/binary and12Native/TLS/owner binding one necessary
600total/60round/24newheights/E27-P24-A24/maturity2/quorum3/full-capacity scope.
Exit first real error/deadline or all required checks; every failure closes whole
currency. Fullfault/VALUE-STRICT-01/Source66/2016/long-history/independent/physical/
allgoal remainOPEN. Evidence: operations/evidence/regional-paged-full-fault-lock-
v3-outcome-20261005.json and regional-paged-fault-runtime-lock-observation-fix-
outcome-20261005.json. Goalactive; commands explicit newworkdir, persistent cwd
remains a UI repair item. Frozen body/PDF/website unchanged.

Final Runtime observation source a373124ealso checks any available height is an
integer within its original cap before returning lock-unknown. Over-cap/bool/
negative heights still refuse. Changed-source15counterexamples/actual retained
status passed3.423seconds/once120; prior56e313/3.285source/report retained. No
Native/runtime/socket/firstsign/recovery or OS-lock probe rerun. Fullfault still
FAILED; original next180fresh preparation/once600and all limits unchanged. See
operations/evidence/regional-paged-fault-runtime-lock-cap-fix-outcome-20261005.json.


2026-10-05 latest paged fullfault FAILED at original600deadline (612.570seconds
including cleanup/source pins/inventory sealing);12nodes exited0,relays stopped,
6152files/exacta373source retained. Isolation original payments/nonzero-round
certificate/offline catchup passed, then restoration; only2Native receipt calls
returned1,38restored samples all had some unknown heights. No actual final Native
import/maturity/keyless/fullcold was established. Old refusal classes were not
retained; samples cannot reconstruct missing scheduling or uniquely prove cause.
All4failed currencies remain sealed; no Native/Runtime/recovery/resign/refund.

Narrow74468bb1receipt driver removes only the simultaneous-all12telemetry query
barrier: exact complete Native recipient authentication/maturity/finality/value
and fair2sec rotation remain mandatory, unknown/pending never credit. Retain
exact successful live responses and categorical lock/no-evidence/fatal outcomes.
Retained-sample old-block/new-query counterexample plus17tests passed4.243seconds
/once120 with Native/runtime/socket/firstsign/recovery0; modeled answers grant no
actual value/fault qualification. Native89/CLIunchanged,all old/source/freeze exact.
Next once180fresh signed zero-allocation custody, then one necessary original
600/60/24/E27-P24-A24/maturity2/quorum3/fullcold scope after17model/terminal/source/
binary/12Native/owner/TLS gates. This budget-ended stage launches no more fullscope.
Goalactive; fullfault/VALUE-STRICT-01/Source66/2016/history/independent/physical/
allgoal OPEN. See operations/evidence/regional-paged-full-fault-runtime-v4-outcome-
20261005.json and regional-paged-fault-async-receipt-fix-outcome-20261005.json.


2026-10-05 fifth paged fullfault remains FAILED at original600deadline;613.933
seconds includes cleanup/pins/seal,12node exit0/relays stopped/6128files retained.
203actual receipt reads:147Native lock busy,23no-evidence,33complete authenticated
responses all pending import. These observation-time statements cannot establish
final stopped Native state. Original maturity/keyless drain/all12cold/conservation
not completed. Earlier6152and all failures stayfailed; no failed Native/Runtime
reopen/recover/resign/refund/copy. Isolation/payments/offline catchup remain finite.

Measured candidate-lock correction retains complete bounded diagnostic/action/exit;
only exact native candidate lock refusal aborts selection before empty/partial
fallback. No skipped native checks, cached authorization or changed bounds. Old2
counterexamples reproduced; new6/related13batch regressions pass. Fresh offline
Native component passed10.319seconds/once180:8new stores, actual locked trial old
empty/new abort; unlocked exact Import candidate;fournet2recipients mature/full
8fixed-head/caller/owner cold, private bytes unchanged;7controllercertificates
qualify setup only. Native89/CLI unchanged. No Runtime/socket; no unique oldfull
fault causality or actual ordinary-retry qualification.261newfiles sealed.

Next once180/one fresh zero-allocation finite ordinary gate: blocked leader trial
must release no Proposal or changed signer/caller head; after release ordinary
native selection/import/maturity/fullcold must complete. All original maturity2,
quorum3/history/capacity bounds remain. Exit first mismatch, full discriminator or
180; failure seals/no unchanged600retry/deadline increase. No new fullscope in this
stage. Source66/2016/history/independent/physical/PQ/VALUE-STRICT-01/allgoal OPEN.
Goalactive; commands explicit newworkdir, persistentcwd remains UI repair item.
Current body2ba62421/PDFc59f9fe8and S1-S18/R1-R24/I1-I12/A-G/N1-N10/P1-P8 adopted;
goal text retains superseded predecessor hashes; frozen paper/site unchanged.
See operations/evidence/regional-paged-full-fault-async-v5-outcome-20261005.json and
operations/evidence/regional-bft-candidate-lock-fix-outcome-20261005.json.


2026-10-05 candidate-lock ordinary Service gate passed73.838seconds/once180exit0.
One helper hosted4actual Service/Runtime instances with ordinary pinnedTLS workers;
no standalone Native node CLI startup or independent host/process qualification.
Fresh8Native custody;4source setup certificates/contact carriage only. Actual
blocked leader trial released no Proposal/native/signer/caller change; next normal
tick signed the exact Import. All4import1/mature3/net2spendable;122complete retained
envelopes/8fixed-head Native/8caller+owner/fullmesh/native1e30conservation cold pass,
private bytes unchanged. Services/allownedthreads stopped;534files sealed.
This changed source is qualified only for that finite ordinary mechanism. Old
6152/6128and every full failure stayFAILED; no unique full root cause is proved.

Next genuinely fresh signed zero-allocation Native/TLS/custody preparation once180,
then at most one necessary original600body/cold fullfault under qualified changed
Python source/current Native89binary/driver/controller binding. Actual original9net
maturity/keylessdrain/all12cold/conservation mandatory;60round/24newheights/E27-P24-
A24/maturity2/quorum3/capacity unchanged. Exit first failure/full invariants/deadline;
failed currency seals/no reopen/recovery/resign/refund/copy/unchanged repeat.
Goalactive; allgoal/VALUE-STRICT-01/2016/history/independent/PQ/physical OPEN.
See operations/evidence/regional-bft-candidate-service-outcome-20261005.json.


2026-10-05 sixth fullfault FAILED292.352seconds/once600exit1, not budget exhausted.
Isolation original payments/missing-leader9/offlinecatchup passed, contacts restored;
ordinary Service labeled a complete envelope rejected with native OS-lock text.
Original action/exit/complete diagnostic were not retained; do not reconstruct
those or infer a bad proof.38receipt calls=22lock/16no-evidence/0complete response;
actual final import/maturity/keyless/full12cold/conservation unknown/notcompleted.
All12nodes exited0/relays stopped/noforcedkill;4136files/exact changed source sealed.
All previous failures remainfailed; no failed Native/Runtime/recovery/resign/refund.
Candidate-v9setup42.089pass is historical preparation only, currency now closed.

Narrow new Service receive source reports typed exact known candidate-independent
validation/sync native lock as deferred, not envelope rejection. Complete action/
integerexit1/full bounded diagnostic required; no bft_seen/trace/ledger/signing
credit, no signed-byte deletion. Subsequent retry runs full Native authentication
again, including later bad proof; wrong action/exit/combined diagnostics and all
other refusals remainrejected. Partial prior Native progress never rolls back.
Retained original production flush AST counter confirms the misclassification;
new5models+13complete batch regressions passed0.024seconds, actual Native/Runtime/
socket/sign0. Initial system-Python diagnostic entry lacked cryptography and did
not execute; existing pinned venv corrected it without installing or repeating
passed regressions. Actual old rejected command/exit remainsunknown.

Next once180/one genuinely fresh8Native/4ordinary Service receive-lock gate:
actual locked full inspect must defer without rejection/seen/caller credit; after
unlock exact complete original bytes must natively authenticate, ordinary import
1/mature3/net2 and full8Native/envelope/mesh/heads/owner/conservation cold complete.
Source4cert/contact setup only,60round/maturity2/quorum3/capacities unchanged. Exit
first mismatch/full behavior/deadline; failure seals/no unchanged600retry or bound
increase. No further fullscope in this stage. Goalactive/allgoal/fullfault/strict/
2016/history/independent/PQ/physicalOPEN. Current paper/site/cwd limitations unchanged.
See operations/evidence/regional-paged-full-fault-candidate-v6-outcome-20261005.json
and operations/evidence/regional-bft-receive-defer-outcome-20261005.json.


2026-10-05 first receive-defer Service gate FAILED44.975seconds/once180exit1:
actual blocked inspect was deferred without credit/custody change, then known
progress reached2. Helper incorrectly required a height in explicit unknown
other-purpose mesh contention; actual final Native maturity/cold not established.
397files/source sealed and never Native/Runtime reopened.1.308msreadonly retained
observation counter proves oldassert refusal/current qualified Driver unknown,
5PID/currency/type/cap negatives refuse;17driver evidence reused, no Native/socket.

Changed controller alone uses exact qualified PID/domain/TLS/limits/error/unknown
classification plus present-height cap/type before waiting. Fresh corrected gate
passed74.627seconds/once180exit0:8Native/4Service in onehelper with pinnedTLS, actual
bft-network-inspect-batch exit1/fullOSlock diagnostic ->deferred, no seen/native/
signer/caller credit; the identical complete frame reauthenticated natively after
unlock. Four import1/mature3/net2,120complete retained envelopes/8fixed-head Native/
8caller+owner/fullmesh/1e30conservation cold, private bytes unchanged. Explicit
unknown samples actually waited. AllServices/ownedthreads stopped,541files sealed.
Source4cert/contact are setup only, no controller consensus after Runtime start;
this is not defaultCLI/independent processes/oldfullFAIL replacement. Native89/
CLI/current Node unchanged between those gates; original44.975 remainsFAILED.

Next fresh signed zero-allocation/custody12Native/TLS preparation once180; at most
one necessary full600body/cold under current typed-receive source/model/actual
ordinary gate/current155Python/Native89/CLI/independentcontroller binding. Original
60round/24newheights/E27-P24-A24/maturity2/quorum3/capacities remain. Actual original
9net maturity/keyless/all12cold/conservation required; exit first mismatch/full
checks/deadline, failure seals/no reopen/recovery/resign/refund/copy/unchanged retry.
Goalactive/allgoal/VALUE-STRICT-01/history/2016/PQ/independent/physical OPEN.
See operations/evidence/regional-bft-receive-defer-service-v1-outcome-20261005.json
and regional-bft-receive-defer-service-v2-outcome-20261005.json.


2026-10-05 seventh fullfault receive-v7 FAILED: original600deadline exhausted,
616.052seconds including cleanup/pins/seal;12nodes exit0/relays stopped/forced[]/
cleanupnull,6657files/exact155Python source d72… and currentNative89/actualCLI sealed.
Isolation/local owner payments/missing9/offlinecatchup passed finite gates.170native
receipt reads=129busy/12no-evidence/29complete responses:18pending import/11imported
immature;allfour replicas observed import13/mature15, native pins13(10)/14(1).
Original maturity/keylessdrain/full12Native cold/conservation notcompleted;final
stoppedNative state unknown. No failed Native/Runtime opens, recovery, replacement,
resign/refund/copy. All prior fullFAILs remainfailed;36.857setup/74.627gate finite only.

Readonly exact-response production predicate counter1.98095seconds/once120 passes:
all29 wait correctly,8synthetic negatives and maturecontrol grant no native rights;
6657privatebytes unchanged. Firstcounter wrong all-pin13 assertion remainsfailed;
last actualpin14 is below15. Retained7sign spans prove inner bft-sign alone is less
than half enclosing work: residual lowerbounds3.364990–4.016831seconds. No precise
stage/lock/replay/relay attribution or unique fullfault cause;bounded rings dropped
old rows. Next once120zeroNative production _sign path/failure-order attribution,
then only bounded scalar diagnostics preserving all custody ordering if needed;
necessary fresh once180no-network actualcomponent binds changedcompanion/Native/CLI.
No new600allocated, unchanged bounds/oldfailures/frozenpaper/site/cwd limitations.
Fulltarget/VALUE-STRICT-01/history/2016/PQ/independent/physical OPEN; goalactive.
See operations/evidence/regional-paged-full-fault-receive-v7-outcome-20261005.json.


2026-10-05 current sign-stage diagnostics candidate preserves status/pending/native/
response/outbox custody order and failure states; five fixed scalar timers retain
no request/head/key/proof.11models pass; original128events/192KiB/32operations and
all native bounds unchanged. Node24f9ddbe…/156Python72ee844c…, Native89/CLI unchanged.
Actual first31.869second no-network component failed helper blanket reward assertion
on unfunded nonorigin;371files/exactsource sealed, neverNative/Runtime reopened.
Two readonly detector failures retained; exact origin-only kernel unchanged.
Corrected fresh once180component passed32.142seconds:4Native P13empty nonorigin,
1Runtime/noService/socket,1explicit Timeout; stages .085339/.000602/.145903/.000577/
.184896seconds, enclosing .417616/unattributed .000299;32complete envelopes/4fixed
heads/native caller/cold and zero value conservation/privatebytes unchanged.
13controller certs setup only; no ordinary owner/network/fullfault qualification.
Empty isolated sample did not reproduce old5–6second spans; no unique cause claim.

Next once180fresh8Native no-network E4/P13loaded-causal-import component, one fresh
owner gross3/net2 atP1/mature3; atP13 one explicitTimeout and five actual stages,
full8Native/envelopes/originalowner/caller/conservation cold. Compare already valid
empty .417616baseline without repeating it. If loaded cost increases, isolate
measured stage before optimization; otherwise measure actualService/contention.
Exit first mismatch/fullcold/originaldeadline; failure seals entire currency, no
reopen/recovery/resign/refund/copy or new600allocation. Fullfault receive-v7 remains
FAILED616.052/6657 plus everyoldFAIL. Alltarget/VALUE-STRICT-01/2016/history/PQ/
independent/physical OPEN, goalactive/frozenpaper/site untouched/cwd UI stillold.
See operations/evidence/regional-bft-sign-stages-outcome-20261005.json.
