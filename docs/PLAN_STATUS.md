# RLDCOIN 当前交付状态

更新：2026-10-05。仅全新无价值地面测试候选；退役主网、旧余额和失败保管不迁移。
总目标：[冻结白皮书实施验收](WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md)的 S1–S18/R1–R24/I1–I12/A–G/N1–N10/P1–P8，
以用户授权编辑修订的正文 `2ba62421...` / PDF `c59f9fe8...` 及[冻结记录](WHITEPAPER_FREEZE_RECEIPT.json)为准；
[完整主计划](RLDCOIN_MASTER_PLAN.md)继续记录实现/风险，不能降低规范目标；
默认网络：[N1–N10 接触中继要求](research/INTERSTELLAR_NODE_MESH_REQUIREMENTS.md)。均未全部完成。

最新完整fault：**第五次仍耗尽原600秒预算，未通过**（收束/封存总613.933秒）；
12节点退出0，两中继停止，6128文件/准确74468bb1失败来源封存。旧6152及全部失败仍失败。
隔离付款、缺席领导者进度和离线追赶有限通过；恢复后203次实际Native收款查询：
147锁忙、23无证据、33完整响应均为认证证据待导入；这不是停止后的最终账本结论。
原收款成熟、keyless drain、全12Native完整cold/守恒未完成；不重开失败保管/重签/退款。

已实施候选试验锁忙窄修复：完整有界原生诊断/实际命令/返回码绑定后，中止本轮
选择，不能把未知有效性当无效并生成空或部分候选。旧两反例复现；新6反例、13相关
batch回归通过。全新无网络原生组件10.319秒/一次180通过：实际锁下旧空候选/新中止，
解锁后精确Import入候选，四收款net2成熟，8固定头Native/caller/owner cold且私有字节未变。
7controller证书只计组件准备；不证明普通服务重试或完整fault唯一根因。Native/CLI未改。
[终态与下一普通重试判别](operations/evidence/regional-bft-candidate-lock-fix-outcome-20261005.json)。
历史“全部通过”仅指当段源码/有限scope，不能覆盖后续失败或全部验收。

当前来源 `89408f5a...` / implementation `8a361699...` / release binary `a45387fa...`：
**普通六阶段完整闭环510.455秒/原600秒有限通过**；四E9/四P6/四A8，全部成熟、
1606阶段合计完整信封/原heads/12Native/最终守恒，27Services正常退出。
普通启动cold路径未改，停止采用明确固定头模式；完整fault和全部协议资格仍OPEN。
六新边界/四原cold-batch/地区strict及release CLI32.956秒保留原scope；
19.164/3.421/121.752及旧600.666、旧完整fault失败均仍失败。

前继来源 `4e2331b4...` / implementation `bb6d1e5b...` 的历史有限范围：已修复原生付款入队
的因果证明遗漏，改用完整原生证明接口；原命令和完整证据均保留，不因入队扣款。
原2.954秒继续转出失败已封存，原批准/调用头/预留不恢复、重签、退款或迁移。
21.670秒新反例复现遗漏；5.065秒测试字段构建失败及21.325秒测试持锁冷启动失败
仍失败。最终45.509秒原始99输入入队、创世只读接收端、坏后证明/缺前置/坏owner
拒绝、冷重放、旧队列/响应回归、CLI及地区lib/tests strict通过。

新来源普通E到P范围105.313秒完整通过，P原net99在3进口、5成熟；其后普通
P继续转出范围 **180.529秒预算耗尽，未通过**。四原P实际在7认证export98，
准确99输入已消费，原永久进口保留；源阶段284完整信封/full Native/原heads/owner
cold通过。最后A live观测为6、已进口而未成熟，**不是最终停止高度**；目的完整cold
未达到，整范围不能称通过。连同此前通过的E/P现场封存，不打开Native/Runtime。

停止核验现采用已有原生4份完整信封/8MiB只读批量接口，每份仍全认证；输入/响应
摘要仅绑定本次请求，不授予账本/签署权。1.015秒工具路径缺失失败保持；修正后
12.614秒合同/真实Native/后置坏证明/容量/新进口owner证明及私有字节检查通过。
小夹具4单独调用对1批量结果相同，约2.128倍；不证明旧live耗尽唯一原因或新普通
成熟cold。Native源不再改变，原45.509严格检查复用；Node冷核验来源已改变。
[准确修复、范围、失败与下一假设](operations/evidence/regional-native-paged-submission-outcome-20261005.json)。

迁移恢复：原任务 goal 已读回 active；后续全部项目命令显式使用
`/Users/galaxy/GitHub/rldcoin`，持久 cwd 仍旧且待界面修复。旧合格CLI
`20d0b0fc...` 的默认入口实际引用已不存在的旧 companion，独立 help-only
探针返回2；旧二进制保留。一次120秒预算内44.068秒从新目录重建CLI
`d8c2af0d...`，构建及新默认 companion help/import 探针均返回0，未创建
Native目录或启动网络。87 Native/153 Python/Core来源、implementation、
冻结材料及旧价值strict基线未变；这是入口恢复，不是新Native付款/冷保管/fault
资格。[准确恢复与新二进制绑定](operations/evidence/regional-migration-driver-recovery-20261005.json)。
下一新scope绑定这份新驱动并重新核验实际Native身份；旧签署夹具/失败/报告不改。
原goal正文仍保存 `c906.../f825...` 前继引用，须向父线程报告；实施规范继续按
当前AGENTS及冻结记录的 `2ba62421.../c59f9fe8...`，不自主改目标正文或白皮书。

既定一次全新继续转出范围已于136.378秒/180秒完整通过：Native准备E4/P3
只计作前置准备；四原P实际99输入签一次gross98，普通节点在4认证出口、5停止。
四新A均在4唯一进口净97、6达到原两块成熟且可花。源204及keyless/目的290份
完整信封共494份逐份Native认证，原独立voter/owner caller heads、原审批及
所有既有Native不可变对象核验；9 Services正常退出，守恒I=U=10^30、E=T=0。
旧180.529秒失败仍失败；有效旧检查未重跑，没有打开失败Native/Runtime。
[准确终态与下一返程判别](operations/evidence/regional-native-paged-onward-fresh-outcome-20261005.json)。

返程一次300秒范围已在 **14.512秒失败**，未通过：owner12原97输入首次签96并
入队时无debit已核验，但驱动构建把原3秒连接尝试断言误改为6秒，在源阶段停止。
四Service退出码为−15/0/0/0，当前自有进程0；目的阶段未启动，实际后续出口、
导入成熟及完整cold均UNPROVEN。停止后的空Native拒绝诊断原因未知，不能因
controller错误称原生协议通过。准确currency及原E/P/A/owner/voter/caller/transport
共1783文件已封存，原请求/签署/预留保持，不再Native/Runtime打开、重签、退款、
恢复或替换。旧136.378秒历史onward仍有效，旧180.529秒整范围仍失败。
[准确返程失败、修复、封存及下一范围](operations/evidence/regional-native-paged-return-outcome-20261005.json)。

一次20秒只读反例实际0.456秒/exit0：三份真实停止观测均为原2worker/3秒attempt/
0.2秒lock；旧6秒断言误拒绝，新独立固定合同接受原值，并拒绝改变/缺字段/错误
类型。新增 `tools/regional_fixture_transport_contract.py` 将传输约束与高度改写
分离；两项回归exit0、私有字节不变，无Native调用/网络/签署权。失败helper不改，
新候选只引用尚未创建的新根，尚未启动。[最小反例](operations/evidence/regional-return-transport-contract-counter-20261005.json)。


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

历史b4来源普通owner提交至目的成熟组合范围已通过：全新零分配根，一次180秒实际
91.981秒；源端只签一个请求，typed queue不debit，四普通节点认证source5出口100
并完成停止核验。随后同一原source keyless普通中继至四新Proxima replicas，均在
3导入net99、5原两块成熟可花。两阶段9次Service启动均clean exit，源阶段191/
收款阶段233完整信封、全部Native/voter-caller/owner核验通过。四目的Native选定
认证前缀共同statement5精确相同且ledger相同，E5/P5/A0 issued=liquid=1.25e30，
一出口/一永久进口，pending/escrow0。
[来源、失败、反例和终态](operations/evidence/regional-native-paged-ordinary-composed-receiving-outcome-20261005.json)。

固定目的终点4的收款25.981秒失败，完整cold未到达；其原33.203秒通过source
fixture随失败共同封存，不再打开Native/Runtime。新network0的12.288秒反例以
八Native/原heads证明import3在4未成熟、5才成熟。Controller按实际import+2
判别，目的仍原24高度上限；新组合用全新货币根，不复活/重签/退款旧现场。
四目的本次都停在5，不证明不同当前高度的兼容分支；Native87/Python未改、准确
strict复用。旧价值库strict、onward/return/fullfault/2016/post64/独立/PQ/physical
仍OPEN。

最新普通源端钱包范围已通过：全新签署零分配货币根，四份原始Native/voter/caller
准备认证前缀3；一个明确成熟input的owner100出口审查/签署并typed入队时，四账本
均未debit。默认四Native Service/Runtime以普通TLS和原三取四认证在高度5实际
纳入、扣原input并保留唯一export100。一次120秒实际33.203秒，clean exit后
200完整信封/四Native完整历史/独立voter-caller heads及原owner钱包/头核验通过。
四副本tip/state/finality/ledger相同，issued `1.25×10^30` = liquid + gross pending100，
imports/received/escrow0；目的手续费1、预计净99尚未进口。
[来源、反例、终态与失败](operations/evidence/regional-native-paged-ordinary-owner-outcome-20261005.json)。
原高度4范围15.199秒无出口，仍失败；3.823秒诊断读错native serde顺序仍失败。
实际4.201秒Native/Runtime反例证明：没有提交时候选为空，完整认证提交到达后
候选含准确付款，构造不debit/sign；只改变controller有限判别，不修改协议。
新的高度5终点在原24高度内，不能补记高度4失败通过或推断其唯一时序原因。

最新[普通节点实际收款](research/REGIONAL_PAGED_CONTACT_REQUIREMENTS.md)已在全新无价值
范围通过：五个默认Native Service/Runtime以普通TLS中继既有P出口98，四个新A
副本均在高度2进口净97、高度4达到原两块成熟并可花。总65.805秒（一次180秒）；
五个进程干净停止，186完整信封、五Native完整历史、独立保留的voter/caller heads
核验通过；四A的tip/state/finality相同，原源owner/signer/caller与历史对象保持。
无控制器造/搬运投票、信封或进口块。[准确源绑定与失败](operations/evidence/regional-native-paged-ordinary-value-outcome-20261005.json)。

当前签署paged profile继承原起源发行曲线：E4实际发行与liquid均为 `10^30 runlai`，
escrow/pending为0。前一计划套用历史小夹具“300”不适用于这个准入，已明确更正
核算预期，经济/共识参数未改。17.683秒拒绝观察失败、62.910秒全部收款/cold后
错误固定300断言失败、26.298秒连接重置观察失败均保留；后两次不能补记整项通过。
0.973秒锁拒绝、5.008秒原生发行核算及0.694秒连接容量反例改变了controller判别；
临时运输尝试失败保留unknown且不授保管/签署/价值权利，实际Native拒绝仍停止。
新通过仅是一段既有出口的普通收件，不资格源端普通钱包提交/继续转出/返程或fullfault。

Native87来源 `b4bc4379...` / implementation `cf4a2c7e...` / release CLI
`2e72ac63...`及节点Python未改；准确复用47.519秒Native/legacy/地区lib-tests strict。
此前默认spool11.132秒、双默认TLS完整收件16.247秒保持各自有限绑定；所有旧失败、
source66容量拒绝、完整2016/长历史、独立custody/crypto/physical与VALUE-STRICT-01
仍未完成。地区strict不能替代旧价值库，冻结正文/PDF/官网均未改。

原P5→7/新A收款的180秒假设已分别终止于原2.954秒入队拒绝及新来源
180.529秒预算失败；这些夹具和批准全部封存。当前下一范围以本页顶部及准确
outcome为准，不复活旧余额或原样重跑。

本文历史“全部通过”仅指各段明确绑定的当时源码、命令和有限scope，例如下述
8831a634来源的491过程/三个Runtime组件；不能覆盖后来完整fault、预算耗尽、
分页/接触/普通节点失败，也不表示最终源码或全部协议资格通过。

当前源绑定开发已推进到 V8 明确累计费用预算、原生 watcher及实际普通领导者自动挑战提案；
[R-CH-FEE-01](research/REGIONAL_CHANNEL_WATCH_REQUIREMENTS.md) 旧费用覆盖失败保留；
[V8候选](research/REGIONAL_CHANNEL_FEE_BUDGET_REQUIREMENTS.md)只修复已测native路径，
完整故障/窗口/独立安全仍未通过，不能把有限scope或守恒称为全部协议完成。
2026-10-05 最小普通 Runtime leader 样本70.186秒通过自动q2提案且未扣款；
首配置拒绝41.693秒及三Runtime旧历史搬运范围120.017秒耗尽仍未通过。
后续改变判别方法的一次180秒范围于179.233秒通过三个普通Runtime实际三取四
认证/高度7纳入q2、原预算仅扣fee3及完整冷重放；controller仍搬运了完整信封，
[该有限范围和下一普通Native/TLS验收](operations/evidence/regional-native-channel-fee-budget-runtime-certification-outcome-20261005.json)。
后续[普通Native/TLS范围](operations/evidence/regional-native-channel-fee-budget-native-tls-outcome-20261005.json)
通过四副本最高q2实际纳入和fee各扣3、clean exit、完整停止cold与caller heads；
live164.517秒、总303.651秒，原60秒轮/24高度/2016窗口未变，无控制器搬运。
首42.973秒启动锁拒绝/未完成启动退出仍未通过；后续仅改变新样本controller
启动观察次序，源码未变，不能宣称已修复或唯一诊断该产品startup风险。
实际OS锁最小反例0.170秒成立；窄read-only startup等待修复后13项当前源检查
及新V8真实Native入口/无钥BFT构造通过，普通live不改等待/头策略。
首次stale helper setup拒绝仍未通过，helper来源修复后换全新fixture验证；
[修复绑定和下一有限缺席leader门槛](research/REGIONAL_NATIVE_STARTUP_CONTENTION_REQUIREMENTS.md)。
没有原样重跑旧TLS或full fault范围。
后续有限缺席leader范围首329.533秒因cold构造器更新未启动carrier配置而
库存检查失败，仍未通过；新0.008秒反例及fixture修复采用独立公开锚严格只读
检查。全新一次范围总261.266/live160.834秒通过三健康副本round1/q2/fee3，
clean exit，133完整信封/339packet/219receipt和四Native/caller；缺席副本及
所有私有库存/hash/mode/size/mtime未变，没有full fault通过。
[准确范围、旧失败及下一完整窗口容量判别](research/REGIONAL_CHANNEL_MISSING_LEADER_REQUIREMENTS.md)。
后续原生窗口容量反例49.515秒完成：连续64 BFT检查点实际保留，65以
snapshot bound拒绝且原生/磁盘不变；2016窗口未改，普通窗口结算仍不可资格。
真实签署判别首编译失败保留，修正范围120.028秒耗尽、最后完整记录height20；
实际signer容量门槛/最终头/cold及CPU归因未知，不能称通过。
新改变方法12高度成本样本24.715秒通过完整cold/四signer/caller heads；Native
sign占独立计时81.4769%，内部成本未分开，未验证128-record门槛。
[完整历史/锁设计义务、成本归因边界和下一可执行模型](research/REGIONAL_BFT_WINDOW_HISTORY_REQUIREMENTS.md)。
后续[可执行完整保留模型](research/REGIONAL_BFT_PAGED_HISTORY_MODEL_V1.md)实际完成
2018模型高度/12108签署记录、887文件/约24MB及64/128活动边界；绝对2016窗口、
费用与永久ID保留。首次整体10.700秒失败于攻击fixture误把已认证相同原文当伪造，
保留未通过；更换未认证完整提案后单项0.579秒通过，原模型及七方法结果按准确
未变来源复用，未重复长轨迹。密码/发行/完整价值/出版均有明确模型前提，
Native第65检查点/128签署容量及真实2016资格仍OPEN。下一实现同时处理普通
Native Store与BFT signer的新规则，不降低旧bound或用只读verifier替代。
历史71-file共用[原生完整保留层](research/REGIONAL_NATIVE_COMPLETE_STREAM_REQUIREMENTS.md)已编写，
该来源尚未接入普通Store/Agent/钱包或启用新signed admission，后续77-file进展见下。实际最小故障2.678秒
确认pending只保留reference会缺完整未发布record；修复先持久完整payload，
再发布页/manifest。22.139秒受影响组件及native库/tests strict通过，三注入边界
保持证据并拒绝继续；同机新进程检查的是145条公共fixture签署record的存储，
不是BFT高度/真实窗口/custody。首20.746秒strict测试告警失败仍保留。
当前library源身份已变化；旧69-source/主binary只保留原有限绑定，未重建主程序、
未复活旧fixture。普通原生分页集成及其一次300秒验证仍OPEN。
字节容量首30.015秒耗尽仍未通过；保持完整逐文件哈希的改变观察方法范围
16.924秒通过256MiB残片加manifest实际拒绝及strict，生产primitive不变。
上一保留层71文件library源`0bdde7ce...`/implementation`98326b85...`的
[总绑定](operations/evidence/regional-native-retained-pages-outcome-20261005.json)
不等于旧主binary或完整原生运行资格。
后续普通BFT Agent已接入完整逐条record内核，exact legacy prefix head改为
进程内增量哈希，仍全认证原生观察/角色/请求/锁/签名；read-only完整页镜像共用
同一内核。一次120秒范围实际25.212秒通过四真实Agents/8认证高度/99付款成熟、
每人18原record与4完整sealed pages、逐prefix独立head oracle、后部坏签名/陈旧
双head/错purpose拒绝及完整pinned same-process冷重放、私有字节/属性不变；
受影响锁/恢复/role-origin及native库/tests strict通过。现73-file library源
`66ab6d20...`/implementation`a2e80dcf...`的
[准确绑定](operations/evidence/regional-native-bft-record-replay-20261005-outcome.json)
不等于普通分页写入/新signed admission或独立/新进程资格；主binary未重建。
该73-file来源Store第65检查点与128签署容量保持OPEN，真正Store/Agent写入集成一次300秒
尚未启动；旧价值库strict独立OPEN，冻结正文/PDF/官网未改。
后续77-file明确signed paged profile已接入普通Store及钱包完整历史审查。
首5.680秒编译失败与8.563秒watcher segment失败保留；修复watcher从完整native
流重放后，一次120秒实际88.056秒通过连续65认证高度/活动64、99付款成熟、
历史签署审查、完整坏尾拒绝和同进程pinned cold，完整原件不删。仅公共fixture
quorum签名，无BFT Agent投票保管。两地区重复foreign legacy envelope反例3.114秒
成立，修复4.255秒通过坏后来签名仍拒绝；最终容量计账小组件/CLI仅编译/strict
7.844秒通过。现77-file library源`d3abffbce056...`/implementation`c0979d1d4a0c...`；
65及mixed各绑定实际来源，未原样重跑或冒称最终全套通过。普通Agent分页写入/
>128历史锁/recover-only尚OPEN，原定一次300秒集成scope未启动，网络预算0。
[实际变化、反例、来源和下一假设](operations/evidence/regional-native-paged-store-outcome-20261005.json)。
旧价值库strict独立OPEN；主binary未重建，旧V8第65及完整fault失败不改称通过。
后续78-file普通Agent已接入normal paged writer及从genesis逐条历史锁重放；
真实四Agent/8高度/72签署/owner99成熟有限样本23.452秒运行完成，整个37.861秒
scope因strict模块位置告警失败，保留未通过。移序/测试接口修正后10.795秒通过
三高度实际Agent/活动parent集缺失时完整历史与自洽hash坏签名拒绝、旧锁路径/
strict/入口compile。held-native新pending事故guard最小反例3.943秒成立；加Native
health/guard/full事故重验后9.942秒受影响范围通过，不打开原失败目录。
现源`00feaf5ab202...`/implementation`26b13da2133c...`，8样本保留准确原来源，
未重复8/65或称final全套通过；[准确Agent结果](operations/evidence/regional-native-paged-agent-outcome-20261005.json)。
上述78-file时中断响应promotion/recover-only未实现，pending严格拒绝保留。当时下一一次60秒
恢复组件先待可审合同/实现；原定300秒>128/实际native活动界/新进程集成范围
未开始，原网络600sec/60sec/max24/2016及成熟/票数/容量不变。旧价值strict仍OPEN。
后续明确keyless原响应恢复已实现，三个native锁发布注入边界21.377秒通过；
错误头/请求/缺失保管/完整hash自洽坏签名及keyless新签均拒绝。4096文件反例
23.575秒确认已发布manifest多预留commit；窄计账修复27.279秒通过，原文/孤儿
不删。首次原定300秒真实Store+四Agent集成于300.033秒耗尽/-15，仍未通过；
最后完整日志height24/每人54records/active24，最终头未知、现场不打开恢复。
实际>128/65及新进程cold未完成，不能以两组件通过替代。81-file准确来源
`56f88b7f8a92...`及[终态/下一成本判别](operations/evidence/regional-native-paged-response-recovery-20261005-outcome.json)
保留所有失败；最终新增测试定义/CLI编译/地区lib-tests strict4.326秒通过，
主binary未重建、旧价值strict独立OPEN。下一一次60秒/最多10本地高度只区分
双完整replay、请求/签名、落盘及Store成本；不原样重复300范围或改网络预算。
后续成本39.930秒明确双重完整replay占签署83.04%，同调用cursor复用及磁盘
manifest缺口修复53.651秒通过必要回归；首14.441秒缺口失败保留。最终源85
文件`f34e58af93aa...`的全新优化集成103.160秒通过Native65/四signer均>128/
活动64、99付款成熟、原响应恢复、>128坏签名/缺页/陈旧头拒绝及新进程完整
cold，私有库存不变。旧300.033耗尽、新118.279夹具路径失败依旧失败；路径
最小修正22.643秒通过后才新建完整fixture，未复活旧现场。
[准确七范围和来源](operations/evidence/regional-native-paged-cursor-capacity-20261005-outcome.json)
仅有限native library集成，不是主binary/完整窗口或故障资格。下一一次180秒
区分65之后新export完整contact证据、目的区真实import/maturity及cold；原
logical/wire/history容量、600/60/max24/2016及VALUE-STRICT-01义务不变。
完整故障、独立保管、长历史/crypto/physical与整项协议资格继续待验。

## 已完成的近期交付

**历史有限基线通过，仅适用于 quiet-broadcast 冻结来源 `8831a634...`、二进制 `72cb9d5f...`：
普通返程、一次原定有限故障及对应严格冷核验通过。**
依据为 `regional-quiet-broadcast-three-region-cycle-20261004.json`、
`regional-quiet-broadcast-joint-fault-fresh-20261004.json` 及对应 cold。
后续 traced 来源 `2309a181...` 与 `67ad71f1...` 的完整故障仍失败；`67ad71f1...` 的普通循环/冷核验通过。
当前邻居尝试位置修复来源 `7e729cd6...` 的组件、531 项过程回归及三个 Runtime 保管检查通过，
单次全新普通循环及严格停止冷核验通过；原固定观察控制器的隔离有限故障仍失败。
同一 Node 来源配合轮换原生观察控制器 `c2540450...` 的单次新有限故障及严格停止核验通过；
不能继承历史有限故障、持续负载及全部协议资格。
保持原成熟高度、票数、容量、24 高度上限、600 秒阶段窗口和实际 60 秒轮超时。
组件速度、运输收件和测试数量均不替代付款资格。

## 当前推进：实时普通接触链

2026-10-04 后续原生反例已验证固定观察副本会漏掉其他兼容认证前缀的成熟状态。
首个构造漏携带副本 0 的来源检查点，3.927 秒拒绝并保留失败目录；第二次采用
新目录并先检查缺依赖拒绝不改状态，完整携带后 6.130 秒完成实际 Native 反例：
副本 1 高度 2 未成熟，0/2/3 高度 3 成熟；观察期间私有字节/元数据不变。
控制器改为 1/2/3/0 轮换，每两秒最多一次完整 Native 读取，不保留旧收款结果；
两次实际读取取得成熟原输出，56 项相关观察/绑定/排空检查通过。
这只改变观察位置，不改 Native、成熟、票数、界限、无钥排空和停止全副本验收。
既有完整故障仍失败。新范围预算一、已用一，使用冻结控制器 `c2540450...`
及新隔离目录，运行 757.088 秒通过实际缺席领导者、隔离当地付款、TLS 追赶、
唯一导入/成熟及无钥证书排空。独立 verifier `43977d15...` 的严格停止核验通过：
E16/P14/A14、12 Native/4 recipient/4 custody、1,940 完整信封/4,348 档案，
300/300/0、私有字节/元数据未变；三份原请求已纳入账本、预留零。
这是精确同机有限范围通过，不能代替持续 BFT、独立保管或全部协议资格，
不能将以前同 Node/其他控制器的失败改称通过，也没有受控速度比较或唯一根因结论。
见[原生副本观察实施记录](operations/GROUND_NATIVE_REPLICA_RECEIPT_20261004.md)。

当前关键路径转向冻结正文 §6/§20 的精确发行递推及完整协议模型。
一次实际旧库判别 41.786 秒完成：17 点中 10 点与独立整数模型不同。
高度 5800001 的旧奖励少一 runlai；23400000 已全发，而规范仍剩一单位，
应于 23400001 释放。原库、167 文件来源、探测程序和差异向量均保留。
实际 Rust 奖励函数已改为储备 floor-half、前 m 个 slot 额外一单位及末期首槽释放。
新 `RLD-ISSUANCE-RESERVE-ERA-V1` 规则哈希 `a0ae7b36...`，直接价值采用声明
增加强制规则身份和新签名域；旧格式、旧域以及全四签错误规则均拒绝。
旧向量保持原字节，新域向量与 Python 独立参考另外绑定。首轮编译类型错误及
旧尾数向量失败保留；修复后两库 69 项检查通过，独立参考 21 点和 13 个拒绝
输入通过。发行库严格静态检查通过，完整价值库严格检查仍未通过：原有两处
字节未变告警及随后 120 秒检查预算耗尽如实保留，没有加入生产告警豁免。
该项以 `VALUE-STRICT-01 / OPEN` 单独纳入
[实施验收待办](operations/RLD_VALUE_SUCCESSOR_STRICT_ACCEPTANCE_TODO.md)：
下次触及该库或候选发布前修复；仅实际构建阻塞判断触发来源不变诊断。
诊断单次120秒，修复验证单次300秒，网络长测预算0；地区账本库严格检查不能替代。
一次新签零发行 fixture 在原 240 秒预算内 15.602 秒完成：171 文件源码
`de74cf78...`、全新创世及两层四签采用、实际首块和另一无钥进程从创世冷重放通过，
私有 fixture 字节未变；错误规则/旧域全四签拒绝，拒绝的尾部不改变状态。
该结果只资格发行/采用组件。当前区域 fixture 固定奖励和有限历史不能资格该递推，
普通 200000 块历史、跨平台及完整协议模型仍待完成，不迁移旧状态、价值与保管。
见[发行分量模型](research/RESERVE_ERA_ISSUANCE_MODEL_V1.md)。

§20 组合关键路径已增加[地区价值模型/原生合同](research/REGIONAL_VALUE_COMPOSITION_CONTRACT_V1.md)。
原单单位模型原样保留；新可执行模型将混合付款、找零、两地费用、通道容量、
挑战储备、关闭/挑战/结算、唯一导入、未终局孤立尾部和事故放入同一互斥 U/E/T。
12 个行为场景、四步前缀 6999 状态/11656 转换通过；模型不变量异常不会被当作
正常拒绝漏掉。实际反例拒绝退款、重复信用、丢掉祖先及自指/缺根。
争议费用接入后整笔承接容量和后续费用/找零/储备归还都须隔离，不能仅冻结费用。
精确混合样本事故前 U18/E14/T0，事故后金额不变而 U5/E14 不可用；挑战/结算
后 U32/E0/T0，后收到事故时 U19 隔离，另有 U13 的无关谱系保留。
这是带理想认证前提的金额/谱系模型，不是原生通道或完整协议 refinement。
另一个完整旧备份实质反例仍失败：无独立最新见证时旧视图能关闭、当前事故
视图拒绝；守恒与冷重放不足以证明新鲜度。下一原生通道/储备实现必须绑定
明确新规则和独立 caller/latest head，不从备份初始化签署权；不得把这些模型
搜索边界移入原生采用或重跑既有通过/失败的长范围。

随后实际实现独立原生通道执行核 `RLD-REGIONAL-CHANNEL-KERNEL-V1`，
最终区域来源 `26c9077a...` / implementation `d46df694...` / 规则 `a7d41f0b...`。
全部实际资金所有者与双方签名、U/E、一次储备消费/归还、旧最新头拒绝及
真实 Native 返程谱系事故检查有组件证据；仍未接入普通命令/状态根/钱包/恢复。
初次 fixture API 编译失败保留；修正后 188 原生回归及严格静态检查
233.806 秒通过，仅绑定其精确来源。逐条复核发现关闭同高度挑战缺口，
一次 3.075 秒反例确认并保留失败来源；改为 c+1…c+2016 后，五项组件场景
及严格静态检查 4.752 秒通过，实际原生资金第 17 储备原子拒绝。
组件高度边界不算真实 2016 区块，未重复有效长历史/网络故障或核心发行证据；
核心 171 文件仍逐字节绑定 `de74cf78...`。同序号冲突与后代、充分储备的收据、
普通执行/冷重放/钱包/保管资格未完成。下一判别是新准入下普通共享执行与
创世冷重放的 U/E/谱系根一致性，网络范围预算当前零；见
[原生组合合同及结果](research/REGIONAL_VALUE_COMPOSITION_CONTRACT_V1.md)。

同一主线继续完成普通原生区块/账本集成，新来源 `3dab638a...`、
implementation `2afd38e3...`、签署 profile `6da15554...`。
新 BFT/segmented value-channel 准入在新域强制绑定完整通道与发行规则；
旧准入/错误规则拒绝，3-of-4 与 4-of-4 阈值不降低。容量和储备进入 E/完整
NativeState 承诺，共享重放执行签署 prior head 的动作；新 origin 使用精确
储备 era 递推，旧固定奖励候选没有获得其资格。实际普通纳入、磁盘重启/
从创世冷重放、篡改尾部不改变头/余额、记录证明丢通道根拒绝、同块有序
开通/储备，以及 BFT 排队不扣款、证书前拒绝、三取四纳入/冷重放通过。
九项通道及严格检查 24.582 秒通过，另 184 项受影响回归跳过已过九项，
224.195 秒通过；两次 fixture 接口编译失败和一次包装器拒绝仍保留。
没有启动/重复旧网络范围；核心 171 文件和冻结正文/PDF/receipt 逐字节未变。
这是同机普通 Native 集成证据，不是默认网络生命周期、通道签署产品或完整资格。
下一缺口为同序号双签冲突完整证据及通道/储备/支付后代隔离，再接独立
所有者签署/恢复及充分储备收据。真实 2016 区块结算、完整地区组合/故障、
独立最新保护、PQC/历史/物理等全部目标仍未完成。见
[普通通道集成结果](operations/evidence/regional-native-channel-integration-outcome-20261004.json)。

本主线后续 V2 来源 `05ac7769...`、implementation `a608bb58...`、签署
profile `ecc6a0fb...` 实现通道同序号冲突的完整资金来源/双方签名证据。
Coin/Export/Escrow/Reservation 的 checkpoint 与 channel identity 并集总界限
仍为 64，原生 Open/费用/找零/储备/挑战/结算/跨区进口及返程完整传播。
真实普通 Earth→Proxima→Earth 及后代通道样本中，事故隔离相关容量、
储备、费用和支付后代，保留全部负债与永久进口；无关成熟输入仍能付款。
后续同 ID 坏签名拒绝，原事故字节不改；另存旧头拒绝，真实关库/重开、
损坏证明拒绝与准确 recover-only 保留残片、私有 seal/fresh restore 通过。
Finality/channel 合计原 16 事故界限保持，第 17 条拒绝并保留准确 pending
guard 和原 16 原件，随后开库拒绝；native contact V3 无降级接入完整证明。

首编译拒绝、第一行为范围返程缺当地终局（11 过/1 失败）、后续严格检查
拒绝过大 enum 均保留。新 fixture 补真实原生四签 finality，未降低门槛；
enum 改为 Box 保持完整 JSON 字节语义。最终 13 行为及严格检查 19.716 秒通过，
另 184 回归跳过已过范围，用单次 300 秒预算在 224.694 秒通过。
同一最终来源共 197 检查通过，核心 171 文件和冻结正文/PDF/receipt 未变，
旧失败 fixture 原件不变，网络 campaign 新预算仍为零。
这仅是明确提交通道事故与已测后代隔离的同机原生资格；自动 off-chain
冲突观察、强制充分储备的 receipt/top-up、所有者首次签署/恢复、真实 2016
普通区块结算、完整网络故障、独立/PQC/历史/物理与全部目标仍未完成。
上一轮下一步将 16 上限误写成收据最低数量；按冻结 §7 纠正为足额成熟
挑战储备，原核/事故检查并未实施该错误门槛。下一反例针对不足/占用/
不成熟储备、旧头及无效状态的收据拒绝，
先定义准确新 fee/receipt/custody 契约再推进。见
[通道事故结果](operations/evidence/regional-native-channel-conflict-outcome-20261004.json)与
[原生组合合同](research/REGIONAL_VALUE_COMPOSITION_CONTRACT_V1.md)。

同一主线完成 V3 收据接受，来源 `ef4e853b...`、implementation `40582c17...`、
profile `905c2d87...`。新 native receipt 把双方前后状态和双方发票签名绑定
准确 amount delta、checkpoint、chosen reserve、预算和上一 receipt/state。
当前认证 open funding、另存 exact storage head、当地 invoice expectation、
正常事故/完整谱系检查同时满足后才接受；一笔成熟储备需独立支付该预算。
原 native 挑战费整数下限仍为 1 runlai；收款方可钉更高且双方签署的预算。
实际预算 3 的缺/不足储备拒绝，成熟 top-up 后两笔储备就可接受，纠正
此前动态下一步的“最低 16”错误；16 是原容量上限，冻结正文 §7 未改。

接受先持久追加普通 native history event 再响应，U/E/T 账面不变。
精确重试逐完整 envelope 认证并返回原历史 receipt，不接受另一付款；
同 ID 坏签名拒绝；完整同序号不同分配收到后保留原生事故，隔离原负债。
普通重开从创世重放最高已接受状态、发票去重和准确 prior link，
私有 image 恢复保留 receipt；旧头、坏 journal tail 和 publication 残留拒绝。
第 256 receipt 全部真实双签、分页持久化及冷重放通过，第 257 拒绝；
contacts/receipts 共用原 256 上限，分页/逻辑/事件/档案界限保持。

首次字段引用编译失败、第一容量 fixture 把 256 event 放进巨型 tail
被原 16-event 分页限制拒绝（18 过/1 失败）均保留，失败私有根未改。
新 fixture 按原整页规则持久化，19 行为及 strict 70.665 秒通过。
同来源实际 CLI 新签零分配 init、ordinary open/reserve/certification、
接受/落盘、旧头拒绝、逐进程重开重试、坏签名拒绝 20 steps / 2.598 秒通过。
另 184 受影响回归跳过已过范围，单次 300 秒预算内 242.398 秒通过；
同一来源合计 203 检查通过，核心 171 与冻结正文/PDF/receipt 未改。
没有第一 owner signing 服务或独立 caller custody/最高已签序号资格；
最高已接受与已签署仍有区别。看守/包含、重组、全回滚/复制钥匙、
实际 2016 区块结算、完整默认网络/独立/PQC/历史/物理与全部目标未完成。
下一主线为 purpose-bound 首次状态/发票签署、最高签署序号及 exact response
恢复的原生保管契约和反例。网络 campaign 新预算仍为零。见
[原生收据结果](operations/evidence/regional-native-channel-receipt-outcome-20261004.json)。

V4 原生 owner 签署组件来源 `e2357a40...` / implementation `89bcf211...`，
在单独私有日志中先持久化自身 initial/state/invoice partial，再返回响应。
准确 current native/owner heads、完整 funding/prior state、金额差和成熟储备
必须满足；另一份同序号请求、坏签名/头、未完成创建和发布残留拒绝。
keyless recover-only 只促进准确已签的一条 pending response，普通 open 不促进，
缺签名不首次签。两实际 owner partial 经 native combine 后仍需完整 receipt
接受，普通账面不变；只给一份或 unsigned 不能接受。
首次 compile 的局部 IO/review错误保留；修正后25 native行为及all-targets
strict 50.408秒、实际CLI42steps/5.605秒通过；余184回归单次300秒内
222.917秒通过，已过25/strict/CLI未重复，共209检查。旧价值库
`VALUE-STRICT-01` 仍独立 OPEN，无 production豁免，冻结正文/PDF不变。

**同来源的 owner 创建安全仍失败。** 最小新目录反例6.170秒确认：原最新
头/日志仍存在、native view不变，同key的新目录仍能签另一序号1分配
40/20的有效own partial，原partial为50/10。对手未重置、第二收据未接受，
账面与旧头保持；反例完成不能称inception/防重置通过。现有锁/最高序号仅
保护一个目录，不能把fresh create当合格restore或声称S11成立。
下一主线绑定完整原保管inception/continuation与独立最新见证；缺见证只读。
新source后单次180秒focused/strict及一次120秒必要CLI判别，网络预算0；
普通wallet-app、channel action signing、encrypted channel backup、真实中断/
重组/看守/完整窗口/网络/PQC/独立/历史/物理继续未完成。见
[所有者签署及失败反例](operations/evidence/regional-native-channel-owner-outcome-20261005.json)。

## V5 通道签署见证：有限地面实现

来源 `b40fdba7...` / implementation `e5062c65...`、binary `8ddd9641...`。
完整 funding 的实际 owner/双方签名指定单独 witness role；公开签署服务要求
分别留存的 native/owner/witness 头与完整认证保管扩展。原 inception 已在见证
留存时，同钥新目录拒绝；无 policy/头或旧 owner backup 拒绝。先持久保存 own
原签名，再见证准确扩展，完成后释放响应；见证失败不回滚/退款。显式首次
见证确认不读 owner key，无钥恢复不能补首次见证批准。

首轮29行为通过但strict因8处测试简写告警失败，未豁免；修正/API接入后
29+build+strict 56.945秒，实际入口7.492秒通过。余184回归在该旧V5来源
`f4815c09...` 单次222.899秒通过，不能说在最终来源全部重跑通过。
后续3.119秒最小反例观察到错误owner头返回拒绝但已发布pending witness，
安全失败与新私有fixture保留。修复将所有caller/完整响应/所属检查前置；
一次preview返回值编译拒绝1.324秒也保留，未启动fixture。最终准确来源上
29行为/build/无豁免all-targets strict 48.575秒通过；全新实际入口49步骤
8.371秒通过：错owner头后两日志/pending不变、准确无钥恢复、同钥reset拒绝、
见证失败后禁止补签及显式完成、两party完整收据接受/重试且货币账面不变。
只改三处通道保管/测试文件，未重复184项未受影响长历史检查或任何网络长测。

此见证角色同机/同进程，receipt及Close/Challenge尚不携完整见证认证，
返回witness_head不授予资金权限。实际中断、独立保管/全回滚/copied keys、
长期见证容量/轮换、wallet-app/完整加密channel备份、full faults/历史/物理
仍未资格，S11及整个协议未完成。旧V4 reset与旧完整故障不会被本通过替换；
`VALUE-STRICT-01` 仍独立未通过，冻结正文/PDF/官网不变。
下一可证伪主线为完整receiver/state proof的见证角色/inception/native认证，
先模型/最小判别单次120秒/1次、网络0；不能只加入hash或降级旧profile。
[准确结果与失败](operations/evidence/regional-native-channel-witness-outcome-20261005.json)，
[权限与恢复契约](research/REGIONAL_CHANNEL_WITNESS_GROUND_CONTRACT.md)。

## V6 完整通道状态见证：原生授权接入

最终来源 `02a15cfc...` / implementation `406c2631...` / binary `52fab24e...`。
新资金条款强制单独 witness role；两实际 parties 与完整 witness proof 共同
认证 state，receipt 逐字绑定 invoice 与原始 inception。Close/Challenge 和
conflict/cold路径共享此验证；原生receipt历史固定上一完整授权声明。
普通combine只构造未授权草稿。Witness V2在原256项/8MiB内保留双方原native
birth/advance与seal，确认完全相同的最高已见证请求；更高未确认 own response
不能seal。无钥recover-seal只恢复准确已签正文，坏body/头不发布pending。

V5录制 native通过的party-only收据已只读验证真实双方签名/ID和精确来源；
它确实缺witness proof，新版真实入口拒绝这类草稿。原观察器两处域/返回字段
错误、两次测试helper编译拒绝及一次30/31资金构造下溢均保留；修复是选择
实际够61单位的input，不按新currency改变的coin ID顺序假定金额，未改参数。
源 `0e76e12c...` 上31 focused/build/strict 63.667秒、184剩余回归221.956秒
及56步全新实际入口11.763秒通过，共215 native检查。最终审阅只改两处签署
规则V5→V6文字标签，所有Rust/Cargo/build/tests字节完全相同；复用215证据，
没有称最终identity又跑215。新身份重建/无豁免strict3.473秒及56步全新入口
11.305秒通过：拒缺见证/坏proof、完整持久seal接受、删钥恢复，无货币credit。

原128/8MiB owner、256/8MiB witness（含seal）、共识/费用/成熟/2016窗口/所有
其他容量保持，网络长scope0。Witness签署的inception承诺并非独立私有保管或
绝对最新证明；旧有效状态仍可能进入关闭窗口，不能声称已自动watch/challenge。
旧完整故障/reset继续失败，旧价值库VALUE-STRICT-01仍独立未通过；S11、全协议/
独立/全回滚/copied keys、长期容量/续证、watcher/inclusion/完整窗口、物理仍未资格。
下一可证伪主线：已接受较高状态面对低状态Close，使用原成熟授权reserve构造
无钥native挑战并正常纳入；最小新模型/反例120秒/1次、网络0，保留原规则与失败。
[V6实现及失败](operations/evidence/regional-native-channel-state-witness-outcome-20261005.json)，
[最终内容身份与复用边界](operations/evidence/regional-native-channel-state-witness-final-label-outcome-20261005.json)，
[权限契约](research/REGIONAL_CHANNEL_STATE_WITNESS_REQUIREMENTS.md)。

当前父块 Prepare 的已认证停止观察显示约 40.180 秒来源等待，其间 20 次准备因本地争用拒绝。
四固定邻居、四尝试槽的旧游标每轮起点不变。实际 TLS 周期争用反例只服务 2/4 邻居；
仅改变起点的互素步长后，同样四轮取得 4/4 双端精确持久收据。该受控租约不是 Native CPU，
不证明唯一旧故障原因或无条件活性。新 397 文件来源 `7e729cd6...`、驱动 `e5f72ec4...`，
531 过程检查及三个 Runtime 保管边界通过；Native/core 字节未变，复用原有效 Native 证据。
按单次新普通范围决策，使用新目录及独立 controller `50259ae2...`，保留 600 秒阶段、
60 秒轮、24 高度、成熟/票数/容量。预算一、已用一，普通循环 759.140 秒及冷核验
63.086 秒通过：E11/P4/A4、300/300/0，12 Native/12 recipient/4 custody、
784 完整信封/1,824 档案，私有字节/权限未变。新普通不替代完整故障资格。
对应一次全新隔离有限故障范围已启动，唯一预算一、已用一；以该停止合格普通范围
为来源，绑定 Node `7e729cd6...` / binary `e5f72ec4...`、独立 fault controller
`20d5427a...` 与 cold verifier `4bb57a09...`。826.144 秒后因原 600 秒唯一导入/成熟
门槛耗尽而失败，所有节点停止。缺席领导者、隔离当地认证及追赶通过，不能算整个范围通过。
新失败报告/源/请求保留；单次预算已用完，不原样重跑。严格失败停止核验 264.871 秒通过：
12 Native/4 recipient/4 custody、2,015 完整信封/4,515 接触档案，私有字节/权限未变。
最终 E17/P13/A16；四个净额 9 收款都在 11 导入、13 成熟并可花费。原三 owner 请求
已纳入当地账本、预留零；没有重签、退款或替换。停止成熟不证明窗口内探测通过，
后续无钥排空未执行，整个故障范围保持失败。
一次停止时间判别 2.724 秒通过：精确冷认证高度 13 证书的 Native 安装/入队标记显示
Proxima 0/2/3 在保守最早截止界前已安装；固定探测副本 1 缺少对应截止前证据，
完整接收标记在该界后约 1.446 秒，但不能据此认定实际安装也晚。未知间隔/未发布尾部保留，
没有伪造精确截止或单次 Native 探测结果。下一步为固定滞后副本与已认证领先副本的
最小 Native 观察模型，未授权新的完整重跑。位置轮转修复不授予完整故障资格。
成功需缺席领导者、隔离当地付款、追赶、新出口唯一导入成熟、无钥证书排空及完整停止冷核验；
失败停止保留，不原样重跑。见 `regional-outbound-peer-phase-joint-fault-stage-decision-20261004.json`。
反例、修复与边界见[出站邻居尝试位置](operations/GROUND_OUTBOUND_PEER_PHASE_20261004.md)。

H-service 已判别为目标保管之前的服务延迟/拒绝，具体全部原因仍待证明。新增默认关闭的有界私有追踪，区分来源入队、普通准备、
TLS 请求、实际保管、目的回执与 Native 完整接收。最小真实进程样本已关联
同一个包、请求 nonce 和完整信封，无事件丢失；一个启动状态缺失样本明确记为未知。
四份观察者失败原件保留，macOS 解释器启动映像/语言环境注册错误已由短进程反例修正。
新冻结 396 文件 `2309a18199c5e7714017b56780001cbdf2527c57b574cc759d09d83ebc9f4c57`，
默认启动程序重建、527 项完整过程回归和三个真实 Runtime 保管阶段已通过；
184 Native/strict 复用逐字节未变的既有证据。全新普通三地区循环 757.729 秒及停止冷核验 63.199 秒通过：
E11/P4/A4、300/300/0，12 原生、12 收款、4 时代保管、1,792 档案，
私有文件/权限不变。普通循环实时追踪有启动/实例上限缺口，不能据此归因。
预算内唯一完整有限故障判别已失败：600 秒内新出口未导入成熟，停止 E13/P11/A12；
守恒 300/290/10（未交付净额 9）。严格停止检查 213.504 秒通过，
12 原生、4 收款、4 时代保管、1,749 完整信封及 3,906 档案，私有字节/权限不变。
三份原 owner 请求均已纳入本地账本、预留零，不替换或退款。
实时 12 个 actor 环无淘汰或拒绝记录；54 条当前父块路径中 12 条无目标信封/回执。
观察到中间保管至首次转发准备约 31–64 秒，以及来源超时包约 88 秒等待；
支持目标保管之前的服务阻塞，尚未区分选择、租约等待或验证 CPU。
单次完整范围预算已用完，不原样重跑。真实 TLS 本地转交反例已复现：
没有实际 Mesh 租约时，前台保留的空闲选择意图仍阻止持久接收；
前台重新选择后同一请求取得实际保管。该锁外暂停为受控屏障，尚未归因全部 Native CPU；
修复将重试 owner/purpose 与调度优先权分开：真实争用/实际 EAGAIN 结束后原有 0.2 秒
窗口保留优先，空闲意图不再无限阻断 TCP。第二份真实 TLS 对照约 0.696 秒通过：
窗口过期后两次双端实际持久收据、完整 transit 抑制和原线程随后重试均核验。
首次 packet ID/transit 摘要观察断言失败原件保留，修正观察器后仅用新目录重验。
50 项相关回归通过；独立审阅后的测试时序屏障已修正。新 396 文件来源冻结
`67ad71f18be1578005caab76689297d7b12f8ba1d46c9e804bc72ced6fd2d858`，
Native/core 未变，默认驱动重建完成；528 项完整回归约 286.381 秒、三个 Runtime
保管边界约 3.592 秒均通过，184 Native/strict 检查复用逐字节未变来源证据。
本地两组件判别预算用完；没有新的完整故障资格，旧失败保持失败。
新普通范围 346.082 秒后因控制器读取 null 可选观察抛错而失败，干净停止 E8/P4/A0。
严格停止检查 31.436 秒通过，12 原生/4 时代保管/492 信封/1,088 档案，私有字节/权限不变。
控制器未知观察处理独立修复，保留原窗口及四副本完整判据；分离控制器冷核验来源绑定
也已提前修复。87 项冻结/相关检查通过；节点来源/二进制完全未变，失败不恢复为通过。
该单次新普通范围已完成：724.131 秒循环、60.450 秒冷核验通过，E11/P4/A4，
12 Native/12 收款/4 保管、788 完整信封/1,760 档案，300/300/0，私有字节/权限不变。
Node `67ad71f1...` / binary `3019b6d9...` / controller `50259ae2...`，不重复该已通过长测试。
原范围会话已终止，无并行原节点进程。下一条有界调度修复的有限故障资格假设、单次预算及
成功/失败退出分支见 `regional-bounded-preference-joint-fault-stage-decision-20261004.json`；
采用已封存的新普通来源启动新隔离副本，不复活旧失败或改其请求。
新范围已实际启动一次，使用精确 Node `67ad71f1...`、fault controller `20d5427a...`
及分离 cold verifier `4bb57a09...`，本范围追踪开启；预算使用记录见
`regional-bounded-preference-joint-fault-scope-start-20261004.json`。814.699 秒后完整范围失败：
缺席领导者、隔离当地付款和离线节点追赶通过，新出口在 Proxima 高度 12 唯一导入，
但原 600 秒内停在 13，四收款均 `IMPORT_ACCEPTED_IMMATURE`。停止 Native 前缀
E16/P13/A16,16,15,15，守恒 300/300/0 不等于成熟付款通过。
严格停止核验 265.007 秒通过，12 Native/4 收款/4 保管、2,014 完整信封/4,504 档案，
私有字节/权限不变。三份原 owner 请求全部纳入当地账本、预留零，最新独立头匹配；
不重签、替换或退款。单次完整故障预算已用完，不原样重跑；旧失败均保留。
下一步按 `regional-bounded-preference-postimport-stage-decision-20261004.json`，
在已认证停止范围上判别当前父块完整信封交付与 Native 接收，不启动 Runtime 或签署。
预算、观察边界与决定见[实时接触采集](operations/GROUND_CONTACT_TRACE_CAPTURE_20261004.md)。

## 已有资格基线与失败原件

运行来源 `7c5b78c85d1b50640ce2d783fd752d7c818387e9be4ddcae3bb208003d4c4c61`，
387 份完整清单；Native/core 与此前已核验源码逐字节相同，默认启动程序精确重建。
运输修复及六项冷启动/锁回归已按明确清单合入 `06660aa`，未发布。

| 检查 | 实际结果 | 判定 |
| --- | --- | --- |
| 冻结回归 | 486 过程检查、3 实际 Runtime 保管阶段通过；184 Native/strict 引用相同 Native/core 的既有证据 | 回归通过 |
| 普通三地区返程 | 743.120 秒；12 原生、12 收款、4 时代保管、1,728 档案冷核验；issued/liquid 300、in_transit 0 | 同机有限循环通过 |
| 原定完整有限故障范围 | 912.029 秒；缺席 leader、隔离当地付款、追赶通过；恢复后新出口未在 600 秒内导入成熟 | **整个范围失败，原件保留** |
| 失败范围严格停止核验 | E14/P12/A16；12 原生、1,989 完整 BFT 信封、4,369 档案、4 时代保管通过，私有字节/权限不变 | 核验失败状态，不替代资格 |
| 三份原始 owner 请求 | INCLUDED_IN_LOCAL_LEDGER、预留零；各自独立最新头及签署高度重放匹配 | 不替换，不退款 |

四个 Proxima 收款检查均为 VERIFIED_EVIDENCE_PENDING_IMPORT，未导入、成熟或可花费。
兼容前缀守恒 issued 300 / liquid 290 / pending_exports 10；Native 候选试算不足半秒。

## 历史 quiet-broadcast 实现与有限验证范围

当前候选运行来源 `8831a6348cbb08772d09f302ea2620a595b0b97b13d9d6e90fc0c3e90c140199`，
388 份完整冻结清单，Native/core 逐字节未变；默认启动程序精确重建，构建 37.96 秒。
已通过并按明确文件清单合入主目录以供审阅，未发布：

- 真实 Runtime 双进程对照：旧候选重复广播重新占锁并拒收入站；新候选在所有完整
  原生信封/收件方副本已持久化后避开空读取，入站落盘、目的回执及 Native 认证通过。
  实际构造全新 Native Runtime，签署头不变、记录零；未调用共识 tick 或首次签署。
- 完全相同且已确认完整排入的原生信封/收件方清单可暂缓空读取；只有进程内有界
  调度提示。变化、容量、失败、重启、四秒或十六次定期复查均走完整 Mesh 路径。
  每份后来接收的完整证据、依赖/时代同步及新鲜 Native 头/签署检查继续强制执行。
- 真实启动失败过程对照：旧消费者在构造失败后仍存活；新候选停止并加入实际启动
  的线程。接收/发送意图区分、原两槽内至多一个未确认延迟输入及活消费者重试一并保留。
- 五项针对性检查以及 **491 项完整过程回归、三个实际 Runtime 保管阶段全部通过**。
  Native 的 184 项测试/strict 检查引用相同 Native/core 的既有证据，本轮明确未重跑。

全新普通三地区付款返程 **673.309 秒通过**，干净停止与严格冷核验 **60.350 秒通过**。
E11/P4/A4 四副本一致；12 原生重放、12 收款、4 时代保管、788 完整 BFT 信封及
1,744 档案核验通过。兼容前缀守恒 issued/liquid 300、in_transit 0，私有字节/权限不变。
原定完整有限故障范围 **881.112 秒通过**，严格停止冷核验 **240.974 秒通过**。
缺席 leader、隔离当地付款、追赶、新出口唯一导入成熟及暂停签署排空均通过。
E13/P15/A14 四副本一致；12 原生、4 新收款、4 时代保管、1,934 完整 BFT 信封、
4,268 档案通过，守恒 300/300/0，私有文件不变。**本轮唯一近期交付已经完成。**
旧失败目录、支付、保管和证据均未改写或迁移；没有恢复旧失败范围或计作通过。
后续按 [资源预算与剩余门槛](operations/GROUND_RESOURCE_AND_GATE_MATRIX.md) 推进；
一次有限故障成功不资格持续负载、长期历史、独立/跨设备保管或物理路线。

此前运输四进程诊断本身未调用本次修改的 `Runtime.broadcast`，仍保留原失败判定，
没有补记为压力通过；不靠改写该模型证明修复。当前资格取决于完整真实 Runtime
回归及新普通/故障范围，不提高原成熟高度、票数、容量、24 高度上限或 600/60 秒窗口。

此前本地 1.12 修订及 23 页 PDF 检查是历史出版准备记录，不是当前冻结正文。
最终无展示版本号白皮书已由用户确认正式发布；当前目标只采用顶部冻结正文/PDF 哈希。
本任务不再修改或发布官网、正文或 PDF；实施记录继续演进，文档对齐不提供 I1–I12 的完整资格。

第 1 个后续门槛已有[资源采集契约](operations/GROUND_RESOURCE_CAPTURE_CONTRACT.md)与
独立只读采集工具；15 项检查及 2.275 秒实际 CLI 诊断通过，完整来源/二进制字节绑定，
三个进程/存储样本、私有日志关联和原目录 7,219 份文件元数据不变均已核验。
诊断进程是本次拥有的短命 sleep 子进程，存储为一个停止的通过样本目录；
没有启动节点或 Native，没有新增持续负载资格。原生价值、每跳字节和完整短命子进程
覆盖仍待接入；明确保留未知和采样间隙，不将样本最大值当作持续峰值。

随后接入有限故障控制器的原生价值审计（原十二 status/三 proof 调用不增加）：
完整认证响应与兼容检查点关联，分别记录未交付毛额/净额，拒绝重复或不匹配导入。
原生/流/资源 29 项、相关控制器 23 项、度量绑定 6 项检查通过；真实停止样本的
15 次原生读取通过，300/300/0 与全部 7,219 份私有文件字节/权限不变。
显式全跳计量使用独立冻结控制器来源 `20d5427a2547fdb699cca679aec152136b3e2a756f044a082a0347a21891e2a7`，
节点来源/二进制未变。新增 22 配置方向有限故障**失败**：净额 9 已在 P13 导入，
停止 P14 未达到成熟 P15，原 600 秒内未成熟。严格停止检查 240.425 秒通过，
覆盖 12 原生、4 收款、4 时代保管、1,990 完整信封及 4,317 档案，私有字节/权限不变。
92 个十秒资源样本与全部 22 方向累计流计量已关联；单进程 RSS 采样最大约 786.7 MiB，
主进程 CPU/存储观察不覆盖完整 Native 子进程或全节点成本。
后续采集器 V2 可显式观察主进程加已退出子进程 CPU，真实父进程和 47 项组件/日志
检查通过；尚未接入旧运行，也不覆盖完整活跃子进程 CPU/RSS 或持续负载。
停止 Native/薄路径同步/分配探针已经完成，否定完整帧 witness 的高 RSS 猜测；
下一活动假设、单次新范围预算与退出分支见
[成本判别](operations/GROUND_RESOURCE_COST_DECISION_20261004.md)，先补实时普通承载链。
原范围与旧失败保持原判定；见[实际度量与剩余缺口](operations/GROUND_RESOURCE_METRICS_FINDINGS_20261004.md)。

## 证据与发布边界

主资格证据：`operations/evidence/regional-fair-carriage-source-inventory-20261004.json`、
`regional-qualified-fair-carriage-frozen-checks-20261004.json`、
`regional-fair-carriage-three-region-cycle-20261004.json`、`regional-fair-carriage-three-region-cold-20261004.json`、
`regional-fair-carriage-joint-fault-fresh-20261004.json`、`regional-fair-carriage-joint-fault-failed-cold-observations-20261004.json`、
`regional-fair-carriage-joint-fault-owner-head-observations-20261004.json`。
本轮：`operations/evidence/regional-qualified-quiet-broadcast-component-summary-20261004.json`、
`regional-qualified-quiet-broadcast-frozen-checks-20261004.json`、`regional-qualified-quiet-broadcast-source-inventory-20261004.json`。
普通范围：`regional-quiet-broadcast-three-region-cycle-20261004.json`、
`regional-quiet-broadcast-three-region-cold-20261004.json`。
故障范围：`regional-quiet-broadcast-joint-fault-fresh-20261004.json`、
`regional-quiet-broadcast-joint-fault-cold-20261004.json`；资源：`regional-quiet-broadcast-ground-resource-baseline-20261004.json`。
资源采集组件：`regional-ground-resource-capture-checks-20261004.json`，不替代新增负载范围。
原生/流接入组件：`regional-ground-value-stream-components-20261004.json`；
冻结控制器清单：`regional-ground-metered-controller-source-20261004.json`。
新增计量失败范围、资源、严格停止检查及来源关联见
[度量发现与完整证据清单](operations/GROUND_RESOURCE_METRICS_FINDINGS_20261004.md)。
此前诊断和来源：[原样保留状态](operations/history/PLAN_STATUS_before_qualified_quiet_broadcast_20261004_1a0a9f7774e5.md)。

公开仓库仍为已验证 v55；v56 材料完整延后保存。不发布微优化或失败变体。
失败状态、签署证据及私有头不改变；不恢复失败范围为通过、不迁移价值、不提高上限或剪除证据。
独立运营、物理链路、长期断连/历史、跨设备保管及真正跨星际资格仍未完成。

## 2026-10-05 V7 原生自动挑战及费用安全失败

原生 watcher 现在从完整 accepted-receipt 历史重建最高状态、核验准确储备和
签署费额、按绝对deadline/原四slots构造无钥Challenge。普通V7 BFT candidate
优先携带，完整原生 quorum/finality决定纳入；本地head观察不是独立最新权威。
34 focused/build/无豁免strict终止通过，双通道native实际certificate/cold重放
通过；新鲜无价值CLI在owner/witness钥文件删除后执行watch/普通mine/cold。
原试验与S11/2016/full-fault/独立/物理资格保持分开。

**R-CH-FEE-01 OPEN / 未通过：** Native实际接受q1/q2后，合法Challenge(q1)
会消费最高q2选择的one-use reserve。Watcher报告覆盖丧失，不能保护q2；
这不是成熟/守恒或调度通过能代替的安全资格。禁止以该receipt接受为生产安全
付款采用。下一一次120秒模型先判别完整费用授权，原账本/余额/失败不迁移、
不退款、不增加16储备最低门槛。[准确契约/反例](research/REGIONAL_CHANNEL_WATCH_REQUIREMENTS.md)。
共享回归因实际BFT候选路径改变一次300秒，184项于221.791秒终止通过；
准确来源共218项native行为、无豁免strict/build及70步CLI通过，不启动network。
最终来源 `4110ffc4...` / binary `57dd7cd9...`，见
[准确结果及未通过项](operations/evidence/regional-native-channel-watch-outcome-20261005.json)。
旧价值库VALUE-STRICT-01仍OPEN，地区strict不替代；冻结正文/PDF/官网不变。

## 2026-10-05 V8 显式费用预算及最高状态覆盖

原V7 R-CH-FEE-01失败仍保留。V8新owner授权绑定累计max_fee及原input；
每次只支出fee，剩余保护金额继续E直到settlement。充分新receipt还须核对
原2016*16 native slot的最坏费额覆盖，不增加16储备最低数/容量或每次fee。
36 focused/build/无豁免strict终态通过，q1后q2原生挑战/完整cold/BFT候选检查
通过；首CLI控制器旧钥断言失败，准确原件保留，更新控制器仅新目录通过。
尚未完成Runtime/TLS实际看守/完整窗口/持续fault/独立安全及S/R/I/A-G/N/P。
见[准确新授权与失败边界](research/REGIONAL_CHANNEL_FEE_BUDGET_REQUIREMENTS.md)。

V8最终来源 `c2b5e8bc...` / binary `838873ba...`：36 focused/strict/build79.902秒，
83步实际CLI24.334秒均终态通过；184未变共享分支引用V7来源4110ffc4的原证据，
未复跑，不能说220项都在新身份重跑。首47步失败10.578秒原件保持。
[源绑定结果/复用边界](operations/evidence/regional-native-channel-fee-budget-outcome-20261005.json)。


## 2026-10-05 原生因果冷核验成本与驱动读取修复

首一次120秒离线范围26.347秒因把Rust字段顺序误作mesh状态canonical排序而失败，
整个167文件currency封存，不再打开Native/Runtime或恢复/重签/退款。独立有界
Native JSON读取修复只处理语法；重复字段、非有限/溢出数、静态符号链接和超限
拒绝，三回归exit0及0.087秒真实队列反例通过，不能授予原生权威。

驱动修正后的全新零分配离线范围一次120秒，27.816秒exit0；无Runtime/网络。
完整原生E6→P5→A3→E1实际进口/成熟，最终E7/P4/A4、三ledger、12独立voter/caller
及三原owner，I=U=1.75×10^30、E=0。四完整单份0.318651秒对原四份批量
0.078273秒（4.071倍），六独立停止查询0.463866秒；坏后certificate、缺因果依赖
和第五份越界均拒绝，原生/owner/voter/caller字节未变。旧7672文件及报告/freeze
pin不变，当前自有进程0；172文件成功小样本另存私有停止inventory。
启动/open/同过程完整认证重用成本未分离，不能解释旧E11/P7/A9深度或唯一600秒
原因，也不能证明新普通cycle/fault；26.347/600.666失败仍失败。

下一可证伪假设：一次固定独立最新头/OS锁/full-genesis只读Native入口逐批完整
认证可减少重复进程/开库成本，而坏后信封、旧head、incident、输入变化仍整体拒绝，
不释放部分成功。准备explicit bounded cold plan，每批原4份/8MiB、wire3MiB、
总512保持；摘要只绑定输入，无serialized ledger权威，不恢复incident或签署。
一次300秒源码/编译/focused strict，再一次120秒新来源全新零分配CLI等价/拒绝/
私有字节检查，网络cycle/fault预算0。首失败/完整判别/预算退出。改变Native须
新身份和全部全新签署fixture；旧来源证据保留原scope，不能自动继承资格。

原goal已读回active，持久cwd仍旧为界面待修，所有命令显式新workdir。规范采用
AGENTS/receipt的正文2ba62421/PDFc59f9fe8和全部S/R/I/A–G/N/P；goal旧前继哈希
引用在本原线程/动态记录报告，父线程传达未确认，不改冻结正文/PDF/官网。
VALUE-STRICT-01/完整cycle/fault/2016/source66/post64/独立/PQ/physical继续OPEN。
[准确来源、成本与下一判别](operations/evidence/regional-native-causal-cold-cost-outcome-20261005.json)。


## 2026-10-05 固定头原生只读冷核验入口

新Native来源89408f5a / implementation8a361699 / release binarya45387fa，
新增独立固定最新head的cold plan：一次OS锁/full-genesis开库，每批完整认证，
最终头/事件/分页manifest/输入目录复查，后置失败不返回部分通过。保留每批4份/
8MiB、wire3MiB、总512及原archive/history/成熟/票数限制；没有恢复、签署或入账。

首源码检查19.164秒编译类型错误失败，修正后一次300秒范围30.142秒完成六新边界
测试、四原cold-batch回归、lib/tests/bin无豁免strict及dev build。首CLI3.421秒
因驱动按字符串而非Rust路径组件计算source而被Trust拒绝；错误身份及两文件保留。
修正身份后的dev CLI原120秒范围121.752秒耗尽，最后完整日志E6，**未进入cold plan**，
整个160文件currency封存，不打开Native/Runtime、恢复/重签/退款。诊断核实旧样本
用release、本轮误用dev；只重建release23.806秒通过，未复跑相同源码strict。

再一次原120秒全新零分配CLI范围32.956秒exit0。原生因果E6→P5→A3→E1实际
进口/成熟，E7/P4/A4及I=U=1.75×10^30、E=0；三原owner、12独立voter/caller
字节不变。八原四份批调用0.682524秒对新八批计划0.388514秒（1.756755倍），
128批512份有序重复完整信封5.181516秒通过；不是512份不同复杂证明负载。
坏后完整certificate、缺因果依赖、旧/零头、第五份、513总份数、输入摘要变更拒绝。
CLI额外两个新零高度Native targets只测pending marker及坏retained incident，字节
保持；完整已认证未索引incident另由新Native边界测试证明，不能混称CLI证据。
成功scope208文件留私有inventory、当前自有活动进程0；所有旧失败/报告/freeze保持。

这是Native组件/小历史controller证据，普通Runtime尚未采用。来源87旧严格测试
保留原scope，不继承到来源89；旧600.666失败、完整cycle/fault、2016/source66/
长期历史/独立/PQ/physical/旧价值strict仍OPEN。下一一次120秒停止适配器判别，
调用者明确提供分别保留最新Native头，保留完整原信封有序多重引用和值、逐输入/响应
绑定、不构造Runtime或恢复保管、不自动采用现观察头；首失败/完整判别/预算退出，
网络cycle/fault budget0。当前成功Native root仅可distinct只读，两个注入incident
目标和旧失败currency禁止Native/Runtime打开；必要时新夹具，不迁移价值。
[准确源码、结果、失败和下一范围](operations/evidence/regional-native-cold-plan-outcome-20261005.json)。


## 2026-10-05 明确固定头的停止适配器

新显式停止入口先使用调用者传入的独立保留非零history head做完整Native history-check，
从该结果取得当前height/tip，再重建准确原信封，原4份/8MiB分批、512总份数/
256MiB处理及archive上限；通过原生固定头计划全认证后才报告完整成功。空表仍须
固定头原生检查。没有自动采样/adopt、Runtime构造、保管恢复或新签署；旧入口和
普通启动cold-batch路径保持原行为。Native message IDs是完整展开原生信封ID，
不是Python body hash；用整个有序批字节摘要和有序value/数量/域/头/响应flags绑定。

一次120秒范围2.961秒exit0：八新机械边界、七原cold-batch、五原stopped回归；
另五真实完整Finalized/submission信封，59snapshot refs/12共享准确完整快照，
162070状态字节/606511展开字节。原Native Source89/implementation8a361699及
release binarya45387fa未变；原成功三地区208文件只读未变，未打开旧失败或注入
incident目录。后置坏完整证书、缺因果依赖、retained value错误、旧/零头和超过
pinned Native的height均拒绝，所有状态字节未变。小样本旧0.225191秒/新0.196752秒
不是旧A9/356信封成本或完整普通/fault性能证明，独立最新保护/保管仍未资格。

新六阶段Source89驱动静态审查一次20秒，实际0.038秒通过，未启动fixture/服务。
源/二进制/新genesis及全部保管、显式新cwd、原600/60/每区24新增高度、成熟/票数/
容量、停止谓词和bounded5秒cleanup保持；停止后明确保存head观察再读回传入pinned
checker，不能把该本机观察称独立最新保护，也没有不匹配后的刷新回退。
下一一次原600秒普通E100→P99→A97→E95六阶段及全部成熟/fullcold/12Native/
owner/最终守恒判别；最高5服务/共27启动，fault budget0。首真正Native/owner/
成熟/head/proof/capacity或非干净终态失败、完整判别或预算退出；保留整个失败
currency/原请求，不恢复重签退款、加预算或原样重跑。旧全部失败、VALUE-STRICT-01、
完整cycle/fault/2016/source66/长期/独立/PQ/physical及全部规范目标仍OPEN。
[准确实现、证据与下一范围](operations/evidence/regional-pinned-stopped-adapter-outcome-20261005.json)。


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
