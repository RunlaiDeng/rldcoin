# 当前实现与有限验收状态

**目标尚未完成。** “全部通过”只可描述注明来源的有限套件，不能涵盖白皮书全部义务。所有旧FAIL和预算耗尽原件保留，后续PASS不追认旧失败。采用[冻结记录](WHITEPAPER_FREEZE_RECEIPT.json)的正文/PDF及全部S1–S18/R1–R24/I1–I12/A–G/N1–N10/P1–P8；官网和纸面冻结。

| 范围 | 真实结果与准确来源 | 资格限制 |
| --- | --- | --- |
| 当前Core | 183文件，来源 `5d1691dc98e4d5fcd4c2c58d2b74234118525a26cc904e68e3a9b1d6f6f7ff27`；全293测试/0失败忽略过滤和6包all-target严格检查通过；V32 37.864650秒/300，相关V31 45.611055秒/原120累计52.137786。 | 混合授权、quorum、联合续证和归档为验证候选；不是账本采用。 |
| 有限续证归档 | 两次真实四签续接、49414B；精确独立latest-head/1–64条/每条32768B/总2097152B边界。初始anchor不改变。 | 两条有效链不证明64条实际吞吐、长期档案、持久锁恢复或独立见证。实际冷文件入口V21已完成有限验证，64条有效链已测量，见下方有限结果。 |
| 完整联合续证运输 | V17 28.928744秒/120；历史Core182 `ee1f46b69457ace45d1b1ade842eb75ad97066b3d1d5b41598f2f000a6885b4a`；24707B三片按原12288包上限，实际互认证TLS完整送达、冷读、实际Core合法接受/坏PQ拒绝。 | 同机同控制者；运输收据不授值权；不自动资格转移至新Core。 |
| 完整quorum运输 | 历史Core182 `d728ef48902986aa2b6e98b21c08ea23c12eab0f414a4a7ddad41c435783ba9a`全284；29679B三片、实际TLS/冷重组/Core和不同实现反向验签。 | 固定三取四候选；不是持久finality采用。 |
| ML-KEM768不同实现 | 固定NIST来源；OpenSSL/fips203 0.4.3实际decap/encap/keygen及同长度ek/dk拒绝子集一致，V10 36.931717、V11 10.871585、V14 10.818353秒，均原120；V13编译FAIL及V12来源解析FAIL保留。 | 有限已知标准子集；不等于完整FIPS203/204、CAVP/FIPS140、恒时、生产随机源、独立审查或采用。 |
| 历史Native完整故障 | head-v16 430.830秒/原600；源提交 `776ceb15f9125dc8762b3707a217a087cf9d6bb3`，Core171 `de74cf78a22e34f558760be0c3cd1ab39e988dfa20eb2722acc23a35fc527d5c`，实际CLI `bef4d5c7bfee1a2455845334fd0824c784df8fdae63a74baea093155fdfb2000`。缺leader、隔离当地付款/追赶、原收款成熟、无钥排空、all12固定头cold、1645信封/5265档案、heads和守恒、24正常停止通过。 | 精确3地区4voter同机无价值profile；全部之前FAIL保持，不是更广故障或独立BFT资格。 |
| 历史旧价值库 | VALUE-STRICT-01 V13完整67（49lib/4offline/14runtime）及严格通过172.226276秒/原300，Core177 `bc623ebe132c25c47553740c7d8a9682f32e0b3b468c8c8dcae412f48601eea8`。旧120/300耗尽和告警失败保留。 | 当前库来源改变后的重新资格及长期/独立采用仍独立；地区strict从未代替旧库。 |

## 最新冷文件入口结果

新增实际Core冷读adapter和RAM-only公开生成器；V20 **FAIL19.966140秒**，改变锁根的反例误给64hex而实际须128hex，入口拒绝并未到预定签名判据，原14项封存。仅修正夹具字段宽度，来源/严格构建/实际binary复用不重建；V21 **PASS0.144540秒、原120累计20.110679秒**，完整两条49414B实际四签链及16拒绝判据、初始文件/locks/consumed不变、无状态安装通过。actualreader `0946bf7b80b4fe717a2e82249652434e7f6313602fd7231607a5b79ec690f62f`，generator `d88e4338116daefe1a363864a1393d7815e28bee60f33514f0deaec98cc260b0`；Core182 f5adb880未改。V20及全部旧失败保持，0网络/Native/Runtime/Node/持久签署钥，25输入文件封存。旧两条有限归档不授64条吞吐、独立caller见证或持久账本资格。

## 64条完整有效归档资源结果

V22 **FAIL0.896450秒**：64次续证生成成功，控制器误将两条样本的24707B逐条固定长度乘64；规范JSON中时代/epoch/nonce数字位数增长导致实际1581531B，冷reader未执行。该预测错误与失败67项保留；只改预期字节数，不改变64/32768/2097152/原120。V23 **PASS0.998831秒、原120累计1.895281秒**：全新RAM-only64完整四签续接，完整1581531B，actual冷reader重构era/key_epoch/nonce65、caller独立latest-head及原locks/consumed；63有效前缀在相同latest下exit1。实际读验0.309571秒、进程峰值5193728B，仅本机该工具链/profile观察，不是吞吐或长期保证。来源及两actualbinary与V21完全相同，严格构建合法复用；68项封存，0网络/Native/Runtime/Node/持久钥，不安装状态。

## 完整多对象小包归档与实际Core组合

新独立public-archive候选保留原每包12288/每对象32768、至多64条/总2097152；4389B规范清单由接收方独立预留SHA512，绑定有序条目大小/完整root，不从包学习信任。4纯模型（包括实际2MiB/192片边界）及V25实际64完整1581531B的逆序193小包/全冷文件/Core组合 **PASS0.261271秒、原60累计0.321970秒**；实际最大包12108B，缺完整条/内片/清单保持不可用，重复/混档/改包/替换清单root拒绝，原输入不改。合法完整档案Core exit0；另一个完全byte-valid、完整送达的坏内层PQ档案由Core exit1明确拒绝。130公开测试文件本地封存，0网络/TLS/Native/Runtime/Node/签署钥调用、不安装状态。旧carriage来源和Core182 f5adb880不变；不是实际网络运输、独立审查/保管或星际航路资格。

## 有限公开包保管/进程冷重启组合

新专属无值公开spool在保留原entry/aggregate/packet上限外，另以256文件及派生gross-byte预算限制全部保管与失败残留；owned private/no-follow正规文件、OS lock、不可替换hardlink发布、file+directory fsync完成后才释放字节收据。重复包重新检查并sync，缺manifest先不可用，部分归档不生成完成目录；失败staging原件不自动清理，不授ledger/locks/value/退款。

V26四相关真实文件/注入write与dir-fsync反例通过，核心方法prefix严格逐字桥接最终CLI；V27 **PASS0.801227秒、原60累计0.890992秒**：全新公开目录，193包在多个实际独立Python进程分97/96接收，首次writer已退出；cold不完整明确拒绝且不产出文件，剩余逆序接收、精确duplicate重新sync不改库存，全部64/1581531B文件和actualCore终态一致。455输入/保管/输出文件封存，0网络/TLS/Native/Runtime/Node/签署钥，不打开旧失败保管或安装状态。实际power-loss/跨设备/独立保管/恶意持续负载并未完成。

## 显式归档保管收据与完整TLS接入

实际原256文件容量V28 **PASS0.056582秒、保管原60累计0.947574秒**，253失败残留计入容量；新packet首次写前拒绝且原hash/inode/mode/mtime不变，已有精确duplicate仍重新sync。

新C显式archive-spool模式以编译绑定的实际Python保管脚本完成接纳/fsync后才发独立的归档收据；3秒单次、12288包上限、peer pin/TLS policy和普通raw-file函数逐字桥接不改。V29 **PASS15.258978秒/原120**：严格C构建、全新TLS夹具，64完整1581531B的193个实际互认证TLS小包分批接纳；半档cold不产出目录，后半逆序续收、完整cold及actualCore65相同。陌生包和真实256满容量两个实际server/client均exit1，不发archive收据，raw传输残留及原保管全部保留；一个普通mode收据另行通过。newC source `abc2e665dd857e7138e5102f678b81b620fd4578fa430d40191735c2b621dc42`、actualbinary `4edb895c2aa04982bf8ecee371f417099d6241d95861332b213e0d6e59f1dc06`、spool bd4a8f11/Core182 f5adb880分别绑定。916项封存，forced[]/全部自有进程正常终态，0Native/Runtime/Node/value，不复活旧失败保管。仍仅同机loopback，不是跨设备掉电、独立运营或物理长延迟；旧TLS资格仅各自旧源，未补授新源完整旧六项。

## 离线归档清单双签候选

独立ARCHIVE_MANIFEST用途和tag6绑定规范有序清单的完整SHA512；Ed25519及ML-DSA87必须同时验证同一意图。签署epoch2在独立policy1–8/current2、7、8内可验；current9、过期/未知撤销/错域/nonce/坏半签/改清单拒绝。64条/32768每条/2MiB总量与原小包上限不改，不安装账本或消费nonce。V30 strict **FAIL6.526731秒**保留；仅按Rust1.98数组分块API修复，无告警豁免。V31真实相关三项与严格PASS45.611055秒/原120累计52.137786；V32同源全293 **PASS37.864650秒/300**，实际测试binary独立封存。旧Core182 f5adb880的全290及运输资格仍按历史来源保留，不自动转给新Core。

## 实际离线清单入口

新增分离policy/observation、规范manifest及detached envelope的actualCore入口，8192/4389/12288边界/no-follow/owned正规文件；全新RAM-only双签、64条清单1581531B不生成持久钥、不消费nonce。V33 strict/build及17实际判据已通过后 **FAIL27.433337秒**：截短manifest正确Core拒绝exit1，控制器错误预期文件错误exit2；20项失败封存。仅修正该预期，复用17有效结果和同源实际binary/严格构建；V34 **PASS0.099325秒、原120累计27.532662秒**，余下截短/过界/非规范/重复字段/symlink/已存在output拒绝，10项封存。Core1835d169/source、reader `0c426aeeb8a9553550da7e28574658a128a1181fc5dc957ece58c0dece3de1ef`、generator `a9385708981b1931d55ba02e6ce5fcfa4f3df5e0212ec1e26144dce243b04928`及controller分别绑定；0网络/Native/Runtime/Node/状态安装。依赖锁仅新增已有sha2=0.10.8直接引用，原包版本/checksum/deps完全不变。

## 清单授权与内层完整档案的同进程冷核验

实际reader新增显式authorized-manifest模式：独立policy双签授权、准确currency/region/count，再在同一owned directory fd逐项检查有序size/SHA512，最后以独立anchor/observations/latest-head执行实际Core全部四签续证；ordinary输出保持相同。V35静态 **FAIL0.760030秒**，输出括号遗漏，0签名/运输；失败源码保留。仅修正语法，V36 **PASS3.152514秒、原120累计3.912544秒**：64完整终态65及原locks/consumed正确，遗漏/重排/重复/缺档/错区/未知权威/超期/坏manifestPQ拒绝；完整字节且新RAM-only合法清单双签、但坏内层PQ的归档仍明确Core拒绝。82项封存，newactualreader `fff3de9ac02b483464a21e4e462aa8620939fafdb8d8bbf921ad0f8f05e8b464`/generator `074680f1be905ec16f5851e827e15db18dc5a5bfacbad157657ecb1a658a89ac`、Core1835d169与controller分别绑定；原文件不变，0网络/Native/Runtime/Node/nonce消费/安装。不授新Native/独立保管或物理资格。

## 下一单一主线

以独立Python规范解析及OpenSSL实际密码实现核验同一公开清单双签，检查purpose/root/nonce/有限horizon并与Core结果比较，一次60秒，首失败退出；只读成功公开字节、不重新签署旧失败输入或重跑TLS/Native。两个密码实现一致仍不等于独立运营/完整协议实现审查或采用。P1–P8及物理期限保持独立。

## 尚未完成

独立安全/实现/运营/保管与跨设备恢复、>200000历史及实测规模预算、任意多源谱系/全组合守恒证明、完整异步密码/时代/治理采用与有限期限续资格、真实物理接触航路及P1–P8均未完成。一亿年是跨代维护目标，不是一次运行保证。源码公开、CI或局部PASS不能替代这些门槛。原600/60轮/24高度、成熟/票数/容量/owner请求不改变。

原运行记录、controller/source/binary绑定、成功和失败、私有保管本地原位保留；公共树只含源码、稳定入口、标准向量和本简表。[稳定验证入口](operations/VERIFICATION.md)、[主计划](RLDCOIN_MASTER_PLAN.md)、[条款映射](WHITEPAPER_IMPLEMENTATION_ACCEPTANCE.md)。
