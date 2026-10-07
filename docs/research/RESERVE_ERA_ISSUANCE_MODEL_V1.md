# 储备时代发行模型与当前验证范围

对应冻结正文 `2ba62421583c60d0d35d295ff859eef558f2d372ea191d2a2dc828bb3e0b477b`
§6、I3/S5/R3，以及 §20 的完整模型要求。模型仅论证发行分量；完整协议的
身份、共识、所有权、通道、谱系、进口、冲突隔离、恢复与时代组合证明仍须另做。

## 整数模型

令 C=10^35 runlai，L=200000。R_0=C，B(R)=R（R<2）或 floor(R/2)。
R_(j+1)=R_j-B(R_j)。对预算 B 定义 q=B div L，m=B mod L，故 qL+m=B，
0≤m<L。时代内已选中 t 个块的发行是 P_R(t)=qt+min(t,m)，0≤t≤L。

**预算与守恒。** 0≤B≤R≤C，因此下一储备仍在 [0,C]，且累计已发行加未发行
储备保持 C。对正储备，B≥1；当 R≥2 时下一储备为 ceil(R/2)。因此固定 C 在
第 117 个时代开始剩余一单位，下一时代归零；至多 118 次储备更新即可结束，
不会按一个巨大高度迭代同样数量的块。

**时代内分配。** P(0)=0，P(L)=qL+m=B。第 t 个块（t≥1）的差分为
q+[t≤m]，即槽位 k=t-1 时 q+[k<m]。所以余数落在前 m 个槽位而非后部。
R=1 时 B=1、q=0、m=1，第一槽释放一单位，后续槽及零储备时代全为零。

**边界和上限。** 对 h=jL+t，累计 I(h)=C-R_j+P_Rj(t)。时代末 P(L)=B，
与下一时代的 C-R_(j+1) 完全相等，因此边界连续且单调。P≤B≤R，故
0≤I(h)≤C。q*t≤B，额外项和完整累计也不超过 C；C<2^128，所有实际乘加减
均以检查整数执行。Genesis I(0)=0，不能调用 height-0 reward。

**选中历史。** 模型输入是从认证创世重放得到的实际选中源块数量，不能由墙钟、
远程状态或缓存初始化。分支切换须重新执行选中父历史；丢弃未终局分支的发行
不能附加在新分支上。以上结论依赖真实块/父/状态执行，数学函数不授予账本权威。
原生分支选择、终局、所有者、费用及当前事故检查仍是独立必要条件。

## 实质差异和修复

The legacy shift/ceil-half and distributed remainder formula differs from the
frozen reserve recurrence. For example, height5800001 differs by one runlai;
the last unit must be released at23400001 rather than23400000. Correct arithmetic
is necessary, but it does not establish actual long-history ledger execution.

Rust 发行函数使用上述模型，Python 以直接槽位奖励另行重算。新组件
`RLD-ISSUANCE-RESERVE-ERA-V1` 绑定完整规则字节，其哈希为
`a0ae7b36b695c787b840d3726fa1fd55e1d5f3874e173346fbf791b7b2ac2153`。
直接价值采用必须提供该哈希，使用新格式和签名域
`RLD-EARTH-SUCCESSOR-ADOPTION-ISSUANCE-V1`。缺字段、不同规则哈希、旧格式
和旧域签名均拒绝；全四签也不能替换本机精确规则身份。

Legacy vectors are retained without automatic conversion. New vectors and signed
adoption rules must bind their exact recurrence and domain. Full value-library
strict checks, long-history execution, independent review and monetary adoption
remain separately required.
