# 有界本地构建与验证

采用本地加速，不安装远端Rust、不扩大服务器操作或创建主机。唯一源码/fixture作者保持串行主线。

最小可证伪反例→相关回归→有变更理由的必要完整scope；已通过且来源不变的证据复用，不为发布/整理重复长测。原期限、成熟、票数、容量及失败保留。

每个主机/toolchain/workspace/profile复用一份target缓存；不能用缓存目录名称证明来源。固定Rust1.98.0、OS/arch/job/profile、对应lock及完整Core/Native来源分隔CI缓存键。依赖缓存和编译输出只加速，实际source、实际binary、controller与evidence分别绑定。

现有CI三项为来源/向量、6包workspace和regional-native；有完整源码键和lock兼容restore-key，Cargo须按当前依赖/source重验。每次阶段读取真实CI状态，缺run不称通过。仅公开依赖/target缓存，私有fixture、钥、caller/owner/voter/witness/账本及TLS状态从不入缓存。

不按旧、大或untracked清理。若以后需要清理，先证明当前/下次build及minimum evidence不依赖准确候选；保持deps、最终binary、唯一源/证据/保管，可重建incremental另行按精确范围授权。
