# 普通区域节点的独立有界出站运输候选

只适用于新私有目录的无价值地面候选。Native/Core、签署阈值、锁、caller head、20 秒基准和原 600/300 秒观察关卡保持；它不是旧失败付款的恢复、采用网络升级、持续 BFT 或物理路线资格。

## 生命周期与所有权

TCP 出站所有权绑定实际线程；重复 worker、其他线程 tick 和重入均拒绝。四个出站联系、四 transit/十六 receipt、原 socket/本地锁/线长/活动与归档容量不变。exact 预备交换先持久推进，然后才打开连接、认证新挑战并绑定请求；关闭 socket 后仍必须实际本地持久保管回复，才允许原临时 hop 抑制。发现不提供新端点、pin、验证者或账本权限。

## 观测和停止

仅保存一个至多 64 KiB 的完整 canonical TCP 观测；每次读取独立解码。完成次数、时间和失败是诊断，不能恢复 cursor、提供 freshness 或授权入账。没有完成 pass 时明确报告 unavailable，耗时为 null。并行 TCP 不计为串行 contact tick 的 CPU/socket 阶段，`tcp_seconds` 为 null；TCP pass 的独立时长在 worker 观测中保留。死线程或诊断超界导致明确拒绝，不回退到前台或抛弃队列。

停止先阻止新 pass，等待当前本地验证/持久保管结束，再释放出站所有权。TCP 关闭 listener 和 socket 后也等待所有入站 worker 实际退出，之后才释放 service 保管锁。三秒 socket 尝试不能代替本地 CPU 完成上界；控制器的原停止关卡仍可失败，失败目录和原 Native/caller 响应必须保留。这不是断电、跨设备或独立防回滚资格。
