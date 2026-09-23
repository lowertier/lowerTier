# Resource optimization: five-step tracklist

Status: all five implementations and validation complete. Resource outcome is mixed; R6 is not promoted. C4/WSS remains the runtime baseline.

Source commits: `35418561` and `5560fc3e`.

- [x] 1. **分配器策略** — 修复环境变量被覆盖的问题，使用 mi_option_set_default；默认保留 10 ms 复用期，显式覆盖仍生效；去掉强制启动回收。 14 个真实二进制参数用例、16 个 purge 对照样本。
- [x] 2. **UDP 向量 I/O** — 只初始化本批有效描述符，缓存 GSO 环境开关；维持批量上限、部分完成处理及失败回退。 8 项 UDP 向量回归、两平台构建及真实 QUIC 载荷。
- [x] 3. **WSS 接收所有权** — 合适的独占缓冲直接复用；共享缓冲直接复制一次；检查隐藏前缀和实际容量，避免小包保留大 slab。 45 项包存储、5 项 WSS 回归；独占缓冲微基准额外分配归零。
- [x] 4. **H2 直接解帧** — 直接解析拥有所有权的 DATA，去掉中间 AsyncRead 复制；窗口额度按 DATA 边界合并返还，保持精确字节记账。 10 项 H2 回归；拆包、合包、畸形长度、EOF、额度返还及 Caddy 集成。
- [x] 5. **缓存与空闲工作** — 缓冲池只预热一批，其余按需分配；池满时避免无效替代分配；QUIC 详细日志改为显式开启，空闲采样退避至 8 秒。 缓冲回收/别名测试、空闲观察器测试、真实负载与停载采样。

Final gates: 125 focused Rust tests; one explicit Caddy integration; 14 allocator option cases; native/ARM release builds; 100 valid network/resource trials.

See `resource-optimization-20260923.md` for the full outcomes, regressions and measurement limitations.
