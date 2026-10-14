# LowTier 本轮修复与直连验证（2026-09-21）

## 结论

本轮修复已落盘，macOS arm64 与 aarch64 Linux musl release 构建成功，55 项相关测试通过，20 组 yutoms ↔ hattori-owrt 测速完成并通过路径检查。H2/WSS 维持约 26 Mbit/s 的观测吞吐，进程 CPU/Gbit 与 RSS 明显低于本轮运行中的 Tailscale 参考。QUIC 上传仍只有约 10 Mbit/s，其 Hattori 端 CPU/Gbit 高于参考，整体“更快且两端 CPU/RSS 均更低”的目标尚未通过验收。

以下结果来自当前工作树，包含此前已经存在的优化。本轮补丁的独立性能增益尚未量化；禁止把当前工作树与 Tailscale 的差异全部归因于本轮改动。

## 实际修改

### QUIC：复用发送队列与 Future

文件：`lowertier/src/tunnel/quic.rs`。

`QuicHybridWriter` 改为发送队列与备用队列轮换。常见成功发送路径通过交换两个 `VecDeque` 的所有权保留存储，消除每批新建队列及成功完成后逐项搬移新到数据的工作。分片扩张超过批次上限时，仍按原有上限分批提交。

发送状态使用 `tokio_util::sync::ReusableBoxFuture`。每次重置来自同一个 async 表达式，布局一致，完成后的分配留给下一批使用。保留原有 DATAGRAM 容量等待、FIFO、错误传播和 TooLarge 恢复语义；没有把有损数据改走可靠流，也没有关闭拥塞控制或加密。

新增测试验证两块队列存储在 256 轮模拟交付中复用、分片批次上限、恢复顺序和致命错误传播。真实 QUIC 连接测试额外验证 24 次连续发送复用 Future 地址且接收顺序正确。此处消除的是这些容器与 Future 的逐批分配，不代表整个 QUIC 数据面已经零分配。代价是每个活跃 writer 保留第二块队列存储。

### H2：读缓冲推进与空 I/O 语义

文件：`lowertier/src/tunnel/http2.rs`。

读取剩余数据从 `Bytes::slice(n..)` 替换为 `Buf::advance(n)`，避免构造新的切片对象及相应所有权操作。零容量 `ReadBuf` 立即完成；全空 vectored write 立即返回零，避免触发待发送缓冲的背压等待。原有流量控制释放策略保持不变。

新增真实 H2 client/server duplex 测试，覆盖空读、部分读取的剩余字节与 EOF、空 vectored write 保留待发送数据。

### Linux PPPoE：修复严格 underlay 策略下无法监听

文件：`lowertier/src/common/network.rs`。

原始基线在 Hattori 的严格接口策略下无法监听本机 PPPoE 公网地址。根因是 Linux 接口过滤器一律排除 `IFF_POINTOPOINT`，同时排除了 PPPoE WAN。现场读取 `/sys/class/net/pppoe-bbd/type` 得到 512，即 PPP 链路类型。

修复后，point-to-point 接口仅在内核类型为 PPP 时继续接受候选检查。缺少类型信息及其他 point-to-point 类型仍被排除；UP、LOWER_UP、非 loopback、非 TUN/TAP、有效地址以及后续接口/CIDR 禁用策略均保留。PPP 类型本身不能证明业务用途，明确的 underlay 规则继续负责出口约束。

原始二进制与失败日志已保留。新版在同一份严格策略下成功监听并完成三种协议实测。WSS 本轮没有修改帧编码；它使用共享接口修复，并完成自身回归和端到端验证。

## 测试路径与方法

测试出口固定为 yutoms `en1` ↔ Hattori `pppoe-bbd`。本轮冻结的客户端本地源地址为 `172.25.23.12`，NAT 源地址为 `133.1.22.2`，Hattori 公网地址为 `58.147.228.119`；旧的 `58.147.236.32` 没有用于本轮测量。源地址绑定的 TCP echo 在测试开始前验证了真实 NAT 出口。

LowTier 的端口为 H2/TCP 15390、QUIC/UDP 15392、WSS/TCP 15393，内层 MTU 1280，Hattori PPPoE MTU 1396。两端启用 secure mode 和原有加密，禁止 Tailscale CIDR 及其他已枚举接口。每组记录开始、中途和结束的两端 peer、路由、连接端点；分析要求单一直接连接、下一跳即对端、地址/端口匹配冻结清单。每组 LowTier 测量另有实际隧道端口的大包抓包证据。

管理 SSH 使用现有 Tailscale 通道；LowTier 测速载荷直接发送到公网端点，未封装在 Tailscale 内。Tailscale 参考载荷使用其自身的 WireGuard 直连传输，并验证无 PeerRelay。参考测试临时增加仅匹配本次本机 UDP 五元组的 PPPoE 回程规则，未修改默认路由或重启守护进程；结束后按完整规则删除并确认规则集恢复。

使用 iperf3 接收端 delivered bytes/goodput，方向 up 为 yutoms → Hattori，down 为反向。LowTier 每协议测试 1/4 流、双向、各 20 秒、各一轮，共 12 组；Tailscale 相同组合各两轮，共 8 组。所有协议顺序运行，未并发争用测试链路。

CPU 指标为进程 user+system CPU 秒除以接收端实际交付 Gbit。采样覆盖整个测试窗口及四秒余量，也包含管理/RPC 活动；没有扣除空闲 CPU。Tailscale 在 yutoms 上计入 LocalAPI loopback adapter，LowTier 计自身守护进程。iperf3 与计入其他上下文的内核网络工作不在该进程指标内。现有 Tailscale 守护进程还服务其他 peers，而 LowTier 是隔离两节点实例，因此这是运行状态对照，不能用来推断等 peer 数的最小 RSS。

## 实测结果

下表是单流结果；Tailscale 使用两轮中位数。CPU 单位为秒/Gbit，顺序均为 yutoms / Hattori。原始精确数值、四流结果及每组 RSS 均保存在 summary.json 和 summary.csv。

| 协议 | 上传 Mbit/s | 下载 Mbit/s | 上传 CPU 秒/Gbit（y / h） | 下载 CPU 秒/Gbit（y / h） |
| --- | ---: | ---: | ---: | ---: |
| Tailscale | 26.04 | 26.74 | 12.99 / 20.55 | 15.01 / 25.57 |
| LowTier H2 | 26.67 | 26.21 | 2.33 / 5.82 | 5.02 / 10.62 |
| LowTier WSS | 25.72 | 26.58 | 1.65 / 6.25 | 3.52 / 9.27 |
| LowTier QUIC | 9.77 | 26.53 | 11.55 / 34.51 | 5.07 / 12.44 |

各组采样 RSS 中位数的范围如下，包含单流及四流负载。

| 协议 | yutoms MiB | Hattori MiB |
| --- | ---: | ---: |
| Tailscale | 236.47–237.22 | 114.36–124.49 |
| LowTier H2 | 39.12–79.75 | 22.18–23.02 |
| LowTier WSS | 37.16–69.16 | 34.59–35.18 |
| LowTier QUIC | 35.44–37.06 | 36.59–45.54 |

H2/WSS 的观测速率接近参考，当前样本不足以把几个百分点的差异解释为稳定的速度优势。它们的进程 CPU/Gbit 和 RSS 差异则较大。QUIC 四流上传为 10.08 Mbit/s、下载为 24.32 Mbit/s；Hattori 上传 CPU 成本升至 40.05 秒/Gbit，仍需继续定位上传的数据报丢失/恢复与内层 TCP 行为。本轮数据没有确证该瓶颈的唯一原因。

本轮未进行高带宽局域网吞吐上限测试、长时间稳态试验或 p99 延迟测试。

## 构建、回归与清理

QUIC 31 项、H2 5 项、网络接口 3 项、WSS 4 项 Rust 测试通过；直连证据门禁 9 项 Python 测试和 Tailscale adapter 3 项既有 Rust 测试通过，总计 55 项。门禁负例包含 relay 下一跳、Tailscale 地址、其他本地接口、公网地址变化、错误端口及额外连接。针对三个本轮修改的源码文件，`git diff --check` 通过。仓库原有编译警告仍存在。

修复版二进制 SHA256：

- macOS arm64：`202910a853777c8fdb56fa362ed2e80801f06c21ee28eb20bc988dd3ecf1ea3e`
- aarch64 Linux musl：`9a5bbf1ec225c93dae42fab1b59099c4dbb80ddb0b93966e95dd0a701b5b78a9`

两端部署到隔离测试目录后重新核对了二进制哈希。最终分析接纳 20 组、拒绝 0 组；原始严格策略启动失败保留为失败证据，没有生成吞吐记录，也没有被混入成功样本。测试进程已退出，Tailscale 临时路由记录为 `active=false, restored=true`，生产服务没有替换或重启。

## 证据与本轮边界

证据目录：`benchmark-results/direct-repair-20260921/`。

`changes.patch` 仅包含本轮三个 Rust 文件相对开工快照的变化，`source-provenance.json` 记录前后源码哈希；所有原有未提交改动保留。`before-native`、`before-linux` 与 before/ 源码快照保留。`manifest.json` 保存本轮实际地址、MTU 与分发二进制哈希。`summary.json`、`summary.csv` 和分组命令 JSON 包含完整 20 组指标及路径证据。执行审计位于 `benchmark-results/.work/direct-repair-20260921.jsonl`；复用的 runner 也将命令审计写入 `.work/direct-yh-20260921.jsonl`。

本轮没有改拥塞控制算法、smoltcp 控制器、加密算法或 WSS 帧格式。后续优化应以 QUIC 上传的低 goodput 和高 Hattori CPU/Gbit 为主要未完成项，保持上述直连验收条件。
