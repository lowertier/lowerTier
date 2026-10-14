# LowTier C4 资源审计 — 2026-09-23 JST

## 测量范围与结论

源码提交：3dd040a00212c09aa72ecdb5acb6dc5dbd6cf643。使用冻结的 C4 二进制，原生 TUN 模式，osku ↔ UTMOWRT。覆盖 H2/TCP、WSS、QUIC，单流/四流及两个方向，每项两次，共 24 组有效测量；另做 6 组独立诊断，未混入性能验收。

每次预热 3 秒、测量 15 秒，实际内层 MTU 1280。验证双方公网直连、认证、连接 ID 稳定及 direct 字节计数覆盖载荷。吞吐为接收端有效吞吐。250 ms 采样进程 CPU、RSS；macOS 另读 physical footprint。CPU100%代表一个逻辑核，osku16核、UTM6核。CPU为采样中间稳定区间约13秒的 user+system 时间差；每Gbit成本按该稳定CPU/接收端吞吐估计。

本轮结果：osku 满载 RSS 约34–40MiB，physical footprint峰值约12.5–14.2MiB；UTM采样RSS峰值约24–46MiB。UTM的CPU大部分记在内核态。QUIC在osku端单位有效数据CPU成本明显高于H2/WSS。测试后的内存未完全恢复到初始水平；这些短测量不足以证明泄漏。

## 满载有效吞吐与CPU、RSS

下表吞吐、CPU为两次中位数，RSS为两次250ms采样的最高值。CPU波动和吞吐范围保存在summary.json，不能把中位数理解为稳定保证。上传为osku→UTM，下载反向。

|协议|流数|方向|接收Mbit/s|osku CPU %|osku RSS峰值 MiB|UTM CPU %|UTM RSS峰值 MiB|
|---|---:|---|---:|---:|---:|---:|---:|
|H2/TCP|1|上传|617.4|36.8|40.0|123.1|42.5|
|H2/TCP|1|下载|464.5|29.3|40.0|50.9|42.7|
|H2/TCP|4|上传|541.9|33.5|39.9|106.0|42.5|
|H2/TCP|4|下载|469.8|29.4|39.8|47.9|35.4|
|WSS|1|上传|575.2|40.5|38.0|120.0|35.5|
|WSS|1|下载|440.5|25.0|38.0|54.8|35.4|
|WSS|4|上传|526.0|32.9|38.0|107.1|35.5|
|WSS|4|下载|477.8|26.4|36.1|53.9|37.6|
|QUIC|1|上传|326.3|48.7|38.4|67.3|45.5|
|QUIC|1|下载|467.8|54.2|38.4|77.4|45.4|
|QUIC|4|上传|274.0|43.1|38.3|65.6|46.3|
|QUIC|4|下载|472.7|54.1|37.6|76.4|38.7|

## CPU效率和卸载后的保留

|协议|osku CPU s/Gbit范围|UTM CPU s/Gbit范围|osku footprint采样峰值 MiB|
|---|---:|---:|---:|
|H2/TCP|0.60–0.63|1.02–1.99|13.59|
|WSS|0.55–0.70|1.13–2.08|12.99|
|QUIC|1.15–1.58|1.62–2.41|14.23|

|协议|osku RSS 初始→停载20秒 MiB|osku footprint 初始→停载20秒 MiB|UTM RSS 初始→停载20秒 MiB|
|---|---:|---:|---:|
|H2/TCP|27.0→40.0|11.2→13.0|22.2→42.1|
|WSS|27.1→38.0|11.1→13.0|22.1→35.5|
|QUIC|28.4→38.4|11.6→12.9|25.5→45.2|

停载后osku约0.19–0.22%单核CPU，UTM约0.78%。macOS RSS增长远大于footprint增长。UTM诊断同时看到约14.8–15.3MiB的RssShmem；因此RSS不可直接当作私有堆内存。

## 已确认的代码问题与优先级

### 1. 分配器强制立即purge，配置覆盖无效

lowertier/src/lowertier-core.rs:25 无条件 mi_option_set(PURGE_DELAY,0)。即使环境设置 MIMALLOC_PURGE_DELAY，:61 分支仍调用该函数覆盖设置。这是已确认的配置问题。独立6秒诊断中，UTM的WSS接收出现37,288次minor fault，H2接收14,686次，QUIC接收45,107次；user CPU远低于system CPU。页面周转值得重点检查，但这些观测不能给出purge的精确CPU占比。

建议先修复配置语义，再对0/10/50/100ms做同版本受控对照，同时检查每Gbit CPU、RSS高水位和停载回落。保留现有吞吐、交付、时延门禁。不能只因降低RSS就把吞吐回退版本留作基线。mimalloc官方文档明确说明立即purge的性能代价。

### 2. 已有向量I/O，需要提高实际批量利用率

lowertier/src/tunnel/udp_vector_io.rs、vendor/quinn/src/runtime/tokio.rs、lowertier/src/instance/linux_tun.rs 已经存在向量I/O/GSO路径。macOS QUIC独立采样频繁出现sendmsg_x，说明接下来应统计每次系统调用的实际datagram数和flush粒度，检查过短批量、重复准备iovec及线程唤醒。避免再加一层队列，也不要重复先前扩大突发导致的回退。睡眠栈/锁等待样本数量不等于CPU时间。

### 3. WSS接收丢弃所有权，强制分配并复制

lowertier/src/tunnel/websocket.rs 的 map_from_ws_message 使用 BytesMut::from(msg.into_payload().as_bytes())。vendor/tokio-websockets/src/proto/types.rs:250 已实现Payload到BytesMut的所有权转换。可优先复用独占且尺寸合理的缓冲区，共享或过大的底层slab仍需按边界复制。必须增加别名、可变访问及保留容量测试，避免1280字节小包钉住64KiB读取slab。

### 4. H2接收适配层的额外复制

lowertier/src/tunnel/http2.rs 的H2Reader将RecvStream DATA复制到通用FramedReader缓冲；lowertier/src/tunnel/common.rs再解析分帧。可以评估直接消费拥有所有权的DATA块并处理跨块帧，减少中间复制。必须保留分帧长度验证、窗口归还和TLS exporter绑定。2MiB接收窗口不能无依据缩小；给定1Gbit/s和15ms RTT，单BDP约1.79MiB。

### 5. 缓冲池可以减小冷启动成本，收益应按真实规模估算

ReusableBufferPool::new预填全部槽位，错误容量回收路径可能先分配替代缓冲再因缓存已满而丢弃。可评估按需填充和避免无效替代分配。当前Linux TUN池已收敛为每队列2×64个约1.8KiB槽位，约0.22MiB/队列；它无法单独解释几十MiB的RSS。PacketBatch池和生产receive_queue已复用，不应重复加入池化抽象。

### 6. 区分网络窗口、排队内存与空闲缓存

QUIC当前DATAGRAM发送/接收上限1/2MiB，socket请求收发各7MiB。这些是容量配置，不能简单相加当作驻留RAM。独立的socket队列在进程RSS之外。每连接统计任务每秒轮询、默认每2秒打印，空闲时可合并或降低无效工作，同时保留必要遥测。用户态TCP的自适应缓冲最多每方向8MiB，长连接空闲时不收缩，可另做安全收缩设计；本次native测试没有经过该用户态TCP栈。

## 测量边界和校验

Darwin CPU原始计数为Mach ticks，自检纠正了直接按纳秒计算的错误，实际使用mach_timebase_info的125/3换算，并与独立process_time校验。UTM没有smaps/smaps_rollup，PSS及private字段不可用；原始采样中的private=0占位已在汇总排除。RSS按Linux异步记账，峰值为采样峰值。

本报告CPU包含目标core的用户态和记入该进程的内核态时间，未包括iperf3、SSH、采样器、其他进程、未记到core的内核中断/软中断和虚拟机宿主成本。独立诊断采样只统计syscall驻留位置，不提供每个syscall精确耗时。UTM缺少内核栈，release二进制已strip，完整Rust热点归因仍需进一步受控剖析。

## 产物与状态

summary.json：完整中位数、范围、CPU效率、空闲状态、原始结果hash及诊断边界。summary.csv：扁平汇总。results/：24组有效测速及空闲采样。profiles/：6组独立诊断、syscall位置、macOS sample和vmmap。findings.json：逐项确认事实、假设、建议。cleanup-and-baseline.json：清理及基线hash检查。

本轮没有修改数据面或分配器默认设置。常驻C4二进制保持不变；本文不会把待验证建议称为已获得的优化收益。

## 官方资料

mimalloc Environment Options: https://microsoft.github.io/mimalloc/environment.html

Linux /proc: https://docs.kernel.org/filesystems/proc.html

Bytes ownership: https://docs.rs/bytes/latest/bytes/struct.Bytes.html

Quinn TransportConfig: https://docs.rs/quinn/latest/quinn/struct.TransportConfig.html

审计目录：benchmark-results/resource-audit-20260923。
