# 参与 lowertier 开发

[English](CONTRIBUTING.md)

## 准备环境

需要 rustup、LLVM 与 Clang，以及 `protoc`。Cargo 会自动安装 `rust-toolchain.toml` 固定的 nightly 版本。

Debian 或 Ubuntu：

```bash
sudo apt-get install -y musl-tools llvm clang protobuf-compiler bridge-utils
git clone https://github.com/lowertier/lowerTier.git
cd lowerTier
cargo build --release --locked -p lowertier --bins
```

CI 构建 Linux（musl）、macOS 与 Windows，各含 x86_64 和 aarch64。具体构建见 `.github/workflows/core.yml`。

| 路径 | 内容 |
| --- | --- |
| `lowertier/` | 节点、命令行工具与网页界面（`lowertier/gui`，构建产物已提交） |
| `lowertier-tracker/` | tracker 与 STUN 服务 |
| `lowertier-contrib/lowertier-ffi/` | 面向平台客户端的 C 接口 |
| `docs/` | 使用指南；`docs/design/` 为协议与实现说明 |
| `script/` | 安装脚本、测试工具与基准测试 |

## 规则

- 只维护当前协议与配置格式，不为旧版本添加兼容路径；破坏性变更后更新测试节点。
- 直接提交到 `main`，使用约定式提交信息：`feat:`、`fix:`、`docs:`、`test:`、`chore:`。
- 文档与代码在同一次变更中更新。修改 `lowertier/src/common/config_schema.rs` 中的选项后重新生成参考：

```bash
python3 script/docs/options-reference.py > docs/options.md
```

## 测试

测试少而精。只保留锁定真实不变量的测试：协议、密码学、认证、ACL、数据包路径或资源上限。
不要为同一断言添加单个与批量两份副本；除非每个组合都是不同的不变量，否则不要写组合矩阵；不要在 `src/` 中放被忽略的性能测试。
CI 将核心测试限制在 500 个以内。

```bash
cargo test -p lowertier --lib
```

release 构建后，可验证两个未配置任何 peer 的节点能通过 tracker 互相发现并传输数据：

```bash
cargo build --release -p lowertier --bin lowertier -p lowertier-tracker --features lowertier-tracker/server --bin lowertier-tracker
python3 script/tests/tracker-bootstrap-test.py
```

Linux 上的网桥测试需要：

```bash
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
sudo sysctl net.bridge.bridge-nf-call-ip6tables=0
```

## 问题

请提交 [issue](https://github.com/lowertier/lowerTier/issues)。
