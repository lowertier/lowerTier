# LowTier 贡献指南

[English Version](CONTRIBUTING.md)

感谢您对 LowTier 项目的关注！本文档提供了参与项目贡献的指南和说明。

## 目录

- [LowTier 贡献指南](#lowertier-贡献指南)
  - [目录](#目录)
  - [开发环境配置](#开发环境配置)
    - [前置要求](#前置要求)
      - [必需工具](#必需工具)
      - [平台特定依赖](#平台特定依赖)
    - [安装步骤](#安装步骤)
  - [项目结构](#项目结构)
  - [构建指南](#构建指南)
    - [构建核心组件](#构建核心组件)
    - [构建注意事项](#构建注意事项)
  - [开发工作流](#开发工作流)
  - [测试指南](#测试指南)
    - [运行测试](#运行测试)
    - [测试要求](#测试要求)
  - [Pull Request 规范](#pull-request-规范)
  - [其他资源](#其他资源)
  - [需要帮助？](#需要帮助)

## 开发环境配置

### 前置要求

#### 必需工具
- Rust 工具链（版本 1.95）
- LLVM 和 Clang
- Protoc（Protocol Buffers 编译器）

#### 平台特定依赖

**Linux (Ubuntu/Debian)**
```bash
# 核心构建依赖
sudo apt-get update && sudo apt-get install -y \
    musl-tools \
    llvm \
    clang \
    protobuf-compiler

# 测试依赖
sudo apt install -y bridge-utils
```

**交叉编译依赖**
- musl-cross 工具链（用于 MIPS 和其他架构）
- 可能需要额外配置（详见 `.github/workflows/` 目录）

### 安装步骤

1. 克隆仓库：
   ```bash
   git clone https://github.com/lowertier/lowertier.git
   cd LowTier
   ```

2. 安装依赖：
   ```bash
   # 安装 Rust 工具链
   rustup install 1.95
   rustup default 1.95
   ```

## 项目结构

```
lowertier/          # 核心功能和库
lowertier-contrib/lowertier-ffi/ # C interface for platform clients
.github/workflows/ # CI/CD 配置文件
```

## 构建指南

### 构建核心组件

```bash
# 标准构建
cargo build --release

# 特定平台构建
cargo build --release --target x86_64-unknown-linux-musl     # Linux x86_64
cargo build --release --target aarch64-unknown-linux-musl    # Linux ARM64
cargo build --release --target x86_64-apple-darwin           # macOS x86_64
cargo build --release --target aarch64-apple-darwin          # macOS M1/M2
cargo build --release --target x86_64-pc-windows-msvc        # Windows x86_64
```

构建产物位置：`target/[target-triple]/release/`

### 构建注意事项

1. ARM/MIPS 的交叉编译需要额外配置
2. Windows 构建需要正确的 DLL 文件
3. 详细构建配置请参考 `.github/workflows/` 目录

## 开发工作流

1. 从 `develop` 分支创建特性分支：
   ```bash
   git checkout develop
   git checkout -b feature/your-feature-name
   ```

2. 按照代码规范进行修改

3. 编写或更新测试

4. 使用规范的提交信息：
   ```
   feat: 添加新功能
   fix: 修复问题
   docs: 更新文档
   test: 添加测试
   chore: 更新依赖
   ```

5. 提交 Pull Request 到 `develop` 分支

## 测试指南

### 运行测试

```bash
# 配置系统（Linux）
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
sudo sysctl net.bridge.bridge-nf-call-ip6tables=0

# 运行维护中的核心/CLI 测试套件
cargo test -p lowertier --lib --verbose
```

### 测试要求

测试要少，只保留会锁住真实不变量的用例：协议、加密、认证、ACL、数据包路径、资源上限。

不要为同一断言再写一份标量路径和一份批量路径。不要为同一条拒绝路径堆叠变体。不要把被 ignore 的性能基准放进 `src/`。

Keep tests for the maintained core and command-line programs. Keep the core suite at or below 500 tests. CI runs the essential suite and checks this limit.

## Pull Request 规范

1. 目标分支为 `develop`
2. 确保所有测试通过
3. 包含清晰的描述和目的
4. 关联相关的 issues
5. 保持变更的原子性和聚焦性
6. 及时更新相关文档

## 其他资源

- [问题追踪](https://github.com/lowertier/lowertier/issues)
- [项目文档](https://github.com/lowertier/lowertier/wiki)

## 需要帮助？

欢迎：
- 提出问题
- 参与社区讨论
- 联系维护者

感谢您为 LowTier 做出贡献！
