# Contributing to LowTier

[中文版](CONTRIBUTING_zh.md)

Thank you for your interest in contributing to LowTier! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
  - [Prerequisites](#prerequisites)
  - [Installation Steps](#installation-steps)
- [Project Structure](#project-structure)
- [Build Guide](#build-guide)
  - [Building Core](#building-core)
- [Development Workflow](#development-workflow)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Additional Resources](#additional-resources)

## Development Environment Setup

### Prerequisites

#### Required Tools
- Rust toolchain (version 1.95)
- LLVM and Clang
- Protoc (Protocol Buffers compiler)

#### Platform-Specific Dependencies

**Linux (Ubuntu/Debian)**
```bash
# Core build dependencies
sudo apt-get update && sudo apt-get install -y \
    musl-tools \
    llvm \
    clang \
    protobuf-compiler

# Testing dependencies
sudo apt install -y bridge-utils
```

**For Cross-Compilation**
- musl-cross toolchain (for MIPS and other architectures)
- Additional setup may be required (see `.github/workflows/` for details)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/lowertier/lowertier.git
   cd LowTier
   ```

2. Install dependencies:
   ```bash
   # Install Rust toolchain
   rustup install 1.95
   rustup default 1.95
   ```

## Project Structure

```
lowertier/          # Core functionality and libraries
lowertier-contrib/lowertier-ffi/ # C interface for platform clients
.github/workflows/ # CI/CD configuration files
```

## Build Guide

### Building Core

```bash
# Standard build
cargo build --release

# Platform-specific builds
cargo build --release --target x86_64-unknown-linux-musl     # Linux x86_64
cargo build --release --target aarch64-unknown-linux-musl    # Linux ARM64
cargo build --release --target x86_64-apple-darwin           # macOS x86_64
cargo build --release --target aarch64-apple-darwin          # macOS M1/M2
cargo build --release --target x86_64-pc-windows-msvc        # Windows x86_64
```

Build artifacts: `target/[target-triple]/release/`

### Build Notes

1. Cross-compilation for ARM/MIPS requires additional setup
2. Windows builds need correct DLL files
3. Check `.github/workflows/` for detailed build configurations

## Development Workflow

1. Create a feature branch from `develop`:
   ```bash
   git checkout develop
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards

3. Write or update tests as needed

4. Use conventional commit messages:
   ```
   feat: add new feature
   fix: resolve bug
   docs: update documentation
   test: add tests
   chore: update dependencies
   ```

5. Submit a pull request to `develop`

## Testing Guidelines

### Running Tests

```bash
# Configure system (Linux)
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
sudo sysctl net.bridge.bridge-nf-call-ip6tables=0

# Run the maintained core/CLI suite
cargo test -p lowertier --lib --verbose
```

### Test Requirements

Keep tests minimal. A test stays in the tree only if it locks a real invariant: protocol, crypto, auth, ACL, packet path, or a resource bound.

Do not add scalar-plus-batch copies of the same assertion. Do not add combinatorial matrices unless each cell is a different invariant. Do not put ignored perf benches in `src/`.

Keep tests for the maintained core and command-line programs. Keep the core suite at or below 500 tests.

```bash
cargo test -p lowertier --lib
```

CI runs this complete essential suite and enforces the 500-test budget.

## Pull Request Guidelines

1. Target the `develop` branch
2. Ensure all tests pass
3. Include clear description and purpose
4. Reference related issues
5. Keep changes focused and atomic
6. Update documentation as needed

## Additional Resources

- [Issue Tracker](https://github.com/lowertier/lowertier/issues)
- [Project Documentation](https://github.com/lowertier/lowertier/wiki)

## Questions or Need Help?

Feel free to:
- Open an issue for questions
- Join our community discussions
- Reach out to maintainers

Thank you for contributing to LowTier!
