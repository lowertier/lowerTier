# Contributing to lowertier

[中文](CONTRIBUTING_zh.md)

## Set up

You need rustup, LLVM and Clang, and `protoc`. Cargo installs the nightly pinned in `rust-toolchain.toml`.

On Debian or Ubuntu:

```bash
sudo apt-get install -y musl-tools llvm clang protobuf-compiler bridge-utils
git clone https://github.com/lowertier/lowerTier.git
cd lowerTier
cargo build --release --locked -p lowertier --bins
```

The CI targets are Linux (musl) and macOS and Windows, each on x86_64 and aarch64. See `.github/workflows/core.yml` for the exact builds.

| Path | Contains |
| --- | --- |
| `lowertier/` | The node, the command-line tool, and the web interface (`lowertier/gui`, built files committed) |
| `lowertier-tracker/` | The tracker and STUN server |
| `lowertier-contrib/lowertier-ffi/` | C interface for platform clients |
| `docs/` | Guides; `docs/design/` holds protocol and implementation notes |
| `script/` | Install script, test harnesses, and benchmarks |

## Rules

- Keep the current protocol and configuration format. Do not add compatibility paths for older builds; update test nodes after breaking changes.
- Commit to `main` with conventional messages: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
- Update the docs in the same change. After changing an option in `lowertier/src/common/config_schema.rs`, regenerate the reference:

```bash
python3 script/docs/options-reference.py > docs/options.md
```

## Tests

Keep tests few and meaningful. A test stays only if it locks a real invariant: protocol, cryptography, authentication, ACLs, the packet path, or a resource bound.
No scalar-plus-batch copies of one assertion, no combinatorial matrices unless each cell is a different invariant, and no ignored benchmarks in `src/`.
CI holds the core suite to at most 500 tests.

```bash
cargo test -p lowertier --lib
```

After a release build, check that two nodes with no configured peers find each other through a tracker and carry data:

```bash
cargo build --release -p lowertier --bin lowertier -p lowertier-tracker --features lowertier-tracker/server --bin lowertier-tracker
python3 script/tests/tracker-bootstrap-test.py
```

On Linux, bridge tests need:

```bash
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
sudo sysctl net.bridge.bridge-nf-call-ip6tables=0
```

## Questions

Open an [issue](https://github.com/lowertier/lowerTier/issues).
