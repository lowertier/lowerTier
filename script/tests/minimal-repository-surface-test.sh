#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

removed_paths=(
  ".envrc"
  "android.nix"
  "flake.lock"
  "flake.nix"
  ".github/actions/prepare-pnpm/action.yml"
  ".github/workflows/nix.yml"
  ".github/workflows/gui.yml"
  ".github/workflows/mobile.yml"
  ".github/workflows/ohos.yml"
)

for path in "${removed_paths[@]}"; do
  if [[ -e "$repo_root/$path" ]]; then
    echo "removed repository surface still exists: $path" >&2
    exit 1
  fi
done

retained_paths=(
  "lowertier-gui/package.json"
  "lowertier-gui/src-tauri/Cargo.toml"
  "tauri-plugin-vpnservice/Cargo.toml"
  "lowertier-web/Cargo.toml"
  "lowertier-web/frontend/package.json"
  "lowertier-web/frontend-lib/package.json"
  ".github/workflows/core.yml"
)

for path in "${retained_paths[@]}"; do
  test -e "$repo_root/$path"
done

active_files=(
  "$repo_root/Cargo.toml"
  "$repo_root/pnpm-workspace.yaml"
  "$repo_root/.gitignore"
  "$repo_root/lowertier.code-workspace"
  "$repo_root/README.md"
  "$repo_root/README_CN.md"
  "$repo_root/CONTRIBUTING.md"
  "$repo_root/CONTRIBUTING_zh.md"
  "$repo_root/.github/actions/prepare-build/action.yml"
  "$repo_root/.github/workflows/core.yml"
  "$repo_root/.github/workflows/offline-source-archive.yml"
  "$repo_root/.github/workflows/release.yml"
  "$repo_root/.github/workflows/test.yml"
)

if grep -En 'flake\.nix|android\.nix|\.flake-profile|\.direnv|\[nix\]' "${active_files[@]}"; then
  echo "removed Nix build surface is still referenced" >&2
  exit 1
fi

if grep -Eq 'lowertier-gui|lowertier-web|lowertier-contrib' "$repo_root/Cargo.toml"; then
  echo "the Cargo workspace contains a non-CLI package" >&2
  exit 1
fi
grep -Fq "'lowertier-gui'" "$repo_root/pnpm-workspace.yaml"
grep -Fq "'tauri-plugin-vpnservice'" "$repo_root/pnpm-workspace.yaml"
grep -Fq "'lowertier-web/frontend'" "$repo_root/pnpm-workspace.yaml"
grep -Fq "'lowertier-web/frontend-lib'" "$repo_root/pnpm-workspace.yaml"

core_workflow="$repo_root/.github/workflows/core.yml"
test_workflow="$repo_root/.github/workflows/test.yml"
release_workflow="$repo_root/.github/workflows/release.yml"
docker_file="$repo_root/.github/workflows/Dockerfile"

required_targets=(
  "x86_64-unknown-linux-musl"
  "aarch64-unknown-linux-musl"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
  "x86_64-pc-windows-msvc"
  "aarch64-pc-windows-msvc"
)

for target in "${required_targets[@]}"; do
  grep -Fq "$target" "$core_workflow"
done

if grep -Eiq 'mips|riscv|loongarch|armv7|i686|freebsd|magisk|build_web|lowertier-web|zigbuild|gui|pnpm' "$core_workflow"; then
  echo "the core workflow contains an unsupported or non-CLI build" >&2
  exit 1
fi

grep -Fq -- '--package lowertier --bins' "$core_workflow"
grep -Fq -- '--no-default-features' "$core_workflow"
grep -Fq -- '--features lean' "$core_workflow"
grep -Fq 'default = ["lean"]' "$repo_root/lowertier/Cargo.toml"
grep -Fq 'lean = [' "$repo_root/lowertier/Cargo.toml"

if grep -Eq 'pre_job|pre-test|test_matrix|nextest archive|upload-artifact|download-artifact' "$test_workflow"; then
  echo "the test workflow contains a duplicate or transfer-only job" >&2
  exit 1
fi

grep -Fq 'cargo nextest run' "$test_workflow"

if grep -Eiq 'lowertier-web|lowertier-gui|gui:|pnpm:' "$test_workflow"; then
  echo "the test workflow contains a frontend build" >&2
  exit 1
fi

grep -Fq 'default-members = ["lowertier"]' "$repo_root/Cargo.toml"
grep -Fq 'lto = "fat"' "$repo_root/Cargo.toml"
grep -Fq 'opt-level = 3' "$repo_root/Cargo.toml"
grep -Fq 'panic = "abort"' "$repo_root/Cargo.toml"
grep -Fq 'force-unwind-tables=no' "$core_workflow"
grep -Fq -- '--remap-path-prefix=$GITHUB_WORKSPACE=.' "$repo_root/.github/actions/prepare-build/action.yml"

if grep -Eiq 'gui_run_id|mobile_run_id|magisk' "$release_workflow"; then
  echo "the release workflow contains a non-CLI artifact" >&2
  exit 1
fi

if grep -Eq '11011|11012/tcp' "$docker_file"; then
  echo "the container exposes a disabled transport port" >&2
  exit 1
fi
grep -Fq 'EXPOSE 11012/udp' "$docker_file"

echo "minimal repository surface tests passed"
