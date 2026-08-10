#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

removed_paths=(
  ".envrc"
  "android.nix"
  "flake.lock"
  "flake.nix"
  ".github/workflows/nix.yml"
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
  ".github/workflows/gui.yml"
  ".github/workflows/mobile.yml"
  "lowertier-web/Cargo.toml"
  "lowertier-web/frontend/package.json"
  "lowertier-web/frontend-lib/package.json"
  ".github/actions/prepare-pnpm/action.yml"
  ".github/workflows/core.yml"
)

for path in "${retained_paths[@]}"; do
  test -e "$repo_root/$path"
done

active_files=(
  "$repo_root/Cargo.toml"
  "$repo_root/pnpm-workspace.yaml"
  "$repo_root/.gitignore"
  "$repo_root/LowTier.code-workspace"
  "$repo_root/README.md"
  "$repo_root/README_CN.md"
  "$repo_root/CONTRIBUTING.md"
  "$repo_root/CONTRIBUTING_zh.md"
  "$repo_root/.github/actions/prepare-build/action.yml"
  "$repo_root/.github/workflows/core.yml"
  "$repo_root/.github/workflows/ohos.yml"
  "$repo_root/.github/workflows/offline-source-archive.yml"
  "$repo_root/.github/workflows/release.yml"
  "$repo_root/.github/workflows/test.yml"
)

if grep -En 'flake\.nix|android\.nix|\.flake-profile|\.direnv|\[nix\]' "${active_files[@]}"; then
  echo "removed Nix build surface is still referenced" >&2
  exit 1
fi

grep -Fq '"lowertier-gui/src-tauri"' "$repo_root/Cargo.toml"
grep -Fq '"lowertier-web"' "$repo_root/Cargo.toml"
grep -Fq "'lowertier-gui'" "$repo_root/pnpm-workspace.yaml"
grep -Fq "'tauri-plugin-vpnservice'" "$repo_root/pnpm-workspace.yaml"
grep -Fq "'lowertier-web/frontend'" "$repo_root/pnpm-workspace.yaml"
grep -Fq "'lowertier-web/frontend-lib'" "$repo_root/pnpm-workspace.yaml"
grep -Fq 'lowertier-web/**' "$repo_root/.github/workflows/core.yml"

echo "minimal repository surface tests passed"
