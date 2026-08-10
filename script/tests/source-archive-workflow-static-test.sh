#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
workflow="$repo_root/.github/workflows/offline-source-archive.yml"

test -f "$workflow"
test ! -e "$repo_root/script/build-offline-source-archive.sh"
test ! -e "$repo_root/script/tests/offline-source-archive-static-test.sh"
test ! -e "$repo_root/script/tests/offline-source-archive-e2e-test.sh"

grep -Fq 'name: LowTier Source Archive' "$workflow"
grep -Eq '^  workflow_dispatch:' "$workflow"
grep -Eq "^      - 'v\*'" "$workflow"
grep -Fq 'uses: actions/checkout@v5' "$workflow"
grep -Fq 'git archive --format=zip' "$workflow"
grep -Fq 'uses: actions/upload-artifact@v5' "$workflow"
grep -Fq 'if-no-files-found: error' "$workflow"

if grep -Eiq 'prepare-build|setup-rust|cargo|pnpm|apt-get|vendor|compile|sha256|name:[[:space:]]+test|run:.*test' "$workflow"; then
  echo 'source archive workflow must only package committed source' >&2
  exit 1
fi

echo 'source archive workflow static tests passed'
