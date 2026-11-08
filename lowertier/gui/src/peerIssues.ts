import type { PeerRow } from "./store";

export interface PeerIssue {
  row: PeerRow;
  reason: string;
  rank: number;
}

interface Version {
  release: number[];
  prerelease: string[];
  commits: number;
}

function version(value: string): Version | undefined {
  // Builds prepend the package version to the Git tag description.
  let text = value.replace(/(?:~|-dirty)$/, "").replace(/^\d+\.\d+\.\d+-(?=v\d+\.)/, "");
  if (/^\d+\.\d+\.\d+-[0-9a-f]{8,}$/i.test(text)) return;
  const description = /^(.*)-(\d+)-g[0-9a-f]+$/i.exec(text);
  const commits = description ? Number(description[2]) : 0;
  if (description) text = description[1];
  const match = /^v?(\d+)\.(\d+)\.(\d+)(?:-([\da-z-]+(?:\.[\da-z-]+)*))?(?:\+[\da-z.-]+)?$/i.exec(text);
  if (!match) return;
  return {
    release: match.slice(1, 4).map(Number),
    prerelease: match[4]?.split(".") ?? [],
    commits,
  };
}

/** Unknown versions and different commit IDs do not establish an older build. */
export function olderVersion(peerVersion: string, localVersion: string): boolean {
  const peer = version(peerVersion);
  const local = version(localVersion);
  if (!peer || !local) return false;
  for (let index = 0; index < peer.release.length; index++) {
    if (peer.release[index] !== local.release[index]) return peer.release[index] < local.release[index];
  }
  if (!peer.prerelease.length || !local.prerelease.length) {
    if (peer.prerelease.length !== local.prerelease.length) return peer.prerelease.length > 0;
  } else {
    for (let index = 0; index < Math.max(peer.prerelease.length, local.prerelease.length); index++) {
      const left = peer.prerelease[index];
      const right = local.prerelease[index];
      if (left === right) continue;
      if (left == null || right == null) return left == null;
      const leftNumeric = /^\d+$/.test(left);
      const rightNumeric = /^\d+$/.test(right);
      if (leftNumeric && rightNumeric) {
        if (Number(left) !== Number(right)) return Number(left) < Number(right);
      } else {
        return leftNumeric !== rightNumeric ? leftNumeric : left < right;
      }
    }
  }
  return peer.commits < local.commits;
}

export function issuesOf(rows: PeerRow[], localVersion: string): PeerIssue[] {
  const issues: PeerIssue[] = [];
  for (const row of rows) {
    const reasons: string[] = [];
    if (!row.direct) reasons.push("No direct connection");
    if (olderVersion(row.version, localVersion)) reasons.push("Older LowTier version");
    if (reasons.length) issues.push({ row, reason: reasons.join("; "), rank: row.direct ? 1 : 2 });
  }
  return issues.sort((left, right) => right.rank - left.rank || left.row.name.localeCompare(right.row.name));
}
