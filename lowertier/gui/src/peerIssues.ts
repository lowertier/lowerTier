import type { PeerRow } from "./store";

export interface PeerIssue {
  row: PeerRow;
  reason: string;
  rank: number;
}

interface Version {
  release: number[];
}

function version(value: string): Version | undefined {
  const match = /^(\d+)\.(\d{2,})$/.exec(value);
  if (!match) return;
  const release = match.slice(1).map(Number);
  if (!release.every(Number.isSafeInteger)) return;
  return { release };
}

/** Unknown version formats do not establish an older release. */
export function olderVersion(peerVersion: string, localVersion: string): boolean {
  const peer = version(peerVersion);
  const local = version(localVersion);
  if (!peer || !local) return false;
  for (let index = 0; index < peer.release.length; index++) {
    if (peer.release[index] !== local.release[index]) return peer.release[index] < local.release[index];
  }
  return false;
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
