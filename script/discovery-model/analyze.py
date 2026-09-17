"""Generate a result report from retained model CSVs; Python standard library only."""
from __future__ import annotations
import csv
import json
import math
from pathlib import Path


def wilson(successes: int, n: int) -> tuple[float, float]:
    p = successes / n
    z = 1.959963984540054
    d = 1 + z*z/n
    center = (p + z*z/(2*n))/d
    radius = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))/d
    return max(0.0, center-radius), min(1.0, center+radius)


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    out = root/'target/discovery-model'
    metadata = json.loads((out/'metadata.json').read_text())
    with (out/'results.csv').open() as f:
        primary = list(csv.DictReader(f))
    runs = sorted(out.glob('results-*.csv'))
    if not runs:
        runs = [out/'results.csv']
    all_rows = []
    for path in runs:
        with path.open() as f:
            all_rows.extend(csv.DictReader(f))
    total = sum(int(r['trials']) for r in all_rows)
    parts = ['# Public discovery model results', '', 'Date: 2026-09-11 (Asia/Tokyo).', '',
             '**Simulation results. No Internet traffic or production networking code was executed.**', '',
             f"Source SHA-256: `{metadata['source_sha256']}`. Compiler: `{metadata['rustc']}`.", '',
             f"Cases per seed: {len(primary)}. Retained runs: {len(runs)}. Total modeled sessions: {total:,}.", '',
             'The successful-check time is the first authenticated-probe/ACK round trip in the model. It excludes transport establishment. Traffic includes both nodes and service responses, DNS assumptions, and peer probes; WAN and LAN are separate. IP-layer bytes exclude Ethernet/Wi-Fi and final transport handshakes. HTTP/TLS byte counts are assumed budgets. Read `script/discovery-model/README.md` before interpreting the numbers.', '',
             '## Primary seed results', '',
             'Percentiles below use successful sessions only. Every row separately reports the success fraction within five seconds. An unconditional 95th percentile is outside the decision window whenever more than 5% of sessions fail.', '']
    for scenario in dict.fromkeys(r['scenario'] for r in primary):
        parts.extend([f'### {scenario}', '',
                      '| Policy | Success within 5 s | First hint p50 (ms) | Check p50, successes (ms) | Check p95, successes (ms) | WAN bytes, all attempts | LAN bytes, all attempts |',
                      '|---|---:|---:|---:|---:|---:|---:|'])
        for r in primary:
            if r['scenario'] != scenario:
                continue
            pct = 100*int(r['success_5s'])/int(r['trials'])
            parts.append(f"| {r['policy']} | {pct:.2f}% | {r['first_hint_p50_ms']} | {r['check_p50_ms_success_only']} | {r['check_p95_ms_success_only']} | {r['mean_wan_ip_bytes_all']} | {r['mean_lan_ip_bytes_all']} |")
        parts.append('')
    parts.extend(['## Replication: success across retained seeds', '',
                  'Wilson 95% intervals quantify Monte Carlo sampling uncertainty under this model. They do not bound Internet deployment uncertainty.', '',
                  '| Scenario | Policy | Success / sessions | Pooled success | Wilson 95% interval |',
                  '|---|---|---:|---:|---:|'])
    selected = {'udp2','udp4','udp8','hedge4','mixed6','hedge4_p100'}
    scenarios = {'open_simultaneous','restricted_simultaneous','restricted_skew_2s','outage20_loss2'}
    for row in primary:
        key = (row['scenario'], row['policy'])
        if key[0] not in scenarios or key[1] not in selected:
            continue
        group = [r for r in all_rows if (r['scenario'],r['policy']) == key]
        n = sum(int(r['trials']) for r in group)
        successes = sum(int(r['success_5s']) for r in group)
        lo,hi = wilson(successes,n)
        parts.append(f'| {key[0]} | {key[1]} | {successes}/{n} | {100*successes/n:.2f}% | {100*lo:.2f}–{100*hi:.2f}% |')
    parts.extend(['', '## Reverse-discovery polling bound', '',
                  'For an incumbent with k equally phased, healthy pull directories and an illustrative common interval I=1800 s, a uniformly arriving new node waits an average I/(2k), with maximum I/k, for the incumbent\'s next poll. This is an ideal lower-latency polling arrangement; it excludes network delay, record propagation, mapping lifetime, and the subsequent punching window. Increasing the initial race width cannot remove this steady-state wait.', '',
                  '| Trackers k | Ideal mean reverse wait (s) | Ideal maximum gap (s) | Minimum IPv4 tracker traffic per node per day (bytes) |',
                  '|---:|---:|---:|---:|'])
    for k in [2,4,8,16,32]:
        parts.append(f'| {k} | {1800/(2*k):.3f} | {1800/k:.3f} | {262*k*86400//1800} |')
    parts.extend(['', 'The traffic column assumes an empty compact response and a fresh BEP-15 connect/announce exchange at every 30-minute poll. It excludes DNS, STUN upkeep, peer probes, nonempty responses, loss, and transport handshakes. Normal announce intervals are service-specific. A 30-minute interval is an input, rather than an assertion about all public trackers.', '',
                  '## Verification output', '', '```text', metadata['tests'].strip(), '```', '',
                  'See `docs/superpowers/specs/2026-09-11-public-discovery-model.md` for implementation decisions and remaining validation gates.', ''])
    destination = root/'docs/performance/public-discovery-model-results.md'
    destination.write_text('\n'.join(parts), encoding='utf-8')
    print(f'Wrote {destination.relative_to(root)}; {total:,} model sessions.')


if __name__ == '__main__':
    main()
