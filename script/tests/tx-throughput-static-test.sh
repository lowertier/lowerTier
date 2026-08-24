#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
benchmark="$repo_root/lowertier/benches/tx_throughput.rs"

test -f "$benchmark"
grep -q 'prepare_scalar_window' "$benchmark"
grep -q 'prepare_batch_window' "$benchmark"
grep -q 'MAX_PREPARED_PAYLOAD_BYTES' "$benchmark"
grep -q 'CompletionTracker' "$benchmark"
grep -q 'wait_for_completed_transfer' "$benchmark"
grep -q 'catch_unwind' "$benchmark"
grep -q 'teardown_topology' "$benchmark"

if ! awk '
    /inst_b\.run\(\)\.await/ { instance_run = NR }
    /add_packet_process_pipeline\(Box::new\(completion\.clone\(\)\)\)/ {
        tracker_install = NR
    }
    END {
        exit instance_run && tracker_install > instance_run ? 0 : 1
    }
' "$benchmark"; then
    echo "the completion tracker must be installed after the instance filters" >&2
    exit 1
fi

if awk '
    /let start = Instant::now\(\);/ {
        timed = 1
        waited = 0
        regions += 1
    }
    timed && /pkt\.clone\(\)|packet\.clone\(\)|batch\.clone\(\)|make_packet_batch|prepare_[a-z_]+_window/ {
        clone_found = 1
    }
    timed && /wait_for_completed_transfer/ { waited = 1 }
    timed && /start\.elapsed\(\)/ {
        if (!waited) {
            missing_wait = 1
        }
        timed = 0
    }
    END {
        exit clone_found || missing_wait || timed || regions != 3 ? 0 : 1
    }
' "$benchmark"; then
    echo "timed benchmark regions must exclude preparation and wait for receiver completion" >&2
    exit 1
fi

echo "tx throughput static tests passed"
