"""Compile/test/run the offline Rust model using structured argv, without a shell."""
from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--trials', type=int, default=10000)
    parser.add_argument('--seed', type=int, default=20260911)
    args = parser.parse_args()
    if not 1 <= args.trials <= 1000000:
        parser.error('--trials must be between 1 and 1000000')
    root = pathlib.Path(__file__).resolve().parents[2]
    source = root / 'script/discovery-model/discovery_model.rs'
    out = root / 'target/discovery-model'
    out.mkdir(parents=True, exist_ok=True)
    log = []
    def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(argv, cwd=root, capture_output=True, text=True, check=False)
        log.append({'argv': argv, 'cwd': str(root), 'exit_code': result.returncode,
                    'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            (out / 'execution.json').write_text(json.dumps(log, indent=2))
            sys.stderr.write(result.stdout + result.stderr)
            raise SystemExit(result.returncode)
        return result
    version = run(['rustc', '--version']).stdout.strip()
    run(['rustfmt', '--edition', '2024', '--check', str(source)])
    tests = out / 'discovery-model-tests'
    binary = out / 'discovery-model'
    run(['rustc', '--edition=2024', '-D', 'warnings', '--test', str(source), '-o', str(tests)])
    test_result = run([str(tests)])
    run(['rustc', '--edition=2024', '-D', 'warnings', '-O', str(source), '-o', str(binary)])
    result = run([str(binary), str(args.trials), str(args.seed)])
    (out / 'results.csv').write_text(result.stdout)
    metadata = {'kind': 'simulation', 'trials_per_case': args.trials, 'seed': args.seed,
                'rustc': version, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                'source': str(source.relative_to(root)), 'tests': test_result.stdout,
                'network_packets_sent_by_experiment': 0}
    (out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    (out / 'execution.json').write_text(json.dumps(log, indent=2) + '\n')
    print(test_result.stdout)
    print(json.dumps(metadata, indent=2))
    print('Results: target/discovery-model/results.csv')


if __name__ == '__main__':
    main()
