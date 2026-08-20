#!/usr/bin/env python3
"""Run the LowTier packet-work sweep through the existing Colima harness."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Iterable


def parse_int_list(value: str, *, minimum: int, maximum: int) -> list[int]:
    values: list[int] = []
    for item in value.split(","):
        parsed = int(item.strip())
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{parsed} is outside [{minimum}, {maximum}]"
            )
        if parsed not in values:
            values.append(parsed)
    if not values:
        raise argparse.ArgumentTypeError("at least one value is required")
    return values


def case_name(inner_bytes: int, batch_cap: int, flows: int, run: int) -> str:
    return f"L{inner_bytes:04d}-B{batch_cap:02d}-F{flows:02d}-R{run:02d}"


def run_command(command: list[str], env: dict[str, str], log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.run(
            command,
            env=env,
            text=True,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    if process.returncode != 0:
        raise RuntimeError(
            f"command failed with exit {process.returncode}; see {log_path}"
        )


def iter_cases(
    packet_sizes: Iterable[int],
    batch_caps: Iterable[int],
    flow_counts: Iterable[int],
    runs: int,
):
    for batch_cap in batch_caps:
        for inner_bytes in packet_sizes:
            udp_payload_bytes = inner_bytes - 28
            if udp_payload_bytes < 1:
                raise ValueError(
                    f"inner packet size {inner_bytes} cannot carry an IPv4 UDP payload"
                )
            for flows in flow_counts:
                for run in range(1, runs + 1):
                    yield inner_bytes, udp_payload_bytes, batch_cap, flows, run


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--result-dir", type=Path, default=Path("target/arm-work-model")
    )
    parser.add_argument(
        "--image", default="lowertier-throughput:work-model"
    )
    parser.add_argument("--docker-context", default="colima")
    parser.add_argument("--packet-sizes", default="64,256,512,1024,1360")
    parser.add_argument("--batch-caps", default="1,4,16,64")
    parser.add_argument("--flows", default="1,4")
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--duration", type=int, default=5)
    parser.add_argument("--omit", type=int, default=1)
    parser.add_argument("--udp-rate", default="12000M")
    parser.add_argument("--raw-gate-bps", type=int, default=12_000_000_000)
    parser.add_argument("--tun-queues", type=int, default=4)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()

    if args.runs < 1 or args.duration < 2 or args.omit < 0:
        parser.error("runs and duration must be positive; omit must be nonnegative")
    if not 1 <= args.tun_queues <= 4:
        parser.error("tun-queues must be between 1 and 4")

    packet_sizes = parse_int_list(args.packet_sizes, minimum=29, maximum=65_507)
    batch_caps = parse_int_list(args.batch_caps, minimum=1, maximum=64)
    flow_counts = parse_int_list(args.flows, minimum=1, maximum=64)
    if args.smoke:
        packet_sizes = [64, 1360]
        batch_caps = [1, 64]
        flow_counts = [1]
        args.duration = max(3, min(args.duration, 4))
        args.runs = 1

    repo_root = Path(__file__).resolve().parents[2]
    harness = repo_root / "script/colima-throughput/e2e.sh"
    result_root = args.result_dir.resolve()
    if result_root.exists() and not args.resume:
        shutil.rmtree(result_root)
    result_root.mkdir(parents=True, exist_ok=True)
    (result_root / "logs").mkdir(exist_ok=True)

    manifest = {
        "packet_sizes": packet_sizes,
        "batch_caps": batch_caps,
        "flow_counts": flow_counts,
        "runs": args.runs,
        "duration": args.duration,
        "omit": args.omit,
        "udp_rate": args.udp_rate,
        "raw_gate_bps": args.raw_gate_bps,
        "tun_queues": args.tun_queues,
        "image": args.image,
        "docker_context": args.docker_context,
    }
    (result_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    cases = list(
        iter_cases(packet_sizes, batch_caps, flow_counts, args.runs)
    )
    first_pending = True
    for index, (inner_bytes, udp_payload, batch_cap, flows, run) in enumerate(
        cases, start=1
    ):
        name = case_name(inner_bytes, batch_cap, flows, run)
        case_dir = result_root / name
        complete = case_dir / "complete.json"
        if args.resume and complete.exists():
            print(f"[{index}/{len(cases)}] reuse {name}", flush=True)
            continue

        case_dir.mkdir(parents=True, exist_ok=True)
        metadata = {
            "case": name,
            "inner_packet_bytes": inner_bytes,
            "udp_payload_bytes": udp_payload,
            "configured_batch_cap": batch_cap,
            "flows": flows,
            "run": run,
            "direction": "forward",
            "node_a": "lowertier-throughput-a",
            "node_b": "lowertier-throughput-b",
        }
        (case_dir / "case.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        build_image = not args.no_build and first_pending
        raw_gate = first_pending
        runtime_env = " ".join(
            [
                f"LOWTIER_PACKET_BATCH_LIMIT={batch_cap}",
                "LOWTIER_DATAPLANE_SAMPLE_EVERY=1",
                "LOWTIER_DISABLE_LINUX_TUN_OFFLOAD=1",
                f"LOWTIER_TUN_QUEUES={args.tun_queues}",
            ]
        )
        env = os.environ.copy()
        env.update(
            {
                "DOCKER_CONTEXT": args.docker_context,
                "LOWTIER_BENCH_IMAGE": args.image,
                "RESULT_DIR": str(case_dir),
                "BUILD_IMAGE": "1" if build_image else "0",
                "RUN_RAW_GATE": "1" if raw_gate else "0",
                "REQUIRE_RAW_GATE": "1" if raw_gate else "0",
                "RAW_GATE_BPS": str(args.raw_gate_bps),
                "MODES": "auto",
                "DIRECTIONS": "forward",
                "UNDERLAY_PROTOCOL": "quic",
                "RUN_TCP": "0",
                "RUN_UDP": "0",
                "RUN_CPU_PROBE": "1",
                "CPU_PROTOCOL": "udp",
                "CPU_UDP_RATE": args.udp_rate,
                "CPU_UDP_LENGTH": str(udp_payload),
                "CAPTURE_DATAPLANE_STATS": "1",
                "PARALLEL_STREAMS": str(flows),
                "DURATION": str(args.duration),
                "CPU_DURATION": str(args.duration),
                "OMIT": str(args.omit),
                "RUNS": "1",
                "LOWTIER_RUNTIME_ENV": runtime_env,
            }
        )
        print(
            f"[{index}/{len(cases)}] {name}: L={inner_bytes} B={batch_cap} F={flows}",
            flush=True,
        )
        try:
            run_command(
                ["bash", str(harness)],
                env,
                result_root / "logs" / f"{name}.log",
            )
        except Exception as error:
            (case_dir / "failure.json").write_text(
                json.dumps({"error": str(error)}, indent=2) + "\n",
                encoding="utf-8",
            )
            raise
        complete.write_text(
            json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8"
        )
        first_pending = False

    fit_script = repo_root / "script/colima-throughput/fit_work_model.py"
    process = subprocess.run(
        [sys.executable, str(fit_script), str(result_root)],
        text=True,
    )
    return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
