# Native process memory, 2026-09-22

The v8 QUIC diagnostic recorded 39.95 MiB of process RSS on UTMOWRT during traffic.
Anonymous resident memory accounted for 24.76 MiB.
The later allocation diagnostic identifies QUIC receive arrays and protobuf descriptors among the live allocations.
It does not fully account for production anonymous RSS.

## Measurement

The fixture used the existing v8 native osku–UTMOWRT configuration with tracker bootstrap and a direct QUIC data path.
It ran a separate 15-second, four-stream reverse TCP transfer.
Process snapshots ran during traffic and after the transfer.
A local release build ran concurrently, so these results do not provide a throughput or CPU comparison.
The diagnostic completed, and cleanup stopped its temporary services and removed its private configuration.

| UTMOWRT memory | During traffic | After traffic |
| --- | ---: | ---: |
| RSS | 40,908 KiB | 41,996 KiB |
| Anonymous RSS | 25,356 KiB | 26,444 KiB |
| File RSS | 4 KiB | 4 KiB |
| Shared-memory RSS | 15,548 KiB | 15,548 KiB |

The core executable resides on `/tmp`, a tmpfs filesystem.
Its mapped text size is 14,964 KiB; its mappings also include read-only data and writable sections.
The shared-memory counter is consistent with resident tmpfs-backed executable pages.
OpenWrt provides neither `smaps` nor `smaps_rollup`, so exact resident ownership by mapping remains unavailable.
The executable and anonymous memory remain part of the reported process RSS.

The process had two owned UDP sockets in both snapshots.
Peer status identified one as the seed connection and one as the direct osku connection.
The sampled UDP transmit and receive queues were empty.
Empty queues do not establish zero kernel socket memory.

## Source model and next investigation

With UDP GRO enabled, each Linux QUIC endpoint reserves a receive array of `1500 × 64 × 32 = 3,072,000` bytes.
The two observed endpoints then require 5.86 MiB of receive-array storage.
Without UDP GRO, each endpoint reserves `1500 × 1 × 32 = 48,000` bytes.
The snapshots do not record the runtime GRO result, so these are conditional allocation estimates.
Neither estimate measures resident memory.
The kernel can leave untouched pages nonresident.
These receive arrays alone cannot explain all 24.76 MiB of anonymous RSS.
Changing their limits without allocation evidence would not address the full observed gap.

Osku's physical footprint was 13.3 MiB during traffic and 13.2 MiB afterward.
The `IOAccelerator` label in `vmmap` covers mimalloc's VM tag 100 in this binary.
That label does not establish GPU use.
Shared-library resident totals from `vmmap` must not be summed as private process memory.

The next memory investigation needs live-allocation ownership or allocator statistics with adequate coverage.
The present release uses `MI_STAT=0`; it does not collect full mimalloc allocation-bin statistics.
The QUIC MTU correction has a separate release measurement in [native transport measurements](zerotier-native-20260922.md).
That matrix retained MTU 1420 and reduced CPU per delivered Gbit.
It did not meet the resident-memory goal.

## Kernel socket counters

`socket-memory.c` uses temporary descriptor copies to read socket options from a running process.
It does not read socket data or change socket settings.
The helper compiled for Linux ARM64 with all compiler warnings treated as errors.
An idle ZeroTier check on UTMOWRT successfully read 23 IPv4 and IPv6 Internet socket descriptors.
That check is a capability test, not a load-matched memory comparison.

The helper records UDP GRO, buffer limits, and `SO_MEMINFO` values.
The revised helper also records the socket inode because multiple descriptors can refer to one socket.
Count unique inodes before calculating socket totals.
The `sk_meminfo` array follows Linux's `SK_MEMINFO_*` order:
receive allocation, receive limit, send allocation, send limit, forward allocation, queued send memory, option memory, backlog memory, and drop count.
The first eight entries use bytes. The final entry counts drops.
Buffer limits are not allocated-memory totals; these fields must not be summed without accounting for overlap.
Later LowTier snapshots use this helper to verify GRO and preserve kernel memory evidence.
The earlier v8 snapshots did not run this helper, so their GRO state remains unverified.

The descriptor-copy contract is documented in [pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html).

## Socket diagnostic follow-up

The separate `native-v8-memory-sockets` run completed the same memory workload with socket-option snapshots.
Both QUIC sockets reported `UDP_GRO=1` during and after traffic.
Their receive-array allocation model is therefore 5.86 MiB for this run.
This result does not establish the earlier run's GRO state or measure the arrays' resident pages.

During traffic, UTMOWRT reported 39,940 KiB RSS, including 24,452 KiB anonymous RSS.
After traffic, those counters were 40,060 KiB and 24,572 KiB.
Four Internet socket descriptors referred to three unique sockets: two QUIC sockets and the local RPC listener.
The discovery socket had two descriptors with one inode.

Both QUIC sockets reported zero receive allocation and zero drop count at both snapshots.
The active data socket reported 33,360 bytes of send allocation during traffic and zero afterward.
Each QUIC socket retained 4,096 bytes of forward allocation.
Each send and receive buffer limit was 14,680,064 bytes; these limits were not allocated-memory totals.
These point samples do not bound kernel-memory peaks during the transfer.

The complete run and cleanup passed in `native-v8-memory-sockets-diagnostic.json`.
The reduced evidence is `native-v8-memory-sockets-memory-summary.json`.

## v9 follow-up

The v9 matrix used matching native and ARM data endpoints with only the MTU detector correction relative to v8.
The seed and tracker retained their exact v8 baseline binaries.
No build or profiler ran during the matrix.
Its separate memory diagnostic followed all ten performance trials in the same daemon instance.

UTMOWRT reported 56,876 KiB RSS during the diagnostic, including 41,260 KiB anonymous RSS.
After traffic, those counters were 57,224 KiB and 41,608 KiB.
Osku's physical footprint was 13.9 MiB in both snapshots.
Both QUIC sockets reported UDP GRO enabled and zero receive allocation at the snapshots.
The receive-array allocation model remains 5.86 MiB.

The earlier dedicated v8 memory diagnostics started fresh daemons and ran only the short diagnostic workload.
Their lifetime histories differ, so these snapshots do not establish a memory regression from the MTU correction.
The full v8 and v9 TCP matrices had similar UTMOWRT RSS peaks: 55.04 and 56.22 MiB.
The next diagnostic will use the existing jemalloc profiling feature to identify sampled allocation symbols.
That allocator differs from production mimalloc; its RSS and CPU will not serve as production comparison measurements.
The release diagnostic retains symbols but does not guarantee complete source-line or inline attribution.

The run and cleanup passed in `native-v9-quic-matrix.json`.
The separate memory summary is `native-v9-memory-summary.json`.

The first profiling build failed while linking a host build script.
The selected macOS 27 SDK contained architecture tags unsupported by that linker.
The recovery selects the installed Xcode 26.5 SDK and its matching host compiler.
The original failure remains in `v10-heap-build.json`; the recovery uses a separate receipt.

The SDK recovery reached final linking but reported seven missing jemalloc symbols.
The host archive tool had produced 96-byte empty archives from valid ARM64 profiling objects.
The recovery preserved an empty archive and rebuilt the profiling archive with LLVM's archive tool.
All seven required exported symbols are present in the recovered archive.
The next build uses jemalloc's supported `JEMALLOC_OVERRIDE` input with a verified archive hash.
The archive recipe and checks remain in `heap-archive-recovery-run.json` and its referenced receipts.

A small ARM64 runtime check on UTMOWRT allocated two MiB and successfully called the allocator's profile control API.
It produced a valid `heap_v2` profile.
The symbolizer attributed its sampled estimate to the known `allocation_probe` function.
This verifies the recovered allocator and symbolization path, not LowTier allocation ownership.
The target configuration preserves non-leaf frame pointers for its profiling backend.
The report also verifies static ARM64 ELF assumptions before interpreting LowTier profiles.

The crate package lacked the `VERSION` file expected during profiler-tool preparation.
The recovery read the generated jemalloc header's version and produced a syntax-checked tool.
The failed and recovered preparation receipts use the `jeprof-prepare` prefix.

## Completed allocation diagnostic

The recovered ARM64 profiling build passed its source guard and symbol checks.
Its SHA-256 is `61168f321c263840e89b4af00925e8b5c322eed5ca6228d12c21468062fbd951`.
UTMOWRT used this diagnostic binary; osku used production v9, and the seed and tracker used v8.
The diagnostic binary also contains the queued-datagram boundary correction, which is absent from measured v9.
The separate 15-second, four-stream reverse workload completed over an authenticated direct QUIC route.
Startup initially returned an unavailable-instance response; subsequent checks established the route.
All temporary processes and private files were removed after collection.

| Jemalloc counter, bytes | Idle | During traffic | After traffic |
| --- | ---: | ---: | ---: |
| Allocated | 15,925,024 | 23,267,344 | 16,416,304 |
| Active | 17,182,720 | 25,120,768 | 18,984,960 |
| Metadata | 4,458,272 | 4,692,512 | 4,720,832 |
| Resident | 22,872,064 | 31,985,664 | 25,964,544 |

Allocator resident memory is not whole-process RSS.
The profiler changes allocation and retention behavior, so these counters do not compare production resource use with ZeroTier.
The sampling interval was 524,288 bytes.
The sampled live-byte estimate for Quinn endpoint initialization was 6,307,318 bytes in all three snapshots.
Allocator bins independently showed two allocations of 3,145,728 bytes each.
Those allocations agree with two requested 3,072,000-byte receive arrays after size-class rounding.

Descriptor initialization through `flags_to_dynamic_message` accounted for a cumulative sampled estimate of 5,451,592 bytes.
This estimate is neither an exact allocation total nor RSS.
Parent and child cumulative rows describe overlapping allocations and must not be added.
Release LTO, missing line tables, and generic symbol names limit finer attribution.
Automatic profiles without a recorded capture phase are classified as `unclassified`.
Their filenames retain the original collection label; the corrected index distinguishes capture from collection.

A separate native allocation counter compared the global descriptor pool with a private pool using the same descriptor bytes.
The global pool retained 1,880,263 requested bytes; the private pool retained 1,893,034 bytes.
Initialization made 35,783 and 35,997 allocation calls, respectively.
The private pool still initializes global descriptors when resolving protobuf options.
This experiment rejected the proposed private-pool memory reduction, so no generator change was applied.
These exact requested-byte counts use the system allocator and do not replace the ARM64 sampled estimates or RSS measurements.
The counter initially failed to link against split Cargo metadata artifacts.
Providing both metadata and archive inputs, with the procedural-macro dependency paths, recovered the build.
All failed attempts remain in the audit.

A second allocation experiment removed only `FileDescriptorProto.source_code_info` from a copied descriptor set.
Every other encoded field remained unchanged.
The embedded descriptor shrank from 77,778 to 28,101 bytes.
Global initialization retained 1,092,305 requested bytes and made 18,172 allocation calls.
This saved 787,958 requested bytes compared with the original input.
Both inputs exposed 15 files and 163 messages, including the three checked configuration and routing types.
The experiment did not test every reflection operation or change production code.
Source locations and comments would be unavailable through the stripped runtime descriptor.
The complete evidence is `descriptor-source-info-experiment.json` and `descriptor-source-info-summary.json`.

The v14 build now removes source metadata from a separate runtime descriptor after Rust generation completes.
Generated Rust documentation and the full schema descriptor remain unchanged.
The transformation uses dynamic protobuf messages to preserve custom options and unknown fields.
The generated runtime descriptor matches the earlier experiment byte for byte: 28,101 bytes, down from 77,778 bytes.
The artifact check is `tracker-discovery-20260922/v14-descriptor-artifact.json`.
The earlier 787,958-byte reduction measures requested allocations with the native system allocator.
It does not establish production RSS savings or a resource-use advantage over ZeroTier.
Matching v14 releases were deployed for one H2 discovery and delivery check on all four client hosts and the seed.
That check did not measure RSS or CPU use.
The descriptor equality and configuration serialization checks passed in `tracker-discovery-20260922/v14-final-focused.json`.

The profile index, reduced report, and allocation comparison are `native-v10-heap-profiles/index.json`,
`native-v10-heap-summary.json`, and `descriptor-allocation-summary.json` in the evidence directory.
The original phase labels remain in separate `*-original.json` records.

## H2 and WSS component checks

Separate v8 H2 and WSS diagnostics used fresh daemons and the same 15-second, four-stream reverse workload.
Each diagnostic selected an authenticated direct route before and after traffic.
The local profiling build ran concurrently, so these are memory component checks without throughput or CPU comparison claims.
Both workloads and cleanup completed.

| UTMOWRT counter | H2 during | H2 after | WSS during | WSS after |
| --- | ---: | ---: | ---: | ---: |
| RSS, KiB | 31,132 | 32,028 | 23,964 | 24,276 |
| Anonymous RSS, KiB | 16,156 | 17,052 | 9,052 | 9,364 |
| File RSS, KiB | 4 | 4 | 4 | 4 |
| Shared-memory RSS, KiB | 14,972 | 14,972 | 14,908 | 14,908 |
| Osku physical footprint, MiB | 13.8 | 13.9 | 12.8 | 13.3 |

Each process had eight unique Internet socket inodes.
Each had one UDP discovery socket with UDP GRO disabled; its data connections used TCP.
The active H2 TCP socket reported 1,569,895 bytes of queued send memory during traffic.
Its send-allocation counter separately reported 130,390 bytes.
The active WSS TCP socket reported 4,866,766 queued bytes and 130,386 send-allocation bytes.
These counters can overlap and must not be added as independent allocations.
Both sockets reported zero for those two counters after traffic.
WSS's socket drop counter was one in both snapshots; this does not establish workload packet loss.
These point samples do not bound kernel-memory peaks.

The results show lower anonymous RSS for these fresh TCP fixtures than the fresh QUIC diagnostic.
They do not identify the allocation owners or prove that all differences come from QUIC receive arrays.
The WSS startup API check initially reported that the instance was not ready; the next check succeeded.
Complete receipts use `native-v8-memory-h2` and `native-v8-memory-wss` prefixes.
Their `memory-summary.json` files preserve socket counters, process counters, and mappings.

## Packet pool initialization correction

Source review found an invalid initialization assumption in packet pool overflow allocation.
The allocator extended `BytesMut` to its full length before initializing the bytes.
The installed `bytes` 1.9.0 API requires initialized data before `set_len`.
Linux TUN receives expose slices and write only the payload region.
The packet prefix and unused tail could remain uninitialized, while recycling assumed a fully initialized slab.
The UDP receive path also used this allocator before clearing its length.

Pool misses now use the existing zero-initialized allocation function.
Reused slabs retain their existing allocation and initialization behavior.
If there are `M` pool misses per second and each slab contains `S` bytes, initialization adds at most `M × S` written bytes per second.
This cost model does not establish a measured throughput or RSS change.
The correction restores the buffer API contract before further performance validation.

The existing empty-pool regression now checks the complete initial buffer, a partial payload write, and the restored prefix and tail after recycling.
The first exact test filter omitted the module path and selected zero tests.
The corrected filter selected one test, which passed.
Both receipts remain under `tracker-discovery-20260922/v19-buffer-initialization-*.json`.
Source inspection establishes the original defect; zero-filled allocator pages can hide it in an ordinary test.

## Evidence

Complete receipts reside in `benchmark-results/zerotier-goal-20260922/`.
The diagnostic receipt is `native-v8-memory-fds-diagnostic.json`.
The summary is `native-v8-memory-fds-memory-summary.json`.
`process-memory.js` records process counters, mappings, and socket ownership without requiring `smaps`.
`memory-evidence.py` checks the RSS components and reduces the saved snapshots.
The audit is `benchmark-results/.work/zerotier-goal-20260922.jsonl`.
