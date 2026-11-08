# Test deployment and baseline policy

The owner confirms that the LowTier nodes in this workflow are test environments. Validated repairs are committed directly to main and deployed without an additional production-release approval step.

After each experiment, leave the affected test instances on the fastest correctness- and delivery-validated baseline for the measured workload. Keep the best known baseline when a candidate regresses. A newer candidate name or successful microbenchmark alone does not qualify it for promotion.

Keep native and userspace results separate, and retain protocol, direction, stream count, MTU, host pair, binary SHA256, source snapshot, receiver-side throughput, delivery/loss, latency, CPU and RSS scope. Use repeated matched trials; preserve contaminated and failed trials separately. A single peak does not replace the established baseline. When selecting one default transport, assess both directions and single/multiple-stream results together; retain protocol-specific best baselines for later comparisons.

Replacement includes the running test binary, a service restart, transfer-integrity verification, authenticated peer and route checks, and a delivery check.
Preserve network identity, secrets, ACLs, routes, and configuration records.
Record configuration changes required for the selected transport.

Do not retain legacy binaries or compressed binary backups on fleet nodes.
Validate the replacement binary before installation.
Remove superseded binaries and transfer files after replacement.
Keep the active binary and any candidate required for an unfinished deployment.
Preserve source references, deployment records, and raw measurements for baseline comparisons.
Recover a prior baseline from its source or the build service when required.

Evidence and deployment manifests live under benchmark-results/throughput-repair-20260922 and benchmark-results/.work/baseline-deploy-20260922. Raw private configuration files stay outside version control.
