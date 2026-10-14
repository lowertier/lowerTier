# Test deployment and baseline policy

The owner confirms that the LowTier nodes in this workflow are test environments. Validated repairs are committed directly to main and deployed without an additional production-release approval step.

After each experiment, leave the affected test instances on the fastest correctness- and delivery-validated baseline for the measured workload. Keep the best known baseline when a candidate regresses. A newer candidate name or successful microbenchmark alone does not qualify it for promotion.

Keep native and userspace results separate, and retain protocol, direction, stream count, MTU, host pair, binary SHA256, source snapshot, receiver-side throughput, delivery/loss, latency, CPU and RSS scope. Use repeated matched trials; preserve contaminated and failed trials separately. A single peak does not replace the established baseline. When selecting one default transport, assess both directions and single/multiple-stream results together; retain protocol-specific best baselines for later comparisons.

Replacement includes the actual running test core and compatible CLI, followed by service restart, binary identity verification, authenticated peer/route checks and a delivery check. Preserve network identity, secrets, ACLs and routes. Configuration changes required for the selected transport must be recorded. Preserve the prior verified baseline for immediate recovery when startup or delivery fails.

Evidence and deployment manifests live under benchmark-results/throughput-repair-20260922 and benchmark-results/.work/baseline-deploy-20260922. Raw private configuration files stay outside version control.
