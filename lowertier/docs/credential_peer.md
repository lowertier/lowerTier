# Signed credential peers

Credential mode uses one signed, URL-safe bundle. The bundle contains the
X25519 private key, the network name, the pinned Ed25519 root, and one signed
certificate.

An administrator node has a non-empty `network_secret`. The node derives the
network root from a domain-separated hash. The node can issue and revoke
credentials.

A credential node has no `network_secret`. The node loads one verified bundle.
The node stores the root public key and fingerprint from that bundle. The node
does not store the root signing seed. The node cannot issue or revoke data.

## Bundle rules

- The bundle uses canonical protobuf bytes.
- The bundle uses URL-safe base64 without padding.
- The bundle uses a random 16-byte `certificate_id`.
- Groups and proxy CIDRs are sorted and unique.
- The certificate signs the canonical certificate fields.
- The certificate lifetime is positive and no longer than 24 hours.
- The root fingerprint is SHA-256 over a domain tag and the root public key.

The verifier checks all fields before it derives the X25519 public key. It checks
the network name, root key, root fingerprint, certificate signature, lifetime,
policy order, and certificate ID.

## Startup

Credential startup requires `secure_mode.credential_bundle`. A raw
`local_private_key` is not a credential input. The loader derives the runtime
private and public keys from the verified bundle.

An empty `network_secret` is absent. A configured network identity with an
empty secret must include a signed bundle. A configuration without a network
identity can start as an unauthenticated shared node.

The loader can pin `secure_mode.credential_root_fingerprint`. The loader rejects
a bundle with a different root fingerprint.

## RPC output

`GenerateCredentialResponse.credential_secret` contains the complete signed
bundle. The response also contains the decoded `CredentialBundle`. Operators
must store the complete bundle. A private key copied without its certificate
cannot authenticate.

`CredentialInfo` reports the certificate ID, role, network name, expiry, and
root fingerprint. It does not report a private key outside the signed bundle.

## Trust and revocation

Administrators publish trusted credentials with the signed certificate. A peer
must verify the certificate with `verify_trusted_credential` before it accepts
the policy.

Revocation state is root-signed. The state contains a sorted set of certificate
IDs and a monotonic state version. The verifier checks a bounded issue time and
future skew.

Applying a valid state performs a grow-only union. The stored version becomes
the maximum of the local and remote versions. Equal versions from different
administrators cannot remove a certificate ID.

Noise admission can carry a short-lived `CredentialCertificateStatus`. The
status is stateless and has a maximum lifetime of 60 seconds. The status binds
the network, root fingerprint, certificate ID, issue time, expiry, sequence,
and revoked flag.

## Verification APIs

Use these manager APIs. Do not rebuild signing bytes in route or handshake code.

```text
verify_credential_bundle_for_network(encoded, network, pinned_root, now)
verify_trusted_credential(credential, network, pinned_root, now)
verify_certificate_bytes(bytes, network, root_fingerprint, subject, role, now)
verify_status_evidence_bytes(bytes, network, root_fingerprint, certificate_id,
                             now, max_lifetime, minimum_sequence)
```

Issuance APIs return `CredentialError::IssuerUnavailable` without administrator
issuer state. The verifier constructor accepts a signed bundle and retains no
root signing seed.
