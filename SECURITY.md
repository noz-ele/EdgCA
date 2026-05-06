# Security Policy

## Reporting a vulnerability

Please report suspected security issues **privately** via GitHub Security Advisories:

- https://github.com/noz-ele/EdgCA/security/advisories/new

Do not open public issues for security reports. We will respond on a best-effort basis; this is a small project without an SLA.

## Scope

EdgCA is a stateless certificate-issuance toolkit for Cloudflare Workers-compatible runtimes. The following are **in scope** for security reports:

- Incorrect ASN.1 / DER encoding of issued certificates that could mislead a verifier.
- Cryptographic signature or KDF misuse, including incorrect use of `globalThis.crypto.subtle`.
- Memory-safety problems, infinite loops, or unbounded allocations triggered by malformed PEM/DER input to public functions.
- Public-API surface that allows a caller to produce a certificate that violates the documented invariants (e.g., `issueIntermediateCA` producing `pathLenConstraint > 0`).

The following are **out of scope** (see [docs/en/NON_GOALS.md](docs/en/NON_GOALS.md) for the full list and rationale):

- Chain validation, revocation (CRL/OCSP), key storage, rotation — EdgCA does not provide them.
- Operational misuse of issued material (leaked private keys, logging secrets, weak storage).
- Caller-controlled inputs producing wrong outputs by design ("garbage in, garbage out" behavior is documented; e.g., `importCertificateAuthority` does not cryptographically validate that `issuerChainPem` actually issued `certPem`).
- `verifyClientCertificateIssuedBy` not authenticating the presenter — by design, this function only verifies issuance, not proof-of-possession of the private key. See the Verify section of the README for details.
- Vulnerabilities in upstream dependencies (Workers runtime, Node.js, browser WebCrypto). Report those upstream.

## Audit status

EdgCA has **not** been independently audited. The implementation is small and self-contained, but you should treat this software as best-effort and review it yourself before relying on it for production trust hierarchies.

## Supported versions

Only the latest version published to npm is supported. Fixes will not be backported to older versions.
