# EdgCA — Non-Goals

> [日本語](../jp/NON_GOALS.md) | English

EdgCA is a stateless library for certificate issuance and bounded validation against explicitly supplied trust anchors. It is not a general PKI runtime. The following are **intentionally not implemented**. When triaging a bug report or improvement suggestion, check this list first.

## 1. Validation

Validation is isolated under `@noz-ele/edgca/verify`. The supported boundary is deliberately narrow:

- `verifyCertificateIssuedBy` checks one certificate/direct-issuer relationship: issuer/subject DN, AKI/SKI, signature, DER validity, and issuer CA constraints.
- `verifyCertificateChain` validates the caller-ordered chain from the leaf's direct issuer to an explicitly supplied trusted root.
- `verifyCertificateSignature` obtains the public key from a certificate and verifies a caller-supplied byte sequence against an ECDSA DER or IEEE P1363 signature. It does not decide whether the certificate is trusted or whether the bytes represent a valid challenge.
- Chain validation checks DER `UTCTime`/`GeneralizedTime`, Basic Constraints, Key Usage, Extended Key Usage, `pathLenConstraint`, known critical extensions, and signature-algorithm consistency.
- Well-formed certificates that fail trust policy return a failure value; unparseable PEM/DER and unsupported algorithms throw.

The following remain intentionally unimplemented:

- **PKI path building / automatic issuer discovery.** EdgCA does not search unordered certificate sets or fetch intermediates from AIA URLs. The caller supplies `leaf → intermediate → root` order.
- **OS/runtime trust-store access.** Trust anchors are explicit in `trustedRootCertificatesPem`; a matching subject DN alone does not establish trust.
- **Chains containing two or more intermediates.** The maximum remains `root → intermediate → leaf`.
- **CRL / OCSP / revocation databases / revocation checks**, including validation that requires network access.
- **TLS `CertificateVerify` validation.** EdgCA does not obtain a handshake signature or exporter from a Cloudflare-terminated TLS connection and does not provide cryptographic binding to that connection.
- **Application-layer proof-of-possession protocols.** EdgCA does not generate, expire, store, or atomically consume nonces/challenge IDs; bind an HTTP message; or parse/canonicalize RFC 9421 fields. `signData` signs caller-built bytes and `verifyCertificateSignature` verifies caller-built bytes; neither interprets the challenge protocol.
- **Server identity / hostname validation.** EdgCA does not compare SAN dNSName entries with a destination hostname.
- **Cloudflare-specific text parsers.** The application converts strings such as `cf.tlsClientAuth.certNotBefore`; the verification module parses only DER `UTCTime`/`GeneralizedTime`.
- **DER sanity checks in `certificateToPem(der)`.** Even a shallow check of "first byte is `0x30` (SEQUENCE)" is not implemented. It cannot distinguish a real cert from junk and would only provide false reassurance. Doing it properly would require a full `parseCertificateDer`, which exceeds the responsibility of an encoder. This stays a low-level encoder.
- **Automatic validation during issuer import.** `importCertificateAuthority` does not validate the signature, time, or constraints of `issuerChainPem`. A caller that needs this check explicitly invokes `verifyCertificateChain` before issuance. Strict parsing in the verification module does not change issuer-module import behavior.
- **A public certificate-parsing API.** The certificate parser remains an internal verification implementation, not a general X.509 inspection surface.

## 2. State management

- **Uniqueness management for `serialNumber`.** Specifying the same `serialNumber` twice for the same issuer does not stop the library. The RFC 5280 §4.1.2.2 uniqueness guarantee is the caller's responsibility. Issuance history is not retained either.
- **Issuance history / audit log / counters.** Stateless.
- **Key storage / encryption-at-rest / KV/D1/R2 integration.**
- **Challenge/nonce storage and replay prevention.** Durable Objects, KV, D1, or other compare-and-consume mechanisms belong to the application or protocol library.
- **Expiry monitoring / rotation.**

## 3. Input "considerateness"

Bad input should throw. Convenience features such as trim, dedup, and auto-completion are not provided. Silent normalization hides caller intent mistakes.

- **No SAN dnsNames / ipAddresses dedup.** When the same value appears more than once, throw (we do not "collapse to one because callers often duplicate").
- **No trimming of trailing-dot FQDNs.** `"example.com."` is invalid as a SAN dNSName, so throw (we do not "strip trailing `.` because callers often typo").
- **No case normalization.** dnsName values are not lowercased. They are encoded as the caller passed them.
- **No Unicode normalization (NFC/NFKC).** Subject attribute values are UTF-8 encoded as the given code points. `café` (composed) and `café` (decomposed) become different DNs.
- **No DN string parser (`"CN=foo,O=Bar"`).** Subject must always be passed as a structured `{type, value}[]`.
- **No multi-valued RDN.** One entry equals one RDN.

## 4. Functional scope

### Bounded signing surface

`@noz-ele/edgca/sign` provides stateless arbitrary-data signing with a caller-owned ECDSA `CryptoKey`.

- Only P-256/SHA-256, P-384/SHA-384, and P-521/SHA-512.
- The caller explicitly selects DER or IEEE P1363 encoding.
- The library accepts only `CryptoKey` and `Uint8Array`, not PEM text, key paths, or storage locations.
- The sign subpath is not re-exported from the root; issuer, verify, and pkcs12 do not statically import it.
- The Node.js CLI may read unencrypted PKCS#8 PEM for `edgca sign-data`, but its internal PEM importer is not a public library API. The CLI signs and base64url-encodes bytes; it does not send HTTP requests.

This primitive does not bring nonce management, request canonicalization, persistence, or replay prevention into scope.

- **No server certificate issuance.** Leaf scope is mTLS client certs (`issueClientCert` / `issueClientCertForPublicKey`) and document-signing certs (`issueDocumentSigningCert`, RFC 9336 `id-kp-documentSigning`). TLS server certs are out of scope.
- **No SAN on document-signing leaves.** `issueDocumentSigningCert` does not accept `dnsNames` / `ipAddresses` / `emailAddresses`. Document-signing certs identify the signer through the Subject DN, not through SAN. If a downstream profile requires SAN, the caller adds it after extending the library; v1 does not.
- **No CSR-based document-signing variant in v1.** There is no `issueDocumentSigningCertForPublicKey`. Internal-keygen-only. The mTLS counterpart exists because client-managed key flows are common for mTLS; document-signing leaves are typically CA-issued with the key staying on the CA host or HSM, so the parity is not yet justified.
- **No CAdES / CMS / PAdES / XAdES / ASiC building or verification.** EdgCA only issues the document-signing certificate. Wrapping a document and signing it (CAdES detached, ASiC-E container, etc.) is a separate concern and lives outside this package.
- **No public certificate parsing API.** `parser.ts` is internal to verification and issuance. CSR parsing **is** in scope (`parseCertificateSigningRequest`) because CSRs arrive from clients at the application layer and have no equivalent Cloudflare-side parser.
- **No CA hierarchy beyond two levels.** At most `root → intermediate → client`. An intermediate cannot have an intermediate underneath it.
- **No RSA / Ed25519 / non-NIST curves at the issuance or verification layers.** Issuance, CSR, and certificate-verification APIs require ECDSA on NIST P-256 / P-384 / P-521 with the standard SHA-256 / SHA-384 / SHA-512 pairings. **`exportPkcs12` is separate**: it is an algorithm-agnostic PKCS#12 packer that accepts any PKCS#8 DER bytes because wrapping does not inspect the inner key algorithm.
- **No issuance policy.** When parsing a CSR, the library extracts the requested subject/SAN and verifies POP, but does not decide whether the CSR should be honored. The caller chooses what subject/SAN values go into the issued cert.
- **No encrypted PKCS#8 PEM (encrypted private key).** PFX (PKCS#12) bundling the encrypted private key is a separate and supported format — see `exportPkcs12` — but standalone `BEGIN ENCRYPTED PRIVATE KEY` PEM is not.
- **No legacy PKCS#12 algorithms or non-modern consumers.** `exportPkcs12` emits PBES2 + PBKDF2-HMAC-SHA-256 + AES-256-CBC for both bags and HMAC-SHA-256 for the outer MAC, and targets Win11+ / Server 2019+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux PKCS#12 consumers. 3DES / RC2 / SHA-1 PBE algorithms, PBMAC1, crlBag, secretBag, nested safeContents, envelopedData, empty passwords, and Windows 10 (and older) are intentionally out of scope.
- **No acceptance of X.509 v1 / v2.** `importCertificateAuthority` accepts only v3 (`[0] EXPLICIT INTEGER 2`). A cert with a missing version field (v1) or `INTEGER 1` (v2) throws. EdgCA itself always emits v3. Importing externally produced legacy-version certs is not a supported use case.

## 5. Conditions for changing these policies

- Validation can be considered when it remains explicit, stateless, WebCrypto-only, and operates only on caller-supplied certificates and byte sequences within the bounded hierarchy.
- Signing can be considered when it remains stateless, WebCrypto-only, uses the existing ECDSA profiles, and operates only on a caller-owned `CryptoKey` and caller-supplied bytes.
- Requirements involving issuer discovery, external retrieval, persistent state, or revocation infrastructure belong in a dedicated PKI library/runtime.
- "Same input → different / unexpected DER" along the single "external input → output cert" path is a **bug** and is in scope for fixing.
- "If the caller passes lying or duplicate input, the result is wrong" and "if the caller does not share state, things break" are **by design** and are not in scope for fixing.
