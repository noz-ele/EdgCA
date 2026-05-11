# EdgCA — Non-Goals

> [日本語](../jp/NON_GOALS.md) | English

EdgCA is a stateless issuance library that only "emits a cert based on the input it was given." The following are **intentionally not implemented**. When triaging a bug report or improvement suggestion, check this list first.

## 1. Validation

The **only** validation API EdgCA provides is `verifyClientCertificateIssuedBy` (an identity check against a single direct issuer: issuer DN match + AKI/SKI match + signature verify). Anything beyond that is intentionally not implemented:

- **Certificate chain validation.** `importCertificateAuthority` does not cryptographically verify whether `issuerChainPem` actually issued `certPem`. If the caller supplies a bogus chain, a bogus chain is what gets emitted. We do not adopt "if we can validate, we should validate."
- **Chain walking / PKI path building.** `verifyClientCertificateIssuedBy` is also limited to **a single direct issuer**. Verifying a leaf issued via an intermediate against the root is out of scope.
- **Extracting time fields from the cert itself.** `verifyClientCertificateIssuedBy`'s `validity` option provides a time check, but the values for `notBefore` / `notAfter` **are passed in by the caller** (the cert is not parsed for them). Converting `cf.tlsClientAuth.certNotBefore` / `certNotAfter` strings to `Date` is the application's responsibility. The library does not contain a parser for X.509 textual formats (`"Dec  4 23:59:59 2025 GMT"`, etc.) or for DER `UTCTime` / `GeneralizedTime`.
- **CRL / OCSP / revocation databases / revocation checks.**
- **DER sanity checks in `certificateToPem(der)`.** Even a shallow check of "first byte is `0x30` (SEQUENCE)" is not implemented. It cannot distinguish a real cert from junk and would only provide false reassurance. Doing it properly would require a full `parseCertificateDer`, which exceeds the responsibility of an encoder. This stays a low-level encoder.
- **RFC compliance checks for imported certs.** Passing a `certPem` that is expired, has a broken signature, has unexpected extensions, has multiple basicConstraints, etc., does not raise an error — issuance proceeds based on the input as given.

## 2. State management

- **Uniqueness management for `serialNumber`.** Specifying the same `serialNumber` twice for the same issuer does not stop the library. The RFC 5280 §4.1.2.2 uniqueness guarantee is the caller's responsibility. Issuance history is not retained either.
- **Issuance history / audit log / counters.** Stateless.
- **Key storage / encryption-at-rest / KV/D1/R2 integration.**
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

- **No server certificate issuance.** Leaf scope is mTLS client certs (`issueClientCert` / `issueClientCertForPublicKey`) and document-signing certs (`issueDocumentSigningCert`, RFC 9336 `id-kp-documentSigning`). TLS server certs are out of scope.
- **No SAN on document-signing leaves.** `issueDocumentSigningCert` does not accept `dnsNames` / `ipAddresses` / `emailAddresses`. Document-signing certs identify the signer through the Subject DN, not through SAN. If a downstream profile requires SAN, the caller adds it after extending the library; v1 does not.
- **No CSR-based document-signing variant in v1.** There is no `issueDocumentSigningCertForPublicKey`. Internal-keygen-only. The mTLS counterpart exists because client-managed key flows are common for mTLS; document-signing leaves are typically CA-issued with the key staying on the CA host or HSM, so the parity is not yet justified.
- **No CAdES / CMS / PAdES / XAdES / ASiC building or verification.** EdgCA only issues the document-signing certificate. Wrapping a document and signing it (CAdES detached, ASiC-E container, etc.) is a separate concern and lives outside this package.
- **No public certificate parsing API.** `parser.ts` is internal — `cf.tlsClientAuth.cert*` already exposes parsed values from Cloudflare, so duplicating that here adds nothing. CSR parsing **is** in scope (`parseCertificateSigningRequest`) because no Cloudflare-side equivalent exists; CSRs come from the client over the application layer.
- **No CA hierarchy beyond two levels.** At most `root → intermediate → client`. An intermediate cannot have an intermediate underneath it.
- **No RSA / Ed25519 / non-NIST curves.** ECDSA on NIST P-256 / P-384 / P-521 is supported (with their standard SHA-256 / SHA-384 / SHA-512 pairings). Other algorithms — including in CSRs — are rejected.
- **No issuance policy.** When parsing a CSR, the library extracts the requested subject/SAN and verifies POP, but does not decide whether the CSR should be honored. The caller chooses what subject/SAN values go into the issued cert.
- **No encrypted PKCS#8 PEM (encrypted private key).** PFX (PKCS#12) bundling the encrypted private key is a separate and supported format — see `exportPkcs12` — but standalone `BEGIN ENCRYPTED PRIVATE KEY` PEM is not.
- **No legacy PKCS#12 algorithms or non-modern consumers.** `exportPkcs12` emits PBES2 + PBKDF2-HMAC-SHA-256 + AES-256-CBC for both bags and HMAC-SHA-256 for the outer MAC, and targets Win11+ / Server 2019+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux PKCS#12 consumers. 3DES / RC2 / SHA-1 PBE algorithms, PBMAC1, crlBag, secretBag, nested safeContents, envelopedData, empty passwords, and Windows 10 (and older) are intentionally out of scope.
- **No acceptance of X.509 v1 / v2.** `importCertificateAuthority` accepts only v3 (`[0] EXPLICIT INTEGER 2`). A cert with a missing version field (v1) or `INTEGER 1` (v2) throws. EdgCA itself always emits v3. Importing externally produced legacy-version certs is not a supported use case.

## 5. Conditions for changing these policies

- The validation surface is reconsidered only if "identity verification that cannot be done on the Cloudflare side and can only be done on the application side" grows.
- "Same input → different / unexpected DER" along the single "external input → output cert" path is a **bug** and is in scope for fixing.
- "If the caller passes lying or duplicate input, the result is wrong" and "if the caller does not share state, things break" are **by design** and are not in scope for fixing.
