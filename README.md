# EdgCA

> [日本語](https://github.com/noz-ele/EdgCA/blob/main/docs/jp/README.md) | English

EdgCA is a small TypeScript library for issuing mTLS client certificates and document-signing certificates from a self-managed CA, and for bounded certificate validation against explicit trust anchors, on Cloudflare Workers-compatible runtimes.

## Features

- **WebCrypto-only, zero runtime dependencies.** All cryptographic operations go through `globalThis.crypto.subtle`. The same code runs on Cloudflare Workers, Node.js 20+, and modern browsers without polyfills or bundler shims.
- **Lightweight.** v0.8.0 — tarball **54.1 kB** · unpacked **209.8 kB** · 82 files. No transitive dependencies; the CLI uses only `node:util.parseArgs`. (Re-measured on every release.)
- **CA hierarchy (two-level).** Create a self-signed root CA and, optionally, issue an intermediate CA from it. Three or more levels of intermediates are intentionally out of scope.
- **PFX (PKCS#12) bundling.** Wrap a cert + private key (and optional chain) into a password-protected `.pfx` / `.p12` for OS keystore import (Win11+, macOS 15+, iOS/iPadOS 18+, modern Linux). Algorithm-agnostic — accepts arbitrary PKCS#8 DER bytes (ECDSA, RSA, Ed25519, …).
- **mTLS client certificate issuance.** Issue a leaf with internal key generation, or from a caller-managed key via the CSR path below.
- **PKCS#10 CSR support.** Build a CSR (with proof-of-possession), parse a received CSR (subject, requested SAN, public key, raw extensions/attributes), verify its POP signature, and issue a cert from a CSR's public key without ever handling the private key.
- **Document-signing certificates (RFC 9336).** Issue a leaf with EKU `id-kp-documentSigning`, usable as the signer cert for CAdES / CMS / ASiC tooling (containers themselves are built separately).
- **Issuance check.** Decide whether a received client certificate was issued by your own CA (issuer-identity match — not full mTLS verification).
- **Bounded chain validation.** Validate a caller-ordered `leaf → intermediate → trusted root` chain, including signatures, validity, CA constraints, and target purpose. Automatic PKI path building and revocation are intentionally out of scope.
- **Arbitrary-data signature verification with a certificate public key.** Extract the public key from a validated certificate and verify ECDSA signatures in DER or IEEE P1363 format. Challenge state and replay prevention remain application concerns.
- **Opt-in arbitrary-data signing.** `@noz-ele/edgca/sign` signs caller-supplied bytes with an ECDSA `CryptoKey` and returns DER or IEEE P1363. It is not re-exported from the root entry point.
- **PEM/DER encode/decode** for certificates and PKCS#10 CSRs.
- **Secret key hygiene at the API boundary.** Private keys flow through the public API only as `CryptoKey` (issuance path) or `Uint8Array` PKCS#8 bytes (`exportPkcs12`); never as `string`. JS strings are immutable and stay on the heap until GC, so they cannot be wiped — secret material must not be held in that form. PEM ↔ CryptoKey conversion is the caller's job (so the lifetime of any string representation stays under caller control).

### Supported algorithms

- **Issuance layer**: ECDSA on NIST P-256 / P-384 / P-521 (with the standard SHA-256 / SHA-384 / SHA-512 pairings). RSA, EdDSA, and other curves are intentionally out of scope at issuance.
- **Verification layer**: the same ECDSA NIST P-256 / P-384 / P-521 set. It is intentionally not a general algorithm verifier.
- **PFX bundling (`exportPkcs12`)**: algorithm-agnostic — accepts any PKCS#8 DER bytes verbatim.

> ⚠ **Not a general PKI runtime.** Chain validation is limited to a caller-ordered hierarchy no deeper than `root → intermediate → leaf`, with explicit trusted roots. EdgCA does not provide automatic path building, AIA fetching, OS trust-store access, revocation (CRL/OCSP), key storage, or rotation. Certificate validation also does not prove that the presenter holds the private key — see [Verify](#verify-cloudflare-worker) below. Full list: [docs/en/NON_GOALS.md](https://github.com/noz-ele/EdgCA/blob/main/docs/en/NON_GOALS.md).

## Contents

- [CLI](#cli) — `npx @noz-ele/edgca …` one-liners for the five most common tasks
- [Quick Start](#quick-start) — root → intermediate → client cert (incl. PFX bundling)
- [Issue a document-signing certificate](#issue-a-document-signing-certificate) — RFC 9336 `id-kp-documentSigning` leaf
- [Verify on Cloudflare Worker](#verify-cloudflare-worker) — confirm a cert was issued by your CA
- [Certificate chain verification](#certificate-chain-verification) — validate an explicit chain to a trusted root
- [Certificate signature verification](#certificate-signature-verification) — verify arbitrary data with a certificate public key
- [Arbitrary-data signing](#arbitrary-data-signing) — opt-in library and CLI signing
- [Issue from a CSR](#issue-from-a-csr) — accept a caller-managed key via PKCS#10 + POP
- [Subject](#subject) · [Scope](#scope) · [Key Handling](#key-handling) · [Development](#development) · [API Documentation](#api-documentation)

## Status

EdgCA is in **v0.8.x — early stabilization**. The author is currently validating the library against real Cloudflare Workers deployments, and the API surface may still shift. To keep that validation focused, **external Issues and PRs are temporarily restricted** and will be re-opened once the API settles. Reading, cloning, forking, and `npm install` are unaffected.

## Install

```sh
npm install @noz-ele/edgca
```

ESM-only (`"type": "module"`). Runs on any runtime where `globalThis.crypto.subtle` is available (Cloudflare Workers, Node.js 20+, modern browsers, etc.). CommonJS `require` is not supported.

### Package entry points

The root `@noz-ele/edgca` entry point remains an aggregate surface for compatibility. Use a purpose-specific subpath when you want an issuance-only bundle to avoid statically importing the verification implementation regardless of tree shaking:

```ts
import { createRootCA, issueClientCert } from "@noz-ele/edgca/issuer";
import {
  verifyCertificateChain,
  verifyCertificateSignature
} from "@noz-ele/edgca/verify";
import { exportPkcs12 } from "@noz-ele/edgca/pkcs12";
import { signData } from "@noz-ele/edgca/sign";
```

`./issuer` owns CA creation/import and intermediate/leaf issuance. `./verify` validates direct issuers and chains using public certificates only; it does not statically import the issuer module. `./sign` is opt-in and is not re-exported by the root, issuer, verify, or pkcs12 entry points, so consumers that do not import it do not add the public signing module to their application dependency graph. The package remains `sideEffects: false`.

## CLI

EdgCA ships a small zero-dependency CLI (`bin: edgca`) for the five most common one-shot tasks. It is a thin wrapper over the library API and uses `node:util.parseArgs` — no transitive dependencies are pulled in for non-CLI consumers.

> `npx` runs the CLI **without installing** it — it fetches the package into npm's local cache, executes the `bin`, and leaves your project's `node_modules` / `package.json` untouched. Use this for one-shot tasks (creating a local dev CA, building a PFX). For repeated use, install globally with `npm install -g @noz-ele/edgca` and then call `edgca …` directly.

All commands write outputs to the **current working directory**. Filenames are derived from `--name` (default: `root` / `intermediate` / `client`). Cert files are `<name>.crt.pem`, private keys are PKCS#8 PEM at `<name>.key.pem`, and full chains (when relevant) are `<name>.chain.pem`.

```sh
# 1. Create a root CA (default: P-256, 3650 days)
npx @noz-ele/edgca create-root-ca --subject "CN=My Test Root,O=Acme,C=JP"
# → ./root.crt.pem, ./root.key.pem

# 2. Issue an intermediate CA from that root
npx @noz-ele/edgca issue-intermediate-ca \
  --ca-cert root.crt.pem --ca-key root.key.pem \
  --subject "CN=My Intermediate,O=Acme"
# → ./intermediate.crt.pem, ./intermediate.key.pem, ./intermediate.chain.pem

# 3. Issue an mTLS client cert from the intermediate
npx @noz-ele/edgca issue-client \
  --ca-cert intermediate.crt.pem --ca-key intermediate.key.pem \
  --ca-chain intermediate.chain.pem \
  --subject "CN=alice" \
  --dns-name alice.example.test --ip 10.0.0.1 \
  --days 365
# → ./client.crt.pem, ./client.key.pem, ./client.chain.pem

# 4. Bundle a cert + key (+ optional chain) into a password-protected PFX
npx @noz-ele/edgca pem-to-pfx \
  --cert client.crt.pem --key client.key.pem --chain client.chain.pem \
  --password "hunter2"
# → ./client.pfx   (defaults to <cert-basename>.pfx next to --cert)
```

Flags summary (run `npx @noz-ele/edgca --help` to see this in your terminal):

```
edgca create-root-ca         --subject <dn>
                             [--days 3650] [--curve P-256|P-384|P-521]
                             [--name root]

edgca issue-intermediate-ca  --ca-cert <pem> --ca-key <pem>
                             --subject <dn>
                             [--days 1825] [--curve P-256|P-384|P-521]
                             [--name intermediate]

edgca issue-client           --ca-cert <pem> --ca-key <pem> [--ca-chain <pem>]
                             --subject <dn>
                             [--dns-name <name>]... [--ip <addr>]...
                             [--days 365] [--name client]

edgca pem-to-pfx             --cert <pem> --key <pem> --password <pw>
                             [--chain <pem>] [--out <pfx>]

edgca sign-data              --key <private-key.pem>
                             (--data-file <path> | --data-base64url <value>)
                             --signature-format <der|ieee-p1363>
```

`--subject` accepts an OpenSSL-style DN string (`"CN=foo,O=bar,C=JP"`); short names are case-insensitive (`CN`/`O`/`OU`/`C`/`ST`/`L`/`E`/`DC`/`SERIALNUMBER`/`STREET`/`POSTALCODE`/`TITLE`/`GIVENNAME`/`SURNAME`/`UID`), and dotted OID attributes (`1.2.840.113549.1.9.1=...`) are accepted as-is. Private keys are read/written as PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`); SEC1 (`EC PRIVATE KEY`) is not supported.

> ⚠ The CLI is a convenience wrapper for local testing and one-shot operational tasks. For programmatic use in a server, Worker, or browser, call the library API directly — that way private keys stay in `CryptoKey` form and never touch disk. See [Key Handling](#key-handling) for the rationale.

## Quick Start

```ts
import {
  createRootCA,
  issueIntermediateCA,
  issueClientCert
} from "@noz-ele/edgca";

const root = await createRootCA({
  subject: [{ type: "CN", value: "dev-root" }],
  days: 3650
});

const intermediate = await issueIntermediateCA({
  ca: root,
  subject: [{ type: "CN", value: "dev-intermediate" }],
  days: 365
});

const client = await issueClientCert({
  ca: intermediate,
  subject: [
    { type: "CN", value: "worker-client" },
    { type: "UID", value: "worker-001" }
  ],
  days: 30
});

// Persist these via your secrets manager / KV / vault.
// `client.privateKey` is a CryptoKey. To persist it, export with
// crypto.subtle.exportKey("pkcs8", client.privateKey) (or another form)
// and treat the resulting bytes as a secret — never log or transmit them.
//   client.certPem        — public certificate
//   client.certChainPem   — full chain to present during mTLS
//   client.privateKey     — secret CryptoKey, hand off only over a trusted channel
```

The basic shape is:

```text
root CA -> intermediate CA -> mTLS client certificate
```

This is the deepest CA hierarchy EdgCA targets. Issuing further intermediate CAs from an intermediate is out of scope.

`client.certChainPem` is concatenated in this order:

```text
client certificate
issuer certificate
issuer chain
```

For a client certificate issued by an EdgCA-built intermediate, the result is `client + intermediate + root`.

### Bundling an issued cert + key as a PFX (PKCS#12)

OS certificate stores (Windows, macOS, iOS) accept a single password-protected `.pfx` (also `.p12`) file containing the leaf cert, optional chain, and the encrypted private key. `exportPkcs12` builds that file from an `IssuedClientCertificate`:

```ts
import { exportPkcs12 } from "@noz-ele/edgca/pkcs12";

const pfxBytes = await exportPkcs12({
  certDer: client.certDer,
  chainDer: [intermediate.certDer, root.certDer],   // optional
  // exportPkcs12 takes raw PKCS#8 DER bytes (algorithm-agnostic), not a CryptoKey.
  // If you hold a CryptoKey, extract the bytes first:
  privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", client.privateKey)),
  password: new TextEncoder().encode(passwordString),
  friendlyName: new TextEncoder().encode("worker-client") // optional, BMPString
});
// pfxBytes is a Uint8Array — write it to disk, send it to a download trigger,
// or hand it to tls.createSecureContext({ pfx: Buffer.from(pfxBytes), passphrase: passwordString }).
```

The password is taken as a UTF-8 `Uint8Array` (not a `string`) so that callers can keep secret bytes off the immutable JS string heap. PBKDF2 iterations default to 600 000 and the MAC KDF iterations to 100 000 — these match OWASP and OpenSSL 3 defaults but are caller-overridable.

The implementation is environment-agnostic (WebCrypto only, no Node-specific APIs), so PFX assembly can run **server-side, in a Cloudflare Worker, or directly in a browser**. A common architecture is to keep the CA on a server while having the browser generate its keypair locally, send a CSR, receive the cert, and assemble the PFX client-side — keeping the private key and password off the wire.

The `@noz-ele/edgca/pkcs12` subpath is provided so consumers that only need PFX assembly can import it without pulling in the CA / CSR / verify modules.

## Issue a document-signing certificate

`issueDocumentSigningCert` issues a leaf intended for signing arbitrary documents (CAdES detached, CMS, ASiC-E containers, etc., which are produced by separate tooling — not by EdgCA). It is **not** an mTLS client certificate: the EKU is `id-kp-documentSigning` (RFC 9336), and `keyUsage` carries `digitalSignature, contentCommitment` instead of just `digitalSignature`. SAN is intentionally not accepted; the signer is identified by Subject DN.

```ts
import {
  createRootCA,
  issueIntermediateCA,
  issueDocumentSigningCert
} from "@noz-ele/edgca";

const root = await createRootCA({
  subject: [{ type: "CN", value: "dev-root" }],
  days: 3650
});

const intermediate = await issueIntermediateCA({
  ca: root,
  subject: [{ type: "CN", value: "dev-intermediate" }],
  days: 365
});

const signer = await issueDocumentSigningCert({
  ca: intermediate,
  subject: [
    { type: "CN", value: "Alice (Document Signer)" },
    { type: "O", value: "Example" }
  ],
  days: 365
});

// signer.certPem        — the signing certificate
// signer.certChainPem   — full chain to embed alongside the signature (signer + intermediate + root)
// signer.privateKey     — secret CryptoKey, used by the document-signing tool to produce the signature
```

The returned shape is `IssuedDocumentSigningCertificate` (structurally identical to `IssuedClientCertificate`; the distinct name flags the EKU profile). The same `exportPkcs12` flow used for mTLS leaves works here too if you need to bundle the signer cert + key into a PFX for tools that consume PKCS#12.

There is no `issueDocumentSigningCertForPublicKey` (CSR variant) in v1, and EdgCA does not produce CAdES / CMS / ASiC containers itself — see [docs/en/NON_GOALS.md](https://github.com/noz-ele/EdgCA/blob/main/docs/en/NON_GOALS.md) for the rationale.

## Verify (Cloudflare Worker)

> ⚠ **What this is — and is not**
>
> `verifyClientCertificateIssuedBy` is **not** mTLS verification. (Real mTLS verification does not exist for a self-managed CA on Cloudflare Workers in the first place.) At most it is *issuance verification*: it confirms that the presented certificate was issued by the specified CA. **That is not the same as authenticating that the presenter is the certificate's legitimate owner.**
>
> A client certificate is, by design, presentable to anyone, and its contents are trivially copyable. You must assume that anyone can be holding a valid copy. Therefore possession of valid certificate data **never** proves legitimate ownership.
>
> Proving legitimate ownership additionally requires verifying possession of the corresponding private key — i.e., a signature made by the private key, verified against the certificate's public key. The TLS handshake's `CertificateVerify` message normally does this, but **the Cloudflare Workers runtime does not expose that signature, so a Worker cannot revalidate the TLS-handshake proof-of-possession itself.** On non-Enterprise plans, Cloudflare's TLS layer also does not know about your self-managed CA, so `request.cf.tlsClientAuth.certVerified` will not be `"SUCCESS"` for certificates EdgCA issued. A separate application-layer challenge can nevertheless be signed by the client and checked with `verifyCertificateSignature`.
>
> Implication: an attacker who has obtained a copy of a valid certificate (logs, leaked storage, network capture, etc.) can present it and pass this check. Use this function as a *minimum* identity-check layer, not as authentication. For real authentication, either (a) use Cloudflare Enterprise with mTLS configured at the TLS layer (Cloudflare validates the handshake signature against your CA), or (b) add an application-layer challenge-response that has the client sign a server-issued nonce with its private key.
>
> Also out of scope (not checked by this function): `BasicConstraints CA=false`, `EKU clientAuth`, revocation, and chain walking.

This section assumes a deployment where **Cloudflare has already extracted the client certificate** and exposes it to your application via `request.cf.tlsClientAuth`. EdgCA does not participate in the TLS handshake; it parses the certificate fields needed for the issuance check above.

### Formats Cloudflare exposes after extraction

| field | format | example |
| --- | --- | --- |
| `certPresented` | whether a client cert was sent | `"1"` / `"0"` |
| `certVerified` | TLS-layer verification status string. **For self-managed CAs on non-Enterprise plans this will not be `"SUCCESS"`** — the TLS layer does not know about your CA. | `"SUCCESS"` / `"FAILED:..."` / `"NONE"` |
| `certRFC9440` | RFC 9440 Structured Field Item (Byte Sequence). Base64 wrapped in `:` | `":MIIB...:"` |
| `certNotBefore` / `certNotAfter` | OpenSSL-style textual format (always GMT). Single-digit day padded with two spaces | `"Dec 24 23:59:59 2025 GMT"` / `"Dec  4 23:59:59 2025 GMT"` |
| `certSubjectDN`, `certIssuerDN`, `certSerial`, etc. | strings | identity extraction |

`verifyClientCertificateIssuedBy` accepts PEM (`certPem: string`) and `Date` / epoch ms (`validity.notBefore` / `notAfter`). Those forms **do not match** what Cloudflare provides, so the application must convert:

- `certRFC9440` (`":...:"`) → strip the surrounding colons, wrap with PEM markers.
- `certNotBefore` / `certNotAfter` (textual) → `new Date(...)` (V8 / the Workers runtime parses this format).

These parsers live in the caller, not in the library, because (a) we do not want to track Cloudflare's output-format changes, (b) we do not want to rely on runtime-dependent `Date.parse` leniency, and (c) the caller already holds the values, so reimplementing them here would be redundant. See [docs/en/NON_GOALS.md](https://github.com/noz-ele/EdgCA/blob/main/docs/en/NON_GOALS.md) for the full rationale.

### Example

```ts
import { importCertificateAuthority, pemToDer, verifyClientCertificateIssuedBy } from "@noz-ele/edgca";

// At Worker startup: import the CA loaded from your vault once.
// The library accepts the private key as a CryptoKey only — convert from
// whatever persistence format you use (PKCS#8 PEM, JWK, raw bytes, ...).
const pkcs8Der = pemToDer(env.CA_PRIVATE_KEY_PEM);
const privateKey = await crypto.subtle.importKey(
  "pkcs8",
  pkcs8Der,
  { name: "ECDSA", namedCurve: "P-256" },
  /* extractable */ false,
  ["sign"]
);
const ca = await importCertificateAuthority({
  certPem: env.CA_CERT_PEM,
  privateKey
});

export default {
  async fetch(request: Request): Promise<Response> {
    const tls = request.cf?.tlsClientAuth;
    if (!tls || tls.certPresented !== "1") {
      return new Response("client certificate required", { status: 401 });
    }
    // Note: tls.certVerified !== "SUCCESS" is expected for self-managed CAs
    // on non-Enterprise plans. The application performs the issuance check below.

    // Convert Cloudflare's formats to the library's formats.
    //   certRFC9440 (":base64:")        -> PEM string
    //   certNotBefore / certNotAfter    -> Date
    const b64 = tls.certRFC9440.replace(/^:|:$/g, "");
    const certPem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;

    const ok = await verifyClientCertificateIssuedBy({
      ca,
      certPem,
      validity: {
        notBefore: new Date(tls.certNotBefore),
        notAfter:  new Date(tls.certNotAfter)
        // omit `now` to use Date.now()
      }
    });
    if (!ok) {
      return new Response("not issued by us, or expired", { status: 403 });
    }

    // Reminder: passing this check does NOT prove the presenter holds the
    // private key. For real authentication, layer a challenge-response
    // (nonce signed with the client's private key) on top.

    // Authorization logic: derive identity from cf.tlsClientAuth.certSubjectDN, etc.
    return new Response(`hello, ${tls.certSubjectDN}`);
  }
};
```

### Notes

- Omitting `validity` performs only the identity check (issuer DN + AKI/SKI + signature). If you instead inline the time check as two comparisons in the application, the result is equivalent.
- "Not issued by us" and "outside the validity window" return `false`; malformed PEM/DER throws. The two error categories are deliberately split.
- Pass the **direct issuer (one cert)** as `ca`. Verifying a leaf issued via an intermediate against the root will return `false` — chain walking is not performed.

## Certificate chain verification

The `@noz-ele/edgca/verify` surface validates a direct issuer or a bounded chain using public certificates only. No CA private key is required.

```ts
import { verifyCertificateChain } from "@noz-ele/edgca/verify";

const result = await verifyCertificateChain({
  certificatePem: clientPem,
  // Direct issuer first. EdgCA accepts zero or one intermediate.
  intermediateCertificatesPem: [intermediatePem],
  // No OS trust store is consulted; trust anchors are explicit.
  trustedRootCertificatesPem: [rootPem],
  purpose: "clientAuth"
});

if (!result.valid) {
  throw new Error(
    `certificate chain rejected at ${result.certificateIndex}: ${result.reason}`
  );
}
```

The verifier checks each child/issuer DN, AKI/SKI, and signature; DER validity times; issuer `BasicConstraints`, `keyCertSign`, and `pathLenConstraint`; the requested target purpose; duplicate and unsupported critical extensions; and inner/outer signature-algorithm consistency. The terminal issuer must be one of the explicitly supplied trusted-root certificates.

This is not an automatic PKI path builder. The caller supplies intermediates in order, and the supported maximum is `root → intermediate → leaf`. EdgCA does not fetch AIA URLs, consult an OS trust store, check CRL/OCSP, verify TLS proof-of-possession, or perform server hostname matching. A valid chain does not prove that the presenter holds the leaf private key.

The existing `verifyClientCertificateIssuedBy` remains unchanged for compatibility. New code should use `verifyCertificateIssuedBy` for one direct link or `verifyCertificateChain` to reach an explicit trusted root.

## Certificate signature verification

`verifyCertificateSignature` verifies an ECDSA signature over caller-supplied bytes using the public key embedded in a certificate. It does not validate the certificate chain, time, Key Usage, EKU, or revocation. Authentication code first validates the same leaf with `verifyCertificateChain({ purpose: "clientAuth" })`.

```ts
import {
  verifyCertificateChain,
  verifyCertificateSignature
} from "@noz-ele/edgca/verify";

const chain = await verifyCertificateChain({
  certificatePem: clientPem,
  intermediateCertificatesPem: [intermediatePem],
  trustedRootCertificatesPem: [rootPem],
  purpose: "clientAuth"
});
if (!chain.valid) throw new Error(`certificate chain rejected: ${chain.reason}`);

const signatureValid = await verifyCertificateSignature({
  certificatePem: clientPem,
  // The exact bytes signed by the client, not a precomputed digest.
  data: signatureBase,
  signature: signatureBytes,
  // RFC 9421 encodes ECDSA signatures as fixed-width r || s.
  signatureFormat: "ieee-p1363"
});
```

ECDSA signatures contain two integers `(r, s)`, with two supported byte encodings:

| `signatureFormat` | Encoding | Typical use |
| --- | --- | --- |
| `"der"` | ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`; total length varies. | X.509 and tooling configured for DER output |
| `"ieee-p1363"` | Fixed-width `r || s`: 64 bytes for P-256, 96 for P-384, 132 for P-521. | RFC 9421 and WebCrypto ECDSA signatures |

The format is mandatory and is never guessed. RFC 9421 registers P-256/SHA-256 and P-384/SHA-384 ECDSA algorithms. EdgCA also supports P-521/SHA-512 within its existing generic verification scope; that does not define a P-521 RFC 9421 algorithm.

A `true` result proves only that the supplied bytes verify under the certificate public key. The caller remains responsible for challenge generation, expiry and one-time consumption; binding the HTTP method, URI, authority, and body digest; RFC 9421 parsing/canonicalization; matching the certificate fingerprint across requests; and mapping the certificate to an identity and permissions. For that reason, this primitive is not named `verifyProofOfPossession`.

## Arbitrary-data signing

`signData` signs caller-supplied bytes with an ECDSA private `CryptoKey`. The implementation uses only `globalThis.crypto.subtle`, `CryptoKey`, and `Uint8Array`, and runs on Node.js, Cloudflare Workers, and modern browsers.

```ts
import { signData } from "@noz-ele/edgca/sign";

const signature = await signData({
  privateKey,
  data: signingInput,
  signatureFormat: "ieee-p1363"
});
```

P-256, P-384, and P-521 use SHA-256, SHA-384, and SHA-512 respectively. `signatureFormat` is mandatory and is never guessed. The library API accepts a `CryptoKey`, not PEM text or a key path; shell clients can use the Node.js CLI instead:

```sh
signature=$(npx @noz-ele/edgca sign-data \
  --key "$client_key" \
  --data-base64url "$signing_input" \
  --signature-format ieee-p1363)
```

`npx @noz-ele/edgca sign-data ...` and `edgca sign-data ...` execute the same CLI command. The former asks `npx` to fetch/cache the package and launch its `bin: edgca`; the latter directly launches the same bin from a local or global installation.

The CLI accepts exactly one of `--data-file` and `--data-base64url`, and writes one unpadded-base64url signature line to stdout. Neither API constructs or stores challenges, canonicalizes HTTP messages, prevents replay, or sends requests.

## Issue from a CSR

When a client manages its own private key and submits a PKCS#10 CSR, EdgCA parses the CSR, verifies its proof-of-possession signature, and issues a certificate that embeds the CSR's public key. The library does **not** auto-adopt the CSR's claimed subject / SAN — the caller passes those explicitly, derived from whatever policy applies in the application layer.

```ts
import {
  importCertificateAuthority,
  issueClientCertForPublicKey,
  parseCertificateSigningRequest,
  verifyCertificateSigningRequestSignature
} from "@noz-ele/edgca";

const csr = await parseCertificateSigningRequest(csrPemFromClient);
if (!await verifyCertificateSigningRequestSignature(csr)) {
  return new Response("CSR proof-of-possession failed", { status: 400 });
}

// Application decides what subject and SAN to issue with. The CSR's claimed
// values are available on csr.subject / csr.requestedDnsNames /
// csr.requestedIpAddresses, but treating them as authoritative is a policy
// decision that lives outside EdgCA.
const issued = await issueClientCertForPublicKey({
  ca,
  publicKey: csr.publicKey,
  subject: policyDerivedSubject,
  days: 30,
  dnsNames: policyDerivedDnsNames
});
// issued has certPem / certDer / certChainPem only — no privateKey, because
// the client owns it.
```

CSRs signed with anything other than `ecdsa-with-SHA256` / `ecdsa-with-SHA384` / `ecdsa-with-SHA512` are rejected at parse time with an explicit error. CSR-level attributes other than `extensionRequest` are surfaced as raw DER under `csr.otherAttributes` for callers that need them; X.509 extensions other than SAN are surfaced under `csr.requestedExtensions` as `{ oid, critical, valueDer }` for caller-side decoding.

POP verification proves only that whoever produced the CSR holds the matching private key. **It is not authorization.** Combine it with whatever transport-level (mTLS) and application-level checks make sense for your enrollment flow.

## Subject

Subject only accepts a structured input. DN strings such as `CN=dev-root,O=Example` are not accepted.

```ts
const subject = [
  { type: "CN", value: "dev-root" },
  { type: "O", value: "Example" },
  { type: "1.2.3.4.5", value: "custom-value" }
];
```

Supported short names:

```text
CN, O, OU, C, ST, L, E, DC, SERIALNUMBER, STREET,
POSTALCODE, TITLE, GIVENNAME, SURNAME, UID
```

Dotted OID strings are also accepted. The ASN.1 string type for values is fixed at UTF8String, with `C` as PrintableString. Multi-valued RDNs are out of scope.

## Scope

In scope:

- ECDSA on NIST P-256 / P-384 / P-521 (paired with SHA-256 / SHA-384 / SHA-512 respectively).
- Key generation, signing, digest, and key import/export via WebCrypto.
- Root CA creation.
- Intermediate CA issuance.
- mTLS client certificate issuance (with internal key generation, or from a caller-provided public key).
- Document-signing certificate issuance with EKU `id-kp-documentSigning` (RFC 9336) and `keyUsage digitalSignature, contentCommitment` — internal key generation only, no SAN.
- CSR (PKCS#10) parsing and proof-of-possession signature verification.
- Identity check that a cert was issued by your own CA (`verifyClientCertificateIssuedBy`, with optional time-validity check).
- Direct public-certificate issuer validation (`verifyCertificateIssuedBy`).
- Caller-ordered chain validation up to `root → intermediate → leaf` (`verifyCertificateChain`), including DER validity, CA/Key Usage/EKU/path-length constraints, and critical-extension policy.
- Arbitrary-data ECDSA signature verification with a certificate public key (`verifyCertificateSignature`), with an explicit DER or IEEE P1363 encoding.
- Arbitrary-data ECDSA signing with a caller-supplied `CryptoKey` (`signData`), with an explicit DER or IEEE P1363 encoding.
- Purpose-specific entry points (`@noz-ele/edgca/issuer`, `@noz-ele/edgca/verify`, and opt-in `@noz-ele/edgca/sign`).
- PEM/DER helpers (certificates only — keys are exchanged as `CryptoKey`).
- PFX (PKCS#12) export of an issued cert + private key with PBES2 (PBKDF2-HMAC-SHA-256 + AES-256-CBC) and HMAC-SHA-256 MAC, scoped to modern consumers (Win11+, Server 2019+, macOS 15+, iOS/iPadOS 18+).
- Basic Constraints, Key Usage, Extended Key Usage, Subject Alternative Name, SKI, AKI.

Intentionally out of scope:

- Server certificate issuance. Leaf scope is mTLS client certs and document-signing certs only.
- Document-signing certificate issuance from a caller-provided public key (`issueDocumentSigningCertForPublicKey`) — not in v1.
- SAN (`dnsNames` / `ipAddresses` / `emailAddresses`) on document-signing leaves.
- CAdES / CMS / PAdES / XAdES / ASiC document signing or container building. EdgCA only issues the signing certificate; producing a signed document or container is a separate concern.
- Automatic PKI path building from unordered certificates, issuer discovery, or AIA fetching.
- OS/runtime trust-store access; trusted roots must be supplied explicitly.
- Chains with two or more intermediate CAs.
- Parsing Cloudflare-specific textual times. The verification module reads DER certificate times; the legacy API still accepts caller-supplied validity values.
- CRL, OCSP, revocation databases, revocation checks.
- TLS `CertificateVerify` validation and proof-of-possession binding to the TLS connection.
- Application-layer proof-of-possession protocol state, including nonce/challenge management, HTTP message canonicalization, and replay prevention. EdgCA only signs caller-built bytes (`signData`) and verifies caller-built bytes (`verifyCertificateSignature`).
- Server hostname/SAN identity verification.
- Key storage, encryption-at-rest, rotation-state persistence, and integration with KV/D1/R2/Secrets.
- RSA, EdDSA, other elliptic curves (CSRs signed with these algorithms are rejected at parse time).
- Legacy PKCS#12 algorithms (3DES, RC2, SHA-1 PBE), PBMAC1, empty passwords, crlBag / secretBag / nested safeContents, and consumers older than the modern targets above are intentionally not produced or supported by `exportPkcs12`.
- A general certificate parsing API (Cloudflare hands you parsed values via `cf.tlsClientAuth.cert*`; the library does not duplicate that).
- Issuance policy decisions (whether to honor a CSR's claimed subject/SAN, deduplicate, etc.) — caller's responsibility.
- DN string parsing.
- Multi-valued RDNs.

## Key Handling

EdgCA exchanges keys as `CryptoKey` only. The library never returns or accepts string forms (PEM, JWK, base64, ...) of private keys, so secret material does not live on the JS string heap at the library boundary. Internally generated keys are extractable so the caller can persist them by calling `crypto.subtle.exportKey` directly, but the choice of persistence format is the caller's.

EdgCA only handles key generation, signing, and SPKI export of public keys. Where keys are stored, how they are encrypted at rest, how rotation state is persisted, and how they integrate with Cloudflare storage products are all the application's responsibility.

### Bringing your own CA key (recommended)

Root and intermediate CAs are long-lived. To keep key management on the caller's side, `createRootCA` and `issueIntermediateCA` accept an existing `keyPair: CryptoKeyPair`. This lets the caller's key-management infrastructure handle the full key lifecycle (generation, storage, rotation) consistently — including the choice of persistence format — which is the recommended path.

EdgCA verifies a supplied public/private pair with a sign/verify round trip before issuance. If the private key is imported with `extractable: false`, its public key cannot be reconstructed by exporting that private key; persist and import the public SPKI separately.

```ts
// Restore a CryptoKeyPair from whatever persistence format you use.
// Below is one example that imports separately stored PKCS#8 and SPKI PEM.
async function loadKeyPair(label: string): Promise<CryptoKeyPair> {
  const pkcs8 = pemToDer(loadFromVault(`${label}-private-pem`));
  const spki = pemToDer(loadFromVault(`${label}-public-pem`));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    /* extractable */ false,
    ["sign"]
  );
  const publicKey = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  return { privateKey, publicKey };
}

const root = await createRootCA({
  subject: [{ type: "CN", value: "dev-root" }],
  days: 3650,
  keyPair: await loadKeyPair("root")
});

const intermediate = await issueIntermediateCA({
  ca: root,
  subject: [{ type: "CN", value: "dev-intermediate" }],
  days: 365,
  keyPair: await loadKeyPair("intermediate")
});
```

Omitting `keyPair` causes the library to generate a key pair internally — convenient for tests and PoCs. Client-certificate keys are intended to be ephemeral, so `issueClientCert` always generates internally.

## Development

```sh
npm run typecheck
npm run build
npm run test
npm audit
```

The main suite (`vitest.config.ts`) runs on `@cloudflare/vitest-pool-workers` to verify WebCrypto behavior on the Workers-compatible runtime. A second suite (`vitest.node.config.ts`, file pattern `*.node.test.ts`) runs under Node so the produced PFX can be validated end-to-end against `node:tls`'s `createSecureContext`. `npm run test` runs both in sequence.

### Property-based tests

Round-trip invariants in the lower layers are expressed as `fast-check` property-based tests, kept one file per target module under `test/<module>.property.test.ts`.

- [test/der.property.test.ts](https://github.com/noz-ele/EdgCA/blob/main/test/der.property.test.ts) — TLV round-trip for INTEGER / OID / OCTET STRING / BIT STRING / SEQUENCE
- [test/bytes.property.test.ts](https://github.com/noz-ele/EdgCA/blob/main/test/bytes.property.test.ts) — `concatBytes`, `binaryToBytes`/`bytesToBinary`, `bytesEqual`, `cloneBytes`
- [test/ip.property.test.ts](https://github.com/noz-ele/EdgCA/blob/main/test/ip.property.test.ts) — IPv4 dotted-quad and IPv6 (full form / `::` compression) encoding
- [test/pem.property.test.ts](https://github.com/noz-ele/EdgCA/blob/main/test/pem.property.test.ts) — round-trip between `certificateToPem` and `pemToDer` / `pemToDerWithLabel` / `splitPemBlocks`

`vitest.config.ts` includes `test/**/*.test.ts`, so `npm run test` runs them all together. The certificate-assembly layer (`ca.ts` / `x509.ts`) is intentionally outside the PBT scope and stays example-based in [test/edgca.test.ts](https://github.com/noz-ele/EdgCA/blob/main/test/edgca.test.ts).

## API Documentation

See [docs/en/API.md](https://github.com/noz-ele/EdgCA/blob/main/docs/en/API.md) for the full API reference.

The initial implementation plan is preserved as history in [docs/jp/PLAN_HISTORY.md](https://github.com/noz-ele/EdgCA/blob/main/docs/jp/PLAN_HISTORY.md) (Japanese only — archival material, not maintained in English).
