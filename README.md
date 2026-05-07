# EdgCA

> [日本語](https://github.com/noz-ele/EdgCA/blob/main/docs/jp/README.md) | English

EdgCA is a small TypeScript library that issues mTLS client certificates from a self-managed CA on Cloudflare Workers-compatible runtimes.

The scope is intentionally narrow:

- Create a self-signed root CA.
- Issue an intermediate CA from a root CA.
- Issue an mTLS client certificate and private key from an intermediate CA.
- Decide whether a received client certificate was issued by your own CA.
- Encode/decode certificates as PEM/DER. Keys are exchanged as `CryptoKey` only — the library never returns or accepts string forms (PEM, JWK, etc.) of private keys.
- Delegate all cryptographic operations to `globalThis.crypto.subtle`.

> ⚠ **Not a PKI runtime.** EdgCA is an issuance toolkit, not a general-purpose PKI library or runtime. It does **not** provide chain validation, revocation (CRL/OCSP), key storage, or rotation. `verifyClientCertificateIssuedBy` is **not** mTLS verification and does **not** authenticate the presenter — see [Verify](#verify-cloudflare-worker) below. Operating a CA safely is the caller's responsibility. Full list: [docs/en/NON_GOALS.md](https://github.com/noz-ele/EdgCA/blob/main/docs/en/NON_GOALS.md).

## Status

EdgCA is in **v0.1.x — early stabilization**. The author is currently validating the library against real Cloudflare Workers deployments, and the API surface may still shift. To keep that validation focused, **external Issues and PRs are temporarily restricted** and will be re-opened once the API settles. Reading, cloning, forking, and `npm install` are unaffected.

## Install

```sh
npm install @noz-ele/edgca
```

ESM-only (`"type": "module"`). Runs on any runtime where `globalThis.crypto.subtle` is available (Cloudflare Workers, Node.js 20+, modern browsers, etc.). CommonJS `require` is not supported.

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

## Verify (Cloudflare Worker)

> ⚠ **What this is — and is not**
>
> `verifyClientCertificateIssuedBy` is **not** mTLS verification. (Real mTLS verification does not exist for a self-managed CA on Cloudflare Workers in the first place.) At most it is *issuance verification*: it confirms that the presented certificate was issued by the specified CA. **That is not the same as authenticating that the presenter is the certificate's legitimate owner.**
>
> A client certificate is, by design, presentable to anyone, and its contents are trivially copyable. You must assume that anyone can be holding a valid copy. Therefore possession of valid certificate data **never** proves legitimate ownership.
>
> Proving legitimate ownership additionally requires verifying possession of the corresponding private key — i.e., a signature made by the private key, verified against the certificate's public key. The TLS handshake's `CertificateVerify` message normally does this, but **the Cloudflare Workers runtime does not expose that signature to the application.** On non-Enterprise plans, Cloudflare's TLS layer also does not know about your self-managed CA, so `request.cf.tlsClientAuth.certVerified` will not be `"SUCCESS"` for certificates EdgCA issued. Workers application code (Enterprise plans excluded) has no way to verify proof-of-possession.
>
> Implication: an attacker who has obtained a copy of a valid certificate (logs, leaked storage, network capture, etc.) can present it and pass this check. Use this function as a *minimum* identity-check layer, not as authentication. For real authentication, either (a) use Cloudflare Enterprise with mTLS configured at the TLS layer (Cloudflare validates the handshake signature against your CA), or (b) add an application-layer challenge-response that has the client sign a server-issued nonce with its private key.
>
> Also out of scope (not checked by this function): `BasicConstraints CA=false`, `EKU clientAuth`, revocation, and chain walking.

This section assumes a deployment where **Cloudflare has already extracted the client certificate** and exposes it to your application via `request.cf.tlsClientAuth`. EdgCA participates in neither the TLS handshake nor DER parsing of the cert; it consumes the values Cloudflare hands you and performs the issuance check above.

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

- ECDSA P-256 + SHA-256.
- Key generation, signing, digest, and key import/export via WebCrypto.
- Root CA creation.
- Intermediate CA issuance.
- mTLS client certificate issuance.
- Identity check that a cert was issued by your own CA (`verifyClientCertificateIssuedBy`, with optional time-validity check).
- PEM/DER helpers.
- Basic Constraints, Key Usage, Extended Key Usage, Subject Alternative Name, SKI, AKI.

Intentionally out of scope:

- Server certificate issuance.
- Public chain-validation APIs.
- Extracting time fields from a cert. `verifyClientCertificateIssuedBy`'s `validity` option performs the time check, but the `notBefore` / `notAfter` values are passed in by the caller from `cf.tlsClientAuth`.
- CRL, OCSP, revocation databases, revocation checks.
- Key storage, encryption-at-rest, rotation-state persistence, and integration with KV/D1/R2/Secrets.
- RSA, EdDSA, other elliptic curves.
- DN string parsing.
- Multi-valued RDNs.

## Key Handling

EdgCA exchanges keys as `CryptoKey` only. The library never returns or accepts string forms (PEM, JWK, base64, ...) of private keys, so secret material does not live on the JS string heap at the library boundary. Internally generated keys are extractable so the caller can persist them by calling `crypto.subtle.exportKey` directly, but the choice of persistence format is the caller's.

EdgCA only handles key generation, signing, and SPKI export of public keys. Where keys are stored, how they are encrypted at rest, how rotation state is persisted, and how they integrate with Cloudflare storage products are all the application's responsibility.

### Bringing your own CA key (recommended)

Root and intermediate CAs are long-lived. To keep key management on the caller's side, `createRootCA` and `issueIntermediateCA` accept an existing `keyPair: CryptoKeyPair`. This lets the caller's key-management infrastructure handle the full key lifecycle (generation, storage, rotation) consistently — including the choice of persistence format — which is the recommended path.

```ts
// Restore a CryptoKeyPair from whatever persistence format you use.
// Below is one example that converts PKCS#8 PEM stored in a vault.
async function loadKeyPair(label: string): Promise<CryptoKeyPair> {
  const pkcs8 = pemToDer(loadFromVault(`${label}-private-pem`));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    /* extractable */ false,
    ["sign"]
  );
  // Derive the matching public key. If you also persist the public key as
  // SPKI, import that directly instead of round-tripping through JWK.
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  delete jwk.d;
  jwk.key_ops = ["verify"];
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
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

Tests use `@cloudflare/vitest-pool-workers` to verify WebCrypto behavior on the Workers-compatible runtime.

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
