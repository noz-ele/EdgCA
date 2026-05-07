# EdgCA API

> [日本語](../jp/API.md) | English

This document describes the public API exported by `@noz-ele/edgca`.

```ts
import {
  createRootCA,
  issueIntermediateCA,
  issueClientCert,
  importCertificateAuthority,
  verifyClientCertificateIssuedBy,
  certificateToPem,
  pemToDer
} from "@noz-ele/edgca";
```

## Types

### `Subject`

```ts
type Subject = Array<{
  type: SubjectAttributeType;
  value: string;
}>;
```

`SubjectAttributeType` accepts the following short names:

```ts
type ShortSubjectAttributeType =
  | "CN"
  | "O"
  | "OU"
  | "C"
  | "ST"
  | "L"
  | "E"
  | "DC"
  | "SERIALNUMBER"
  | "STREET"
  | "POSTALCODE"
  | "TITLE"
  | "GIVENNAME"
  | "SURNAME"
  | "UID";
```

Dotted OID strings such as `"1.2.3.4.5"` are also accepted.

Each subject entry is encoded as a single-valued RDN. Input order is preserved. The ASN.1 string type for a value is determined by the attribute OID: `C` (`2.5.4.6`) uses PrintableString, emailAddress (`1.2.840.113549.1.9.1`) uses IA5String, and everything else uses UTF8String. A dotted OID equivalent to a short name (`CN`, `O`, ...) selects the same string type.

DN string input and multi-valued RDNs are not supported.

### `CertificateAuthority`

```ts
interface CertificateAuthority {
  certPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  issuerChainPem: string;
}
```

`issuerChainPem` is the PEM chain of CAs above this one. It is an empty string for a root CA. For an intermediate issued from a root, it contains the root certificate PEM.

The deepest CA hierarchy EdgCA targets is `root CA -> intermediate CA -> client certificate`. Issuing further intermediate CAs from an intermediate is out of scope.

Private keys are returned as `CryptoKey` only. The library does not produce string forms (PEM, etc.) of private keys. If you need to persist the key, call `crypto.subtle.exportKey("pkcs8", privateKey)` (or another export form) yourself; the key must be extractable for that to work.

### `IssuedClientCertificate`

```ts
interface IssuedClientCertificate {
  certPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  certChainPem: string;
}
```

`certChainPem` is concatenated as `leaf + issuer + issuerChain`. For a client certificate issued by an intermediate that was issued from a root, the result is `client + intermediate + root`.

### `SerialNumber`

```ts
type SerialNumber = bigint | number | string | Uint8Array;
```

When omitted, a positive random 16-byte serial number is generated.

If you need a deterministic serial number, prefer `bigint`, `number`, or `Uint8Array`. A `string` is interpreted as either decimal digits or hexadecimal text.

## Functions

### `createRootCA(options)`

Creates a self-signed root CA.

```ts
function createRootCA(options: {
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  pathLenConstraint?: number;
  keyPair?: CryptoKeyPair;
}): Promise<CertificateAuthority>;
```

The issued certificate includes:

- `basicConstraints CA=true`, critical.
- `keyUsage keyCertSign,cRLSign`, critical.
- Subject Key Identifier.
- Authority Key Identifier.

The root certificate is self-signed. The returned `issuerChainPem` is `""`.

`pathLenConstraint` defaults to `1`. The only allowed values are `0` and `1`. A root with `pathLenConstraint=0` can only issue client certificates; it cannot issue intermediate CAs.

When `keyPair` is provided, the root CA is issued with that key pair. The recommended path is to load a key from long-term storage, turn it into a `CryptoKey` via WebCrypto's `importKey`, and pass it here. When omitted, the library generates a P-256 ECDSA key pair internally (test / PoC use). `privateKey.usages` must include `"sign"` and `publicKey.usages` must include `"verify"`.

### `issueIntermediateCA(options)`

Issues an intermediate CA from a root CA. An intermediate CA cannot issue further intermediate CAs.

```ts
function issueIntermediateCA(options: {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  pathLenConstraint?: number;
  keyPair?: CryptoKeyPair;
}): Promise<CertificateAuthority>;
```

The issued certificate includes:

- `basicConstraints CA=true`, critical.
- `keyUsage keyCertSign,cRLSign`, critical.
- Subject Key Identifier.
- Authority Key Identifier.

The `pathLenConstraint` of the issued intermediate CA is always `0`. Either omit `pathLenConstraint` or pass `0`. Specifying `1` or higher throws.

If the issuer root CA has `pathLenConstraint=0`, this function throws. This prevents creating an intermediate CA under a root that is meant to issue only leaf certificates.

The returned CA's `issuerChainPem` carries the parent chain.

When `keyPair` is provided, the intermediate CA is issued with that key pair. As with `createRootCA`, the recommended path is to import a stored key into a `CryptoKey` and pass it here. When omitted, the library generates a P-256 ECDSA key pair internally.

### `issueClientCert(options)`

Issues an mTLS client certificate and private key from a CA.

```ts
function issueClientCert(options: {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  dnsNames?: string[];
  ipAddresses?: string[];
}): Promise<IssuedClientCertificate>;
```

The issued certificate includes:

- `basicConstraints CA=false`, critical.
- `keyUsage digitalSignature`, critical.
- Extended Key Usage `clientAuth`.
- Subject Key Identifier.
- Authority Key Identifier.
- Subject Alternative Name only when `dnsNames` or `ipAddresses` is specified.

SAN is optional for client certificates.

### `importCertificateAuthority(options)`

Imports a CA certificate and private key and returns a `CertificateAuthority` usable for subsequent issuance.

```ts
function importCertificateAuthority(options: {
  certPem: string;
  privateKey: CryptoKey;
  issuerChainPem?: string;
}): Promise<CertificateAuthority>;
```

`privateKey` must correspond to the public key of the certificate (verified via a sign/verify round trip). An incorrect `certPem` (expired, broken signature, unexpected extensions, etc.) does not raise an error — by design, certificates are issued exactly as the input dictates. The return value has the same `CertificateAuthority` shape as `createRootCA()` and `issueIntermediateCA()`.

When re-importing an intermediate CA, pass the parent chain via `issuerChainPem`. This chain is used to build `certChainPem` when issuing a client certificate.

The caller is responsible for turning persisted key material into a `CryptoKey` — for example, `crypto.subtle.importKey("pkcs8", …, { name: "ECDSA", namedCurve: "P-256" }, extractable, ["sign"])` for PKCS#8 PEM. The library does not perform format conversion.

### `verifyClientCertificateIssuedBy(options)`

Decides whether `options.ca` was the issuer of `options.certPem`. This is a post-handshake issuance check intended to be used in a Cloudflare Worker after decoding the PEM from `request.cf.tlsClientAuth.certRFC9440`, to confirm that the client certificate came from your own self-managed CA.

> ⚠ **This is not mTLS verification, and it does not authenticate the presenter.** It only confirms the certificate was issued by the specified CA. A client certificate is by design presentable to anyone, and its contents are trivially copyable; possession of valid certificate data does **not** prove legitimate ownership. Proof-of-possession requires verifying a signature made by the corresponding private key, which the Cloudflare Workers runtime does not expose. On non-Enterprise plans, `request.cf.tlsClientAuth.certVerified` will not be `"SUCCESS"` for self-managed CAs either. An attacker holding a copied certificate will pass this check. For real authentication, use Cloudflare Enterprise mTLS or layer an application-level challenge-response (nonce signed with the client's private key). See [README.md → Verify](../../README.md#verify-cloudflare-worker) for the full discussion.

```ts
function verifyClientCertificateIssuedBy(options: {
  ca: CertificateAuthority;
  certPem: string;
  validity?: {
    notBefore: Date | number;
    notAfter: Date | number;
    now?: Date | number;
  };
}): Promise<boolean>;
```

Returns `true` if all of the following hold; `false` otherwise:

- (when `validity` is provided) `validity.notBefore ≤ now ≤ validity.notAfter`.
- The issuer DN of `certPem` exactly matches the subject DN of `ca`.
- The Authority Key Identifier of `certPem` exactly matches the Subject Key Identifier of `ca`. If `certPem` has no AKI, returns `false`.
- The signature of `certPem` verifies under `ca.publicKey` (ECDSA P-256 / SHA-256).

Inputs that fail to parse as PEM or DER throw an `Error`. The two error categories are deliberately separated: "not issued by us" returns `false`; malformed input throws.

#### `validity` option

An optional time-validity check. Evaluated only when provided. The values are converted by the caller from `cf.tlsClientAuth.certNotBefore` / `certNotAfter` to `Date` or epoch milliseconds (the library does not read the cert's own `notBefore` / `notAfter` fields).

| field | type | required | default | meaning and constraints |
| --- | --- | --- | --- | --- |
| `notBefore` | `Date \| number` | ✅ | — | Invalid before this time. `Date` or epoch ms. `NaN` / non-finite throws. |
| `notAfter` | `Date \| number` | ✅ | — | Invalid after this time. Same constraints as above. `notBefore > notAfter` throws. |
| `now` | `Date \| number` | — | `Date.now()` | The "current" time used in the comparison. Can be set explicitly for tests or past-time verification. |

If `now` is outside the window, the function returns `false` immediately without running the identity check (skipping cert parse and signature verify to avoid expensive crypto). When `validity` is omitted, no time check is performed.

#### Usage (Cloudflare Worker)

```ts
import { verifyClientCertificateIssuedBy } from "@noz-ele/edgca";

const tls = request.cf!.tlsClientAuth!;

// Reshape the RFC 9440 Structured Field (":<base64>:") into PEM.
const b64 = tls.certRFC9440.replace(/^:|:$/g, "");
const certPem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;

const ok = await verifyClientCertificateIssuedBy({
  ca,                                          // a previously imported CertificateAuthority
  certPem,
  validity: {
    notBefore: new Date(tls.certNotBefore),    // string -> Date conversion is the caller's job
    notAfter:  new Date(tls.certNotAfter)
  }
});
```

To check identity only without inspecting time, omit `validity`:

```ts
const ok = await verifyClientCertificateIssuedBy({ ca, certPem });
```

If you would rather inline the time check as two comparisons in the application instead of having the library do it, the result is equivalent:

```ts
const now = Date.now();
const inWindow =
  Date.parse(tls.certNotBefore) <= now && now <= Date.parse(tls.certNotAfter);
const ok = inWindow && await verifyClientCertificateIssuedBy({ ca, certPem });
```


This function performs **only an identity check against a single direct issuer + (optionally) a time-validity check**. The following are out of scope:

- Chain walking (e.g., verifying a leaf issued via an intermediate against the root). Pass the **direct issuer** (the root if issued directly from the root, the intermediate if issued via an intermediate) as `ca`.
- Revocation checks (CRL / OCSP).
- Auto-extraction from the `cf.tlsClientAuth` shape. Decoding the RFC 9440 form (`:base64:`) and parsing the `certNotBefore` / `certNotAfter` strings into `Date` are the caller's job.

If you operate multiple CAs and want to know which one issued a cert, iterate over your CA array on the caller's side.

### `certificateToPem(der)`

Encodes DER certificate bytes into a PEM certificate block.

```ts
function certificateToPem(der: Uint8Array): string;
```

### `pemToDer(pem)`

Decodes the first PEM block in the given string into DER bytes.

```ts
function pemToDer(pem: string): Uint8Array;
```

## Errors

EdgCA throws `Error` for invalid input or operations outside its scope.

Examples:

- `subject` is empty or not an array.
- Unsupported subject attribute type.
- Malformed dotted OID.
- The value of `C` is not valid PrintableString.
- Invalid SAN IP address.
- `days` is not a positive number.
- The imported private key does not correspond to the CA certificate's public key.
- The issuer certificate is not a CA.
- The issuer certificate lacks `keyCertSign`.
- Attempting to issue an intermediate CA from anything other than a root CA.
- Attempting to issue an intermediate CA from a root with `pathLenConstraint=0`.
- A `pathLenConstraint` exceeding the maximum two-level CA hierarchy.

`verifyClientCertificateIssuedBy` returns a `boolean` for the issuer-identity check. No result type is provided for other validations (time, chain, revocation).

## Field Reference

This section walks through each field of the interfaces exported from `types.ts` in tabular form. When scaffolding code, defaults and constraints aren't always readable from the type signature alone in an IDE, so this reference summarizes them.

Legend:

- The "Required" column: `✅` means the field has no `?`; `—` means the field is optional.
- The "Default" column: the value applied internally when the field is omitted. `—` means "the field itself is not encoded if unspecified".
- Constraints are conditions checked at call time. Violations throw `Error`.

### Options

#### `CreateRootCAOptions`

The argument to `createRootCA`. Represents the input set for creating a single self-signed root CA. At minimum it requires the subject DN and the validity period; whether to allow intermediates underneath (`pathLenConstraint`) and bringing in an existing key pair (`keyPair`) are optional. Both fresh issuance and reproducible issuance (with a brought-in key) are handled by a single interface.

| field | type | required | default | meaning and constraints |
| --- | --- | --- | --- | --- |
| `subject` | `Subject` | ✅ | — | The subject DN of the root CA. Order is preserved. Because the cert is self-signed, the issuer DN holds the same value. See § `Subject` for details. Empty arrays are not allowed. |
| `days` | `number` | ✅ | — | Validity in days from `notBefore`. Positive finite numbers only. One day is a flat `86_400_000ms` addition (no leap seconds). No upper-bound check. |
| `notBefore` | `Date` | — | call time (`new Date()`) | The validity start time. Encoded as `UTCTime` for 1950–2049 and as `GeneralizedTime` outside that range. |
| `serialNumber` | `SerialNumber` | — | CSPRNG-derived 16-byte random (positive, MSB cleared, satisfies CAB BR 7.1's ≥64 bit entropy requirement) | Caller's **explicit** specification of the integer that identifies the issued cert within the issuer. Normally omit this and let the default random value handle it (this satisfies both the stateless nature of Workers and industry standards); only pass a value when you need a deterministic one — for audit, test reproducibility, or carrying a serial assigned by an external system. See § `SerialNumber` for input shapes. After DER encoding, exceeding 20 octets throws. |
| `pathLenConstraint` | `number` | — | `1` | The number of intermediate levels allowed under this root. Only `0` or `1` is allowed. A root with `0` cannot issue intermediates and is reserved for client certs only. |
| `keyPair` | `CryptoKeyPair` | — | generated internally (P-256 ECDSA, `extractable: true`) | A brought-in key pair. `privateKey.usages` must include `"sign"` and `publicKey.usages` must include `"verify"`. Extractability is the caller's choice; the library only uses `subtle.sign` and `subtle.exportKey("spki", publicKey)` (the private key does not need to be extractable). When omitted, a key pair is generated via WebCrypto. |

#### `IssueIntermediateCAOptions`

The argument to `issueIntermediateCA`. The input set for issuing a single intermediate CA from an existing root CA. Differs from `CreateRootCAOptions` in two ways: the parent root is passed via `ca`, and `pathLenConstraint` is effectively fixed at `0` because intermediates cannot have intermediates underneath them.

| field | type | required | default | meaning and constraints |
| --- | --- | --- | --- | --- |
| `ca` | `CertificateAuthority` | ✅ | — | The parent root CA. Passing an intermediate as the parent throws. Passing a root with `pathLenConstraint=0` also throws. Passing a cert with `isCA=false` or no `keyCertSign` throws. |
| `subject` | `Subject` | ✅ | — | The subject DN of the intermediate CA being issued. |
| `days` | `number` | ✅ | — | Same as `CreateRootCAOptions.days`. Additionally, the library does not stop you from specifying a value that exceeds the issuer's `notAfter` (the resulting cert will be rejected by verifiers). |
| `notBefore` | `Date` | — | call time | Same as `CreateRootCAOptions.notBefore`. |
| `serialNumber` | `SerialNumber` | — | CSPRNG-derived 16-byte random | Same as `CreateRootCAOptions.serialNumber`. |
| `pathLenConstraint` | `number` | — | `0` | The `pathLenConstraint` of the issued intermediate is always `0`. If specified explicitly, only `0` is allowed; `1` or higher throws. |
| `keyPair` | `CryptoKeyPair` | — | generated internally | Same as `CreateRootCAOptions.keyPair` (the intermediate CA's key pair). |

#### `IssueClientCertOptions`

The argument to `issueClientCert`. The input set for issuing a single mTLS client certificate. Specify the issuer via `ca` (either a root or an intermediate is fine). Client cert keys are assumed to be short-lived, so unlike the CA options, this does not accept `keyPair`. SAN is optional; when neither `dnsNames` nor `ipAddresses` is specified, the extension itself is omitted.

| field | type | required | default | meaning and constraints |
| --- | --- | --- | --- | --- |
| `ca` | `CertificateAuthority` | ✅ | — | The issuer. Either a root or an intermediate is fine. Passing a cert with `isCA=false` or no `keyCertSign` throws. |
| `subject` | `Subject` | ✅ | — | The subject DN of the client cert being issued. |
| `days` | `number` | ✅ | — | Same as `CreateRootCAOptions.days`. |
| `notBefore` | `Date` | — | call time | Same as `CreateRootCAOptions.notBefore`. |
| `serialNumber` | `SerialNumber` | — | CSPRNG-derived 16-byte random | Same as `CreateRootCAOptions.serialNumber`. |
| `dnsNames` | `string[]` | — | `undefined` | SAN dNSName entries. The SAN extension is emitted only when this is specified. RFC 1035 §2.3.1 preferred name syntax: each label starts and ends with `[A-Za-z0-9]` and may contain `-` internally; label length ≤63 chars; total length ≤253 chars; a leading `*.` wildcard is allowed. Violations throw. |
| `ipAddresses` | `string[]` | — | `undefined` | SAN iPAddress entries. IPv4 / IPv6 strings. Can be combined with `dnsNames`. When neither is specified, the SAN extension itself is omitted. |

`issueClientCert` **always** generates the client cert key internally, so there is no `keyPair` option. Client cert keys are assumed to be ephemeral.

#### `ImportCertificateAuthorityOptions`

The argument to `importCertificateAuthority`. The input for reconstructing a `CertificateAuthority` instance from persisted CA material (cert PEM + private `CryptoKey`, plus the parent chain when applicable). Used not for creating a new CA but for loading a stored CA at Worker startup so it can be used for subsequent issuance.

| field | type | required | default | meaning and constraints |
| --- | --- | --- | --- | --- |
| `certPem` | `string` | ✅ | — | The CA certificate PEM to import. The first `BEGIN CERTIFICATE` block is read. |
| `privateKey` | `CryptoKey` | ✅ | — | The private `CryptoKey` (ECDSA P-256, `["sign"]` usage) corresponding to `certPem`. The library performs a sign/verify round-trip against the public key to confirm the pair matches. Mismatches throw. Extractability is the caller's choice. Format conversion (PEM → CryptoKey, etc.) is the caller's job. |
| `issuerChainPem` | `string` | — | `""` (empty) | When the imported subject is an intermediate CA, the PEM of its parent chain. Used to build `certChainPem` when issuing a client cert. Multiple `CERTIFICATE` blocks are concatenated with newlines. An empty string is treated as a root. |

### Results

#### `CertificateAuthority`

A single instance type that bundles a CA into three pieces: "private key + own cert + parent chain". Returned by `createRootCA` / `issueIntermediateCA` / `importCertificateAuthority`, and can be passed directly as the `ca` argument to `issueIntermediateCA` / `issueClientCert`. Treat it as one handle that bundles all the state the issuance functions need. To persist a CA, save `certPem` and the exported private-key bytes (export with `subtle.exportKey` on the caller side) along with `issuerChainPem`; restore by re-importing the key into a `CryptoKey` and passing it back through `importCertificateAuthority`.

| field | type | meaning |
| --- | --- | --- |
| `certPem` | `string` | The PEM of the CA's own certificate (`CERTIFICATE` block). |
| `certDer` | `Uint8Array` | The DER bytes of the CA's own certificate. Equivalent to decoding `certPem`. |
| `privateKey` | `CryptoKey` | A WebCrypto `CryptoKey` instance for `["sign"]`. |
| `publicKey` | `CryptoKey` | A WebCrypto `CryptoKey` instance for `["verify"]`. |
| `issuerChainPem` | `string` | The PEM of the parent CA chain. `""` for a root CA. For an intermediate, the PEM of the root. When multiple CAs are included, they are separated by newlines. |

#### `IssuedClientCertificate`

The return value of `issueClientCert`. A type that returns the issued client cert as three pieces: "private key + cert + complete chain". Cannot be reused for further issuance because no CA usage is intended (re-importing it would yield a `CertificateAuthority`, but since `issueClientCert` outputs a leaf cert, it would not function as an issuer). The complete chain to present to a verifier is provided in `certChainPem`.

| field | type | meaning |
| --- | --- | --- |
| `certPem` | `string` | The PEM of the client certificate. |
| `certDer` | `Uint8Array` | The DER bytes of the client certificate. |
| `privateKey` | `CryptoKey` | A WebCrypto `CryptoKey` for `["sign"]`. |
| `publicKey` | `CryptoKey` | A WebCrypto `CryptoKey` for `["verify"]`. |
| `certChainPem` | `string` | leaf + issuer + issuerChain joined by newlines, forming the complete chain. When issued via an intermediate, the order is `client + intermediate + root`. |

### `SubjectAttribute`

A single entry that makes up a `Subject`. The Subject DN (Distinguished Name) of an X.509 cert is a structure of multiple attributes in order; one such attribute is represented as `{ type, value }`. EdgCA does not accept DN string input like `CN=foo,O=Example` — the structured array form is required by design. Multi-valued RDNs (multiple attributes within a single RDN) are also unsupported; one entry equals one RDN.

| field | type | required | meaning and constraints |
| --- | --- | --- | --- |
| `type` | `SubjectAttributeType` | ✅ | The attribute type. A short name (`CN`, `O`, `OU`, `C`, `ST`, `L`, `E`, `DC`, `SERIALNUMBER`, `STREET`, `POSTALCODE`, `TITLE`, `GIVENNAME`, `SURNAME`, `UID`) or a dotted OID string (`1.2.3.4.5`). Unsupported short names and malformed OIDs throw. |
| `value` | `string` | ✅ | The attribute value. The string type is selected by OID (`C` → PrintableString, emailAddress → IA5String, otherwise UTF8String). The same rule applies to dotted OIDs equivalent to a short name. A `C` value that is not valid PrintableString throws. An emailAddress value that is not valid IA5 (ASCII) also throws. |

### `SerialNumber` input shapes

`SerialNumber` is a union type alias (`bigint | number | string | Uint8Array`) used when the caller wants to specify the cert's serial number explicitly. The cases for explicit specification are limited; usually you should omit it and rely on the library's random 16-byte generation. Specify a value for audit requirements demanding determinism, tests requiring reproducibility, or when carrying a serial assigned by an external system. The interpretation per input type is:

| input type | interpretation | constraints |
| --- | --- | --- |
| omitted | 16-byte random, MSB cleared to make it positive | — |
| `bigint` | encoded as the integer directly | DER-encoded length ≤ 20 octets |
| `number` | encoded as the integer directly | same as above |
| `string` (`/^\d+$/`) | converted to `BigInt` as decimal | same as above |
| `string` (hex) | normalized to even length and read as bytes | same as above |
| `Uint8Array` | used as a byte sequence directly | ≥ 1 byte, ≤ 20 bytes |

## Non-Goals

EdgCA does not provide:

- Server certificate issuance.
- A public certificate parsing API.
- Certificate chain validation (chain walking / PKI path building). `verifyClientCertificateIssuedBy` is limited to identity confirmation against a single direct issuer.
- Extraction of time fields from a cert. `verifyClientCertificateIssuedBy`'s `validity` option provides a time check, but `notBefore` / `notAfter` are passed in by the caller (it is the application's job to convert `cf.tlsClientAuth.certNotBefore` / `certNotAfter` to `Date`).
- CRL, OCSP, revocation databases, revocation checks.
- Key storage, encryption-at-rest, or Cloudflare storage integration.
- Key format conversion (PEM ↔ CryptoKey, JWK ↔ CryptoKey, etc.). The choice and conversion of a persistence format are done by the caller, using the WebCrypto API directly.
