# EdgCA API

> 日本語 | [English](../en/API.md)

この文書は `@noz-ele/edgca` から export される public API のドラフトです。

```ts
import {
  createRootCA,
  issueIntermediateCA,
  issueClientCert,
  issueClientCertForPublicKey,
  issueDocumentSigningCert,
  importCertificateAuthority,
  createCertificateSigningRequest,
  parseCertificateSigningRequest,
  verifyCertificateSigningRequestSignature,
  verifyCertificateIssuedBy,
  verifyCertificateChain,
  verifyCertificateSignature,
  verifyClientCertificateIssuedBy,
  certificateToPem,
  csrToPem,
  pemToDer,
  pemToDerWithLabel,
  splitPemBlocks,
  encodePem,
  generateKeyPair,
  arrayBufferFromBytes,
  exportPkcs12
} from "@noz-ele/edgca";
```

root entry point は後方互換の aggregate surface とし、全 API を再 export します。用途を限定して bundle したい場合は次の subpath を使います。

```ts
// CA 作成・証明書発行だけ。verify module を静的 import しない。
import {
  createRootCA,
  importCertificateAuthority,
  issueIntermediateCA,
  issueClientCert,
  issueClientCertForPublicKey,
  issueDocumentSigningCert
} from "@noz-ele/edgca/issuer";

// 公開証明書による検証だけ。issuer module と CA 秘密鍵は不要。
import {
  verifyCertificateIssuedBy,
  verifyCertificateChain,
  verifyCertificateSignature
} from "@noz-ele/edgca/verify";

// PFX 組み立てだけ。
import { exportPkcs12 } from "@noz-ele/edgca/pkcs12";
```

`package.json` は `sideEffects: false` を維持する。subpath は tree-shaking の有無に依存せず、発行だけを使う consumer が今後拡大する verify module を静的 import しないための境界です。`./verify` の public API は PEM / DER と公開鍵だけを扱い、`CertificateAuthority.privateKey` を要求しません。

ECDSA は **NIST P-256 / P-384 / P-521** をサポートします。内部生成のデフォルト curve は P-256 で、それ以外を使う場合は WebCrypto で `CryptoKeyPair` を生成し `keyPair` option で渡します。各 curve に対応する hash は標準ペアリング (P-256/SHA-256、P-384/SHA-384、P-521/SHA-512) です。CA hierarchy 内で curve を混在できます (例: P-256 root → P-384 intermediate → P-521 leaf)。各 cert の signatureAlgorithm は **issuer** の curve を反映します。

## Types

### `Subject`

```ts
type Subject = Array<{
  type: SubjectAttributeType;
  value: string;
}>;
```

`SubjectAttributeType` は次の短縮名を受け付けます。

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

`"1.2.3.4.5"` のような dotted OID 文字列も受け付けます。

各 subject entry は single-valued RDN として encode されます。入力順序は保持されます。値の ASN.1 string type は属性 OID で決まります。`C` (`2.5.4.6`) は PrintableString、emailAddress (`1.2.840.113549.1.9.1`) は IA5String、それ以外は UTF8String です。短縮名 (`CN`, `O`, ...) と等価な dotted OID 入力でも同じ string type が選ばれます。

DN 文字列入力と multi-valued RDN は対応しません。

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

`issuerChainPem` は、その CA より上位の PEM chain です。root CA では空文字列です。root から発行した intermediate CA では root certificate PEM が入ります。

EdgCA が扱う CA 階層は最大で `root CA -> intermediate CA -> client certificate` です。intermediate CA からさらに intermediate CA を発行する chain は対象外です。

秘密鍵は `CryptoKey` として返されます。library は秘密鍵の string 表現 (PEM 等) を返しません。永続化が必要な場合は呼び出し側で `crypto.subtle.exportKey("pkcs8", privateKey)` などを行ってください (`privateKey` が extractable である必要があります)。

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

`certChainPem` は `leaf + issuer + issuerChain` の順で出力されます。root から作成した intermediate で client certificate を発行した場合は、`client + intermediate + root` になります。

### `IssuedDocumentSigningCertificate`

```ts
interface IssuedDocumentSigningCertificate {
  certPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  certChainPem: string;
}
```

`issueDocumentSigningCert` の戻り値です。構造は `IssuedClientCertificate` と完全に同一ですが、interface 名を分けることで「この cert に埋め込まれている EKU は `id-kp-documentSigning` (RFC 9336) であって `clientAuth` ではない」という意味論を読者に明示します。`certChainPem` の連結順序は `leaf + issuer + issuerChain`。

### `SerialNumber`

```ts
type SerialNumber = bigint | number | string | Uint8Array;
```

省略時は、正のランダムな 16-byte serial number を生成します。

決定的な serial number が必要な場合は、`bigint`、`number`、または `Uint8Array` の利用を推奨します。`string` は decimal digits または hexadecimal text として扱われます。

### `CertificateVerificationPurpose`

```ts
type CertificateVerificationPurpose =
  | "ca"
  | "clientAuth"
  | "documentSigning";
```

`verifyCertificateChain` の target certificate に期待する profile。省略時は用途固有の leaf / CA profile を検査せず、chain、時刻、issuer CA 制約、署名、critical extension だけを検証します。

### `CertificateChainVerificationResult`

```ts
type CertificateVerificationFailureReason =
  | "not-yet-valid"
  | "expired"
  | "issuer-name-mismatch"
  | "key-identifier-mismatch"
  | "invalid-signature"
  | "issuer-not-ca"
  | "issuer-key-usage-invalid"
  | "path-length-exceeded"
  | "target-profile-invalid"
  | "invalid-chain-order"
  | "duplicate-extension"
  | "signature-algorithm-mismatch"
  | "unsupported-critical-extension"
  | "untrusted-root";

type CertificateChainVerificationResult =
  | {
      valid: true;
      trustedRootIndex: number;
    }
  | {
      valid: false;
      reason: CertificateVerificationFailureReason;
      certificateIndex: number;
    };
```

`certificateIndex` は `0` が target certificate、`1` がその直接 issuer で、chain 上の位置を表します。`untrusted-root` では次に必要だった terminal issuer の位置を示します。trust 条件を満たさない well-formed certificate は `valid: false`。PEM / DER として解析不能、未対応 signature algorithm、API option 不正は結果値ではなく例外です。

### `EcdsaSignatureFormat`

```ts
type EcdsaSignatureFormat = "der" | "ieee-p1363";
```

`verifyCertificateSignature` に渡す ECDSA signature の byte 表現です。

- `"der"`: ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`。各 INTEGER の符号保持 encode により全体長は可変。
- `"ieee-p1363"`: `r` と `s` を curve の component size にゼロ埋めし、`r || s` の順に連結した固定長表現。P-256 は 64 bytes、P-384 は 96 bytes、P-521 は 132 bytes。

形式の自動判定は行いません。caller は署名を生成した API / protocol に合わせて必ず明示します。RFC 9421 の `ecdsa-p256-sha256` と `ecdsa-p384-sha384` は `"ieee-p1363"` に対応します。

### `ExportPkcs12Input`

```ts
interface ExportPkcs12Input {
  certDer: Uint8Array;
  chainDer?: Uint8Array[];
  privateKey: Uint8Array;         // PKCS#8 DER bytes、algorithm 非依存
  password: Uint8Array;           // UTF-8 bytes、空 NG
  friendlyName?: Uint8Array;      // UTF-8 bytes、内部で BMPString に変換
  iterations?: number;            // PBKDF2、default 600_000
  macIterations?: number;         // PKCS#12 v1 KDF、default 100_000
}
```

`privateKey` は **PKCS#8 DER bytes (`Uint8Array`)** で受け取ります (`CryptoKey` ではありません)。PKCS#12 wrapping は内部 algorithm を見ない byte-level の操作 (PBES2 で暗号化して埋め込むだけ) なので、`exportPkcs12` は ECDSA / RSA / Ed25519 など任意の algorithm の PKCS#8 を受けます。発行 API (createRootCA 等) は引き続き ECDSA P-256/P-384/P-521 限定です ([NON_GOALS](NON_GOALS.md) 参照)。`CryptoKey` を持っている caller は `crypto.subtle.exportKey("pkcs8", key)` で bytes を取り出してから渡してください。

`password` は UTF-8 の `Uint8Array` で受け取ります (`string` 不可)。秘密の bytes を JS の immutable な string heap に置かない設計のためです。`friendlyName` を渡した場合は byte stream で UTF-8 → UTF-16BE 変換を行い (string を経由しません) BMPString として埋め込みます。password 由来の中間 buffer は使用後 `fill(0)` で wipe します。`privateKey` の buffer は library 側で書き換えません (caller 所有のため)。wipe したい場合は呼び出し後に caller が行ってください。

## Functions

### `createRootCA(options)`

自己署名 root CA を作成します。

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

発行される証明書には次を含めます。

- `basicConstraints CA=true`、critical。
- `keyUsage keyCertSign,cRLSign`、critical。
- Subject Key Identifier。
- Authority Key Identifier。

root certificate は self-signed です。返却値の `issuerChainPem` は `""` です。

`pathLenConstraint` 省略時は `1` です。指定できる値は `0` または `1` です。`0` の root CA は client certificate だけを発行でき、intermediate CA は発行できません。

`keyPair` を渡すと、その鍵ペアで root CA を発行します。鍵管理を呼び出し側に寄せるため、長期保管されている鍵を WebCrypto `importKey` で `CryptoKey` 化してから渡す利用形態が推奨です。省略時は内部で P-256 ECDSA 鍵を生成します (テスト・PoC 用途)。`privateKey` の usages に `"sign"`、`publicKey` の usages に `"verify"` が含まれている必要があります。両鍵は署名・検証 round-trip で対応を確認し、不一致なら発行前に throw します。

### `issueIntermediateCA(options)`

root CA から intermediate CA を発行します。intermediate CA からさらに intermediate CA を発行することはできません。

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

発行される証明書には次を含めます。

- `basicConstraints CA=true`、critical。
- `keyUsage keyCertSign,cRLSign`、critical。
- Subject Key Identifier。
- Authority Key Identifier。

発行される intermediate CA の `pathLenConstraint` は常に `0` です。`pathLenConstraint` option は省略するか `0` を指定してください。`1` 以上を指定した場合、この関数は例外を投げます。

issuer root CA が `pathLenConstraint=0` の場合、この関数は例外を投げます。これは、leaf certificate だけを発行できる CA の下に intermediate CA を作らないためです。

返却される CA の `issuerChainPem` には parent chain が保存されます。

`keyPair` を渡すと、その鍵ペアで intermediate CA を発行します。`createRootCA` と同じく、保管済みの鍵を `CryptoKey` 化してから渡す形が推奨です。秘密鍵と公開鍵の対応を発行前に確認します。省略時は内部で P-256 ECDSA 鍵を生成します。

### `issueClientCert(options)`

mTLS 用 client certificate と秘密鍵を CA から発行します。

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

発行される証明書には次を含めます。

- `basicConstraints CA=false`、critical。
- `keyUsage digitalSignature`、critical。
- Extended Key Usage `clientAuth`。
- Subject Key Identifier。
- Authority Key Identifier。
- `dnsNames` または `ipAddresses` が指定された場合のみ Subject Alternative Name。

client certificate における SAN は任意です。

### `issueClientCertForPublicKey(options)`

呼び出し側が用意した公開鍵に対して mTLS client certificate を発行します。`issueClientCert` と違い library は鍵ペアを生成せず、cert と DER と chain だけを返します。client が自分で秘密鍵を管理し CSR で enrollment する flow で使います。

```ts
function issueClientCertForPublicKey(options: {
  ca: CertificateAuthority;
  publicKey: CryptoKey;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  dnsNames?: string[];
  ipAddresses?: string[];
}): Promise<{
  certPem: string;
  certDer: Uint8Array;
  certChainPem: string;
}>;
```

発行 cert の extension は `issueClientCert` と同じ (`basicConstraints CA=false`、`keyUsage digitalSignature`、EKU `clientAuth`、SKI、AKI、optional SAN)。埋め込まれる `subjectPublicKeyInfo` は `options.publicKey` を `subtle.exportKey("spki", …)` で export して入れるため、caller の公開鍵は extractable である必要があります。CA の署名 curve が signature algorithm を決め、leaf の埋め込み curve はそれと独立で良い。

この関数は leaf の秘密鍵を一切扱いません。client 側の秘密鍵管理 (POP 検証など、後述の `verifyCertificateSigningRequestSignature` を参照) は呼び出し側の責務です。

### `issueDocumentSigningCert(options)`

文書署名用 certificate と秘密鍵を CA から発行します。発行される leaf は **mTLS client certificate ではなく**、任意 document への署名 (CAdES、CMS detached、ASiC-E など。これらの container 生成は本 library の対象外で、別 tooling で行う) を意図した cert です。

```ts
function issueDocumentSigningCert(options: {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
}): Promise<IssuedDocumentSigningCertificate>;
```

発行される証明書には次を含めます。

- `basicConstraints CA=false`、critical。
- `keyUsage digitalSignature, contentCommitment`、critical。`contentCommitment` (旧 *non-repudiation*、RFC 5280 §4.2.1.3) は「この鍵で行った署名が署名者を content に紐付ける意図がある」という慣行的な bit。
- Extended Key Usage `id-kp-documentSigning` (OID `1.3.6.1.5.5.7.3.36`、RFC 9336)、non-critical。RFC 9336 §3 によりこの KeyPurposeId は「X.509 PKIX 構造以外の document に対する署名検証用途」を示し、`clientAuth` / `serverAuth` / `codeSigning` とは意図的に区別されます。
- Subject Key Identifier。
- Authority Key Identifier。

`issueClientCert` との主要な差分:

- **SAN なし**。`dnsNames` / `ipAddresses` / `emailAddresses` は受け取りません。文書署名 leaf における署名者 identity は Subject DN で表します。詳細は [`docs/jp/NON_GOALS.md`](NON_GOALS.md) §4。
- **CSR 経由の発行 variant なし** (v1)。`issueDocumentSigningCertForPublicKey` は提供しません。文書署名鍵は CA host または HSM 側で生成・保持される flow が一般的なため。理由は `NON_GOALS.md` §4。
- **CAdES / CMS / ASiC builder なし**。本 library は cert 発行のみ。document を包んで署名する処理は別 package の責務。

`ca` は root でも intermediate でも構いません。返却される `certChainPem` は `leaf + issuer + issuerChain` の順 (例: `signing-leaf + intermediate + root`)。leaf 鍵は常に内部で P-256 ECDSA (`extractable: true`、usage `["sign", "verify"]`) として生成されます。秘密鍵の永続化と取り扱いは呼び出し側の責任で、`issueClientCert` と同じ扱いです。

### `createCertificateSigningRequest(input)`

呼び出し側が用意した subject と ECDSA `CryptoKeyPair` から PKCS#10 CSR (RFC 2986) を組み立てます。署名は鍵ペアの private key の curve で行い (P-256/SHA-256、P-384/SHA-384、P-521/SHA-512)、CSR の DER と PEM の両方を返します。鍵ペアの生成・保持は library 側では行いません。秘密鍵は呼び出し側が用意して持ち続けます。

```ts
function createCertificateSigningRequest(
  input: CreateCertificateSigningRequestInput
): Promise<CreatedCertificateSigningRequest>;

interface CreateCertificateSigningRequestInput {
  subject: Subject;
  keyPair: CryptoKeyPair;
  dnsNames?: readonly string[];
  ipAddresses?: readonly string[];
  extensions?: readonly CertificateSigningRequestExtension[];
}

interface CertificateSigningRequestExtension {
  oid: string;
  critical: boolean;
  valueDer: Uint8Array;
}

interface CreatedCertificateSigningRequest {
  der: Uint8Array;
  pem: string;
}
```

挙動:

- **algorithm 範囲**: `keyPair.privateKey` と `keyPair.publicKey` は同一の supported curve 上の ECDSA である必要があります。RSA、Ed25519、curve が食い違う pair は API 境界で throw。
- **SAN**: `dnsNames` / `ipAddresses` のいずれかが非空なら `extensionRequest` 属性内に SAN extension を emit します。両方とも空配列の場合は SAN 属性自体を出力しません。dNSName / iPAddress の検証は発行系の SAN encoder と同じで、重複 dNSName / 不正なホスト名 / 不正な IP literal は throw します。
- **caller-supplied extensions**: `extensions` の各 entry は `extensionRequest` にそのまま埋め込みます。`valueDer` の中身は library が parse / 検証しません。SAN や他の caller-supplied extension と OID が重複した場合は `Duplicate CSR extension OID` で throw。
- **順序**: caller-supplied `extensions` は入力順を保持し、SAN (emit する場合) は常に先頭に置きます。
- **PEM 形式**: `pem` field は RFC 7468 の `CERTIFICATE REQUEST` label を使用します。
- **state なし**: 関数は純粋で、同じ入力で 2 回呼べば 2 つの異なる DER が返ります (ECDSA 署名は randomized なため)。

これは `parseCertificateSigningRequest` + `verifyCertificateSigningRequestSignature` の producer 側 API です。呼び出し側で鍵を持つ運用と、issuer 側の `issueClientCertForPublicKey` を組み合わせると、秘密鍵を一切ネットワーク越しに渡さず enrollment できます。

### `parseCertificateSigningRequest(input)`

PKCS#10 (RFC 2986) CSR を DER バイト列または PEM 文字列で受け取り、発行に必要な構造化 field を取り出し、それ以外は raw bytes として呼び出し側に渡します。

```ts
function parseCertificateSigningRequest(
  input: string | Uint8Array
): Promise<ParsedCertificateSigningRequest>;

interface ParsedCertificateSigningRequest {
  subject: Subject;
  publicKey: CryptoKey;
  subjectPublicKeyInfoDer: Uint8Array;
  requestedDnsNames: readonly string[];
  requestedIpAddresses: readonly string[];
  requestedExtensions: readonly { oid: string; critical: boolean; valueDer: Uint8Array }[];
  otherAttributes: readonly { oid: string; valuesDer: ReadonlyArray<Uint8Array> }[];
  signatureAlgorithmOid: string;
  signatureDer: Uint8Array;
  certificationRequestInfoDer: Uint8Array;
}
```

挙動:

- **algorithm 範囲**: `ecdsa-with-SHA256` / `ecdsa-with-SHA384` / `ecdsa-with-SHA512` のみ受理。RSA、Ed25519 等は `Unsupported CSR signatureAlgorithm` で throw。
- **PEM label**: `CERTIFICATE REQUEST` (RFC 7468) と legacy `NEW CERTIFICATE REQUEST` の両方を受理。
- **subject**: encoder と同じ前提 (single-valued RDN のみ) で `Subject` 配列に decode。`UTF8String` / `PrintableString` / `IA5String` 値型に対応。
- **SAN 抽出**: `extensionRequest` 属性の SAN から `requestedDnsNames` と `requestedIpAddresses` を取り出す。IPv4 は dotted-quad、IPv6 は RFC 5952 の `::` 圧縮 (最長ゼロランをまとめる)。
- **`requestedExtensions`**: `extensionRequest` に入っている全 X.509 extension (SAN を含む)。`valueDer` は OCTET STRING の中身。
- **`otherAttributes`**: OID が `extensionRequest` 以外の CSR-level attribute (例: `challengePassword`) の生 DER。
- **`certificationRequestInfoDer`**: 内側 `CertificationRequestInfo` SEQUENCE の生バイト列、POP 検証用。

library は **policy を一切適用しません**。CSR の主張 subject/SAN を採用するか、algorithm が許容ラインかなどは EdgCA の外で判断します。

### `verifyCertificateSigningRequestSignature(parsed)`

CSR 自身の埋め込み公開鍵で CSR 署名を検証します (POP)。

```ts
function verifyCertificateSigningRequestSignature(
  parsed: ParsedCertificateSigningRequest
): Promise<boolean>;
```

`parsed.certificationRequestInfoDer` への署名が `parsed.publicKey` で verify できれば `true`。これは「CSR を作った主体が対応する秘密鍵を持っている」ことを示すだけで、**identity の確認や発行可否の認可ではありません**。enrollment flow の transport (mTLS) や application 層の認証と組み合わせて使います。

### `importCertificateAuthority(options)`

CA certificate と private key を import し、後続の発行に使える `CertificateAuthority` として返します。

```ts
function importCertificateAuthority(options: {
  certPem: string;
  privateKey: CryptoKey;
  issuerChainPem?: string;
}): Promise<CertificateAuthority>;
```

`privateKey` は certificate の public key と対応している必要があります (sign/verify round trip で確認します)。正しくない `certPem` (期限切れ・壊れた署名・想定外の extension など) を渡しても error にはならず、入力に従ってそのまま誤った証明書が発行される仕様です。返却値は `createRootCA()` や `issueIntermediateCA()` と同じ `CertificateAuthority` 形状です。

intermediate CA を再 import する場合は、`issuerChainPem` に parent chain を渡します。この chain は client certificate 発行時の `certChainPem` 構築に使われます。

呼び出し側は永続化された PKCS#8 PEM などを `crypto.subtle.importKey("pkcs8", …, { name: "ECDSA", namedCurve: "P-256" }, extractable, ["sign"])` で `CryptoKey` 化してから渡してください。library は format 変換を行いません。

### `verifyCertificateIssuedBy(options)`

certificate と直接の issuer 1 本の関係を検証します。issuer の秘密鍵や `CertificateAuthority` は不要です。

```ts
function verifyCertificateIssuedBy(options: {
  certificatePem: string;
  issuerCertificatePem: string;
  at?: Date | number;
}): Promise<boolean>;
```

次のすべてが成立した場合に `true` を返します。

- certificate の issuer DN と issuer certificate の subject DN が一致する。
- certificate の AKI と issuer certificate の SKI が一致する。AKI / SKI が必要な位置に存在しなければ `false`。
- certificate の署名を issuer certificate の公開鍵で検証できる。
- certificate と issuer certificate の DER 内 `notBefore ≤ at ≤ notAfter` が成立する。`at` の default は `Date.now()`。
- issuer certificate が `BasicConstraints CA=true` と `KeyUsage keyCertSign` を持つ。
- 重複 extension、署名 algorithm の内外不一致、未対応 critical extension がない。

この関数は 1 link だけを対象とし、target certificate の EKU profile や root への到達は検証しません。chain 全体と用途を確認する場合は `verifyCertificateChain` を使います。trust 条件の不成立は `false`、構文上処理不能な PEM / DER、未対応 algorithm、不正な `at` は例外です。

### `verifyCertificateChain(options)`

caller が順序を明示した certificate chain を、明示された trust anchor まで検証します。

```ts
function verifyCertificateChain(options: {
  certificatePem: string;
  intermediateCertificatesPem?: readonly string[];
  trustedRootCertificatesPem: readonly string[];
  at?: Date | number;
  purpose?: CertificateVerificationPurpose;
}): Promise<CertificateChainVerificationResult>;
```

入力規則:

- `intermediateCertificatesPem` は target の**直接 issuer から順番**に渡す。EdgCA の 2-level CA 制約に合わせ、要素数は `0` または `1`。
- `trustedRootCertificatesPem` は 1 本以上を明示する。OS / runtime の trust store は参照しない。
- `at` の default は `Date.now()`。target、intermediate、選択された root の DER 内有効期間を同じ時刻で検証する。
- `purpose` は target に期待する profile。`"ca"` は `CA=true` と `keyCertSign`、`"clientAuth"` は `CA=false`、`digitalSignature`、EKU `clientAuth`、`"documentSigning"` は `CA=false`、`digitalSignature`、`contentCommitment`、EKU `id-kp-documentSigning` を要求する。

検証内容:

1. target から順に、各 child / issuer 間の issuer DN、AKI / SKI、署名を検証する。
2. issuer として使う intermediate / root の `BasicConstraints CA=true`、`KeyUsage keyCertSign`、`pathLenConstraint` を検証する。
3. target、intermediate、root の DER 内 `UTCTime` / `GeneralizedTime` を parse し、有効期間を検証する。
4. 重複 extension、未対応 critical extension、TBSCertificate と外側の signature algorithm 不一致を拒否する。
5. chain 末尾の issuer が `trustedRootCertificatesPem` の certificate と DER 全体で一致することを要求する。DN だけの一致では信頼しない。
6. 選択された EdgCA root の自己署名と CA 制約を整合性 check する。root の信頼自体は自己署名ではなく、caller が trust anchor として明示したことから得る。

この関数は unordered な候補群から issuer を探索しません。AIA 取得、OS trust store、CRL / OCSP、TLS handshake の proof-of-possession、server hostname 照合も行いません。

```ts
import { verifyCertificateChain } from "@noz-ele/edgca/verify";

const result = await verifyCertificateChain({
  certificatePem: clientPem,
  intermediateCertificatesPem: [intermediatePem],
  trustedRootCertificatesPem: [rootPem],
  purpose: "clientAuth"
});

if (!result.valid) {
  throw new Error(
    `certificate chain rejected at ${result.certificateIndex}: ${result.reason}`
  );
}
```

### `verifyCertificateSignature(options)`

certificate に含まれる公開鍵を使い、caller が渡した任意データの ECDSA signature を検証します。

```ts
function verifyCertificateSignature(options: {
  certificatePem: string;
  data: Uint8Array;
  signature: Uint8Array;
  signatureFormat: EcdsaSignatureFormat;
}): Promise<boolean>;
```

入力規則:

- `certificatePem` は公開鍵を取得する leaf certificate PEM。先頭の `BEGIN CERTIFICATE` block を読む。
- `data` は署名時に使用したものと同じ生 byte 列。事前計算した digest ではなく、WebCrypto が対応 hash を適用する前の message を渡す。
- `signature` は `signatureFormat` で指定した byte 表現の ECDSA signature。
- `signatureFormat` は `"der"` または `"ieee-p1363"` の必須指定。形式を byte 列から推測しない。

certificate の公開鍵 curve に応じて、P-256/SHA-256、P-384/SHA-384、P-521/SHA-512 の標準ペアリングで検証します。well-formed な入力で cryptographic signature が一致すれば `true`、別の鍵、改変された `data`、または改変された署名なら `false` を返します。不正な PEM / DER、未対応 algorithm、不正な署名形式、curve に対して不正な長さの P1363 signature は例外です。

この関数は次を検証しません。

- certificate chain、trust anchor、有効期間、Basic Constraints、Key Usage、EKU、失効状態。
- nonce / challenge の発行時刻、有効期限、一意性、未使用状態。
- HTTP method、URI、authority、body digest と `data` の対応。
- RFC 9421 の `Accept-Signature`、`Signature-Input`、`Signature` の parse と canonicalization。
- TLS handshake の `CertificateVerify` や TLS connection への binding。

認証用途では、先に同じ `certificatePem` を `verifyCertificateChain({ purpose: "clientAuth" })` で検証し、application が nonce、HTTP request、certificate fingerprint 等から再構築した署名対象を `data` に渡します。

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
if (!chain.valid) {
  throw new Error(`certificate chain rejected: ${chain.reason}`);
}

const signatureValid = await verifyCertificateSignature({
  certificatePem: clientPem,
  data: signatureBase,
  signature: signatureBytes,
  signatureFormat: "ieee-p1363"
});
```

この API は cryptographic signature primitive であり、それ単体を `verifyProofOfPossession` とは呼びません。nonce の新鮮性、リプレイ防止、request binding を caller が成立させた時に、protocol 全体として private key の proof-of-possession になります。

この関数は private key material を入力に取りません。caller 所有の `data` / `signature` buffer は変更せず、WebCrypto に渡すために作成した範囲ぴったりの一時 `ArrayBuffer` copy は検証完了後にゼロクリアします。certificate と signature は公開情報ですが、`data` に機密性のある request 内容が含まれる可能性を考慮し、library が作った余分な copy の寿命を検証処理内に限定します。

### `verifyClientCertificateIssuedBy(options)`

> **互換 API:** 新規コードでは `@noz-ele/edgca/verify` の `verifyCertificateIssuedBy` または `verifyCertificateChain` を推奨します。この API は既存 caller のため root entry point に残し、現在の引数と挙動を変更しません。

`options.ca` が `options.certPem` を発行した issuer か判定します。Cloudflare Workers で `request.cf.tlsClientAuth.certRFC9440` を decode した PEM を受け取り、自分の自己 CA が発行した cert かを application 側で確認するための post-handshake な発行元 check です。

> ⚠ **これは mTLS の検証ではなく、提示者の認証もしません。** 単に「証明書が指定 CA で発行されたか」を判定するだけです。client certificate は誰にでも提示できる情報で内容は容易にコピーできるため、証明書情報を持っていることは正当な持ち主であることの根拠になりません。Cloudflare Workers runtime は TLS handshake の `CertificateVerify` を公開しないため、Worker は TLS handshake 自体の proof-of-possession を再検証できません。非 Enterprise プランでは自前 CA に対して `request.cf.tlsClientAuth.certVerified === "SUCCESS"` にもなりません。コピーした証明書を提示する攻撃者はこの check を通過します。本物の認証には Cloudflare Enterprise mTLS、または application 層で nonce 等を署名させ、`verifyCertificateSignature` で検証する challenge-response を重ねてください。詳細は [README.md → Verify](README.md#verify-cloudflare-worker) を参照。

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

判定は次のすべてが成立で `true`、いずれかが不成立で `false` を return します。

- (`validity` 指定時) `validity.notBefore ≤ now ≤ validity.notAfter` が成立する。
- `certPem` の issuer DN が `ca` の subject DN と完全一致する。
- `certPem` の Authority Key Identifier が `ca` の Subject Key Identifier と完全一致する。`certPem` が AKI を持たない場合は `false`。
- `certPem` の signature を `ca.publicKey` で verify できる (ECDSA P-256 / P-384 / P-521 と標準 hash pairing)。

PEM や DER として parse 不能な入力は `Error` を投げます (CA 不一致 = `false`、入力破損 = throw、と扱いを分ける)。

#### `validity` option

省略可能な時刻有効性 check。指定された場合のみ評価します。値はすべて呼び出し側が `cf.tlsClientAuth.certNotBefore` / `certNotAfter` から `Date` または epoch milliseconds に変換して渡します (library は cert の `notBefore` / `notAfter` field を参照しません)。

| field      | 型               | 必須 | default      | 意味と制約                                                                                                |
| ---------- | ---------------- | ---- | ------------ | --------------------------------------------------------------------------------------------------------- |
| `notBefore` | `Date \| number` | ✅   | —            | この時刻より前は invalid。`Date` または epoch ms。`NaN` / 非有限値は例外。                                  |
| `notAfter`  | `Date \| number` | ✅   | —            | この時刻より後は invalid。同上の制約。`notBefore > notAfter` は例外。                                       |
| `now`       | `Date \| number` | —    | `Date.now()` | 比較する現在時刻。テスト・past-time 検証用に明示できる。                                                    |

時刻ウィンドウ外なら identity check を実行せず即 `false` を返します (cert parse・signature verify を skip して expensive な crypto を節約)。`validity` を省略した場合は時刻判定をしません。

#### 使い方 (Cloudflare Worker)

```ts
import { verifyClientCertificateIssuedBy } from "@noz-ele/edgca";

const tls = request.cf!.tlsClientAuth!;

// RFC 9440 Structured Field (":<base64>:") を PEM に整形
const b64 = tls.certRFC9440.replace(/^:|:$/g, "");
const certPem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;

const ok = await verifyClientCertificateIssuedBy({
  ca,                                          // 自前で import 済みの CertificateAuthority
  certPem,
  validity: {
    notBefore: new Date(tls.certNotBefore),    // 文字列 → Date 変換は caller 責務
    notAfter:  new Date(tls.certNotAfter)
  }
});
```

identity だけで時刻を見ない場合は `validity` を省略します。

```ts
const ok = await verifyClientCertificateIssuedBy({ ca, certPem });
```

時刻を library 関数では見ず application 側で 2 行比較する場合は次のようになります (動作は等価)。

```ts
const now = Date.now();
const inWindow =
  Date.parse(tls.certNotBefore) <= now && now <= Date.parse(tls.certNotAfter);
const ok = inWindow && await verifyClientCertificateIssuedBy({ ca, certPem });
```


この関数は **発行 issuer 1 本に対する identity 確認 + (任意で) 時刻有効性** だけを行います。次は対象外です。

- chain 遡及 (intermediate を介して root から発行された leaf を root に対して verify するなど)。`ca` には**直接の発行者** (root から直接発行なら root、intermediate 経由なら intermediate) を渡してください。
- revocation check (CRL / OCSP)。
- `cf.tlsClientAuth` 型からの自動抽出。RFC 9440 形式 (`:base64:`) からの decode と、`certNotBefore` / `certNotAfter` 文字列の `Date` への parse は呼び出し側で行います。

複数 CA を運用していて「どれが発行したか」を知りたい場合は、呼び出し側で CA 配列を回してください。

### `certificateToPem(der)`

DER certificate bytes を PEM `CERTIFICATE` block に encode します。`encodePem("CERTIFICATE", der)` と等価です。

```ts
function certificateToPem(der: Uint8Array): string;
```

### `csrToPem(der)`

DER PKCS#10 CSR bytes を PEM `CERTIFICATE REQUEST` block (RFC 7468 §7) に encode します。`encodePem("CERTIFICATE REQUEST", der)` と等価です。

```ts
function csrToPem(der: Uint8Array): string;
```

### `encodePem(label, der)`

任意の DER bytes を、指定 RFC 7468 label 付きの PEM block にまとめます (base64 + 64 文字折り返し)。`certificateToPem` と `csrToPem` の内部で使われており、CLI など他の label 種別を emit したい場合 (例: `crypto.subtle.exportKey("pkcs8", …)` で取り出した PKCS#8 秘密鍵に `"PRIVATE KEY"` を被せる) に呼び出せます。

```ts
function encodePem(label: string, der: Uint8Array): string;
```

### `pemToDer(pem)`

文字列内の最初の PEM block を、label を問わず DER bytes に decode します。

```ts
function pemToDer(pem: string): Uint8Array;
```

### `pemToDerWithLabel(pem, label)`

`label` と完全一致する最初の PEM block を取り出して decode します。一致する block が存在しない場合や、一致したが body が空の場合は throw します。1 つの PEM ファイルに複数種別の block が混在しているとき (例: `"CERTIFICATE"` と `"PRIVATE KEY"` と `"CERTIFICATE REQUEST"`) に、目的の種別だけを安全に取り出す用途で使います。

```ts
function pemToDerWithLabel(pem: string, label: string): Uint8Array;
```

### `splitPemBlocks(pem)`

1 つ以上の PEM block を含む文字列を、完全な PEM block (`-----BEGIN/END-----` 行を含む) 文字列の配列に分割します。chain ファイル (`leaf + intermediate + root` を連結したもの) を label で判別する前に block 単位で回したい場合に使えます。

```ts
function splitPemBlocks(pem: string): string[];
```

### `generateKeyPair(curve?)`

指定 supported curve 上の extractable な ECDSA `CryptoKeyPair` (`["sign", "verify"]`) を生成します。default は P-256。CA / 発行 / CSR 作成 API は同じ目的で `keyPair` option を受け取れるため、この helper は主に「先に鍵を作って中身を確認してから渡したい」呼び出し側向けです。

```ts
function generateKeyPair(curve?: SupportedCurve): Promise<CryptoKeyPair>;

type SupportedCurve = "P-256" | "P-384" | "P-521";
```

### `arrayBufferFromBytes(bytes)`

与えられた `Uint8Array` の中身をコピーした新しい `ArrayBuffer` を返します。WebCrypto (`crypto.subtle.importKey`、`crypto.subtle.sign` 等) に bytes を渡すとき、TypeScript の厳格な lib 型のもとで `BufferSource` を満たしつつ、呼び出し側が保持する元 buffer と aliasing しないために使います。

```ts
function arrayBufferFromBytes(bytes: Uint8Array): ArrayBuffer;
```

### `exportPkcs12(input)`

leaf 証明書、任意の issuer chain、対応する秘密鍵 (PKCS#8 DER bytes) をひとまとめにした password 付き PFX (PKCS#12) を組み立てます。鍵の algorithm は inspect せず、任意の PKCS#8 (ECDSA / RSA / Ed25519 など) をそのまま通します。出力は DER bytes の `Uint8Array` で、そのまま `.pfx` / `.p12` として書き出したり、`tls.createSecureContext({ pfx, passphrase })` に渡したり、Win11+ / Server 2019+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux PKCS#12 consumer に取り込めます。

```ts
function exportPkcs12(input: ExportPkcs12Input): Promise<Uint8Array>;
```

algorithm は固定です:

- 証明書 bag: PBES2 + PBKDF2-HMAC-SHA-256 + AES-256-CBC。
- 秘密鍵 bag (`pkcs8ShroudedKeyBag`): PBES2 + PBKDF2-HMAC-SHA-256 + AES-256-CBC。
- 外側 MAC: HMAC-SHA-256、鍵は PKCS#12 v1 KDF (RFC 7292 App. B、ID = 3、u = 32、v = 64) で導出。
- PBKDF2 の prf は `hmacWithSha256` + `NULL` parameters を**明示**して emit します。仕様 default に頼ると HMAC-SHA-1 にサイレント縮退する罠があるため意図的に避けています。

反復回数の default は PBKDF2 が `600_000`、MAC KDF が `100_000` で、OWASP の現代的推奨と OpenSSL 3 の default と揃えています。両方とも引数で上書きできます (リソース制約のある環境向けに小さい値を渡せる)。空 password、`Uint8Array` 以外の password / friendlyName / `privateKey`、空 `privateKey`、非正の反復回数は API 境界で reject します。

対象外 (出力しない、scope consumer での再 import も対象外): 旧式 3DES / RC2 / SHA-1 PBE algorithm、PBMAC1、crlBag、secretBag、入れ子 safeContents、envelopedData、Windows 10 (以前)。詳細は [`docs/jp/NON_GOALS.md`](NON_GOALS.md)。

同一コードが Cloudflare Workers / Node 20+ / modern browser のいずれでも変更なく動きます。`exportPkcs12` は `globalThis.crypto.subtle` のみに依存します。ブラウザ用途では `import { exportPkcs12 } from "@noz-ele/edgca/pkcs12"` という subpath 経由で CA / CSR / verify モジュールを静的 import せずに取り込めます。

```ts
import { exportPkcs12 } from "@noz-ele/edgca/pkcs12";

const pfx = await exportPkcs12({
  certDer: client.certDer,
  chainDer: [intermediate.certDer],
  // exportPkcs12 は PKCS#8 DER bytes を受けるので、CryptoKey から取り出して渡す。
  privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", client.privateKey)),
  password: new TextEncoder().encode(passwordString),
  friendlyName: new TextEncoder().encode("worker-client")
});
```

## Errors

EdgCA は invalid input や対象外操作に対して `Error` を投げます。

例:

- subject が空、または array ではない。
- 未対応の subject attribute type。
- 不正な dotted OID。
- `C` の値が PrintableString として不正。
- SAN の IP address が不正。
- `days` が正の数ではない。
- import した private key が CA certificate の public key と対応しない。
- issuer certificate が CA ではない。
- issuer certificate に `keyCertSign` がない。
- root CA 以外から intermediate CA を発行しようとした。
- `pathLenConstraint=0` の root CA から intermediate CA を発行しようとした。
- 最大 2 段の CA 階層を超える `pathLenConstraint` を指定した。
- `password` が空 / `Uint8Array` ではない / 不正な UTF-8 sequence を含む (`exportPkcs12`)。
- `friendlyName` を渡したが `Uint8Array` ではない (`exportPkcs12`)。
- `privateKey` が空でない `Uint8Array` (PKCS#8 DER bytes) ではない (`exportPkcs12`)。
- `iterations` または `macIterations` が正の整数ではない (`exportPkcs12`)。

検証 API は「処理不能」と「処理できたが信頼条件を満たさない」を分離します。

- 壊れた PEM / DER、未対応 algorithm、不正な option は `Error`。
- `verifyCertificateIssuedBy` の issuer 不一致、期限外、署名不正は `false`。
- `verifyCertificateChain` の chain / profile / trust 不成立は `CertificateChainVerificationResult` の `{ valid: false, reason, certificateIndex }`。
- `verifyCertificateSignature` は well-formed な入力に対する署名不一致を `false`、不正な署名 encode、P1363 の長さ不一致、不正 option を `Error` とする。
- legacy `verifyClientCertificateIssuedBy` は従来どおり CA 局判定の `boolean`。

失効状態は検証対象外なので result reason に含めません。

## Field Reference

このセクションは `types.ts` から export される interface の field を 1 つずつ表で解説します。雛形を作る時、IDE 上で型 signature だけでは default や制約が読み取れないため、ここに参照情報をまとめます。

凡例:

- **必須** 列の `✅` は `?` なし field、`—` は optional field。
- **default** 列は optional 時に内部で適用される値。`—` は「未指定の場合 field 自体が encode されない」を意味する。
- 制約は library が呼び出し時に検査する条件。違反時は `Error` を投げる。

### Options

#### `CreateRootCAOptions`

`createRootCA` の引数。自己署名 root CA を 1 本作るための入力一式を表す。subject DN と有効期間が最低限必要で、配下に intermediate を置くか (`pathLenConstraint`) と既存鍵の持ち込み (`keyPair`) を任意で指定する。新規発行と再現発行 (持ち込み鍵) の両方を 1 つの interface で扱う。

| field               | 型               | 必須 | default                                                                                       | 意味と制約                                                                                                                                                                                                                                                                                       |
| ------------------- | ---------------- | ---- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `subject`           | `Subject`        | ✅   | —                                                                                             | root CA の subject DN。配列順序は保持。self-signed のため issuer DN にも同値が入る。詳細は § `Subject` 参照。空配列は不可。                                                                                                                                                                       |
| `days`              | `number`         | ✅   | —                                                                                             | `notBefore` からの有効日数。正の有限数のみ。1 日 = `86_400_000ms` の単純加算 (閏秒なし)。上限の check なし。                                                                                                                                                                                       |
| `notBefore`         | `Date`           | —    | 呼び出し時刻 (`new Date()`)                                                                    | validity の開始時刻。1950–2049 は `UTCTime`、それ以外は `GeneralizedTime` で encode。                                                                                                                                                                                                              |
| `serialNumber`      | `SerialNumber`   | —    | CSPRNG 由来 16-byte random (正値、MSB cleared、CAB BR 7.1 の ≥64 bit entropy 要件を満たす) | 発行 cert を issuer 内で識別する integer の**呼び出し側明示指定**。通常は省略して default の random に任せ (Workers の stateless 性と業界標準準拠を両立)、監査・テスト再現性・外部システムからの採番引き継ぎ等で決定的な値が要る時だけ渡す。入力型は § `SerialNumber` 参照。DER encode 後 20 octet を超えると例外。 |
| `pathLenConstraint` | `number`         | —    | `1`                                                                                           | root CA の下に作れる intermediate の段数。`0` または `1` のみ許容。`0` の root は intermediate を発行できず client cert 専用になる。                                                                                                                                                                |
| `keyPair`           | `CryptoKeyPair` | —    | 内部生成 (P-256 ECDSA、`extractable: true`)                                                  | 持ち込み鍵ペア。`privateKey.usages` に `"sign"`、`publicKey.usages` に `"verify"` が含まれている必要がある。`extractable` は呼び出し側の選択で、library は `subtle.sign` / `subtle.exportKey("spki", publicKey)` のみ使う (private 側は extract 不要)。省略時は WebCrypto で生成。                |

#### `IssueIntermediateCAOptions`

`issueIntermediateCA` の引数。既存 root CA から intermediate CA を 1 本発行するための入力。`CreateRootCAOptions` との違いは、親となる root を `ca` で渡す点と、intermediate のさらに下に intermediate を置けない設計のため `pathLenConstraint` が実質 `0` 固定である点。

| field               | 型                     | 必須 | default                       | 意味と制約                                                                                                                                                                                       |
| ------------------- | ---------------------- | ---- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ca`                | `CertificateAuthority` | ✅   | —                             | 親となる root CA。intermediate を親にすると例外。`pathLenConstraint=0` の root を親にしても例外。`isCA=false` または `keyCertSign` なしの cert を渡しても例外。                                  |
| `subject`           | `Subject`              | ✅   | —                             | 発行する intermediate CA の subject DN。                                                                                                                                                          |
| `days`              | `number`               | ✅   | —                             | `CreateRootCAOptions.days` と同じ。加えて、issuer の `notAfter` を超える指定をしても library は止めない (verifier 側で reject される cert ができる)。                                              |
| `notBefore`         | `Date`                 | —    | 呼び出し時刻                  | `CreateRootCAOptions.notBefore` と同じ。                                                                                                                                                          |
| `serialNumber`      | `SerialNumber`         | —    | CSPRNG 由来 16-byte random | `CreateRootCAOptions.serialNumber` と同じ。                                                                                                                                                       |
| `pathLenConstraint` | `number`               | —    | `0`                           | 発行される intermediate の `pathLenConstraint` は常に `0`。明示する場合は `0` のみ許容、`1` 以上は例外。                                                                                          |
| `keyPair`           | `CryptoKeyPair`       | —    | 内部生成                       | `CreateRootCAOptions.keyPair` と同じ (intermediate CA の鍵ペアを渡す)。                                                                                                                            |

#### `IssueClientCertOptions`

`issueClientCert` の引数。mTLS 用 client certificate を 1 本発行するための入力。`ca` で issuer を指定する (root / intermediate のどちらでも可)。client cert の鍵は短命利用を前提に常に内部生成されるため、CA 用 options と違って `keyPair` を受け付けない。SAN は任意で、未指定なら extension 自体が省略される。

| field          | 型                     | 必須 | default                       | 意味と制約                                                                                                                                                                                                       |
| -------------- | ---------------------- | ---- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ca`           | `CertificateAuthority` | ✅   | —                             | 発行 issuer。root または intermediate どちらでも可。`isCA=false` または `keyCertSign` なしの cert を渡すと例外。                                                                                                  |
| `subject`      | `Subject`              | ✅   | —                             | 発行する client cert の subject DN。                                                                                                                                                                              |
| `days`         | `number`               | ✅   | —                             | `CreateRootCAOptions.days` と同じ。                                                                                                                                                                              |
| `notBefore`    | `Date`                 | —    | 呼び出し時刻                  | `CreateRootCAOptions.notBefore` と同じ。                                                                                                                                                                          |
| `serialNumber` | `SerialNumber`         | —    | CSPRNG 由来 16-byte random | `CreateRootCAOptions.serialNumber` と同じ。                                                                                                                                                                       |
| `dnsNames`     | `string[]`             | —    | `undefined`                   | SAN dNSName。指定時のみ SAN extension が出力される。RFC 1035 §2.3.1 preferred name syntax: 各 label は `[A-Za-z0-9]` で始終端し内部に `-` 可、label 長 ≤63 chars、全長 ≤253 chars、先頭の `*.` ワイルドカード可。違反は例外。 |
| `ipAddresses`  | `string[]`             | —    | `undefined`                   | SAN iPAddress。IPv4 / IPv6 文字列。`dnsNames` と併用可。両者未指定なら SAN extension 自体が省略される。                                                                                                          |

`issueClientCert` は client cert の鍵を**常に内部生成**するため、`keyPair` option はない。client cert の鍵は ephemeral 想定。

#### `IssueDocumentSigningCertOptions`

`issueDocumentSigningCert` の引数。文書署名用 leaf を 1 本発行するための入力。`IssueClientCertOptions` との差は、SAN 系 field (`dnsNames` / `ipAddresses`) を持たないこと。文書署名 leaf における署名者 identity は Subject DN だけで示す。`IssueClientCertOptions` と同じく `keyPair` option はなく、leaf 鍵は常に内部生成される。

| field          | 型                     | 必須 | default                       | 意味と制約                                                                                                            |
| -------------- | ---------------------- | ---- | ----------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `ca`           | `CertificateAuthority` | ✅   | —                             | 発行 issuer。root または intermediate どちらでも可。`isCA=false` または `keyCertSign` なしの cert を渡すと例外。            |
| `subject`      | `Subject`              | ✅   | —                             | 発行する文書署名 leaf の subject DN。署名者を識別するための DN。                                                         |
| `days`         | `number`               | ✅   | —                             | `CreateRootCAOptions.days` と同じ。                                                                                    |
| `notBefore`    | `Date`                 | —    | 呼び出し時刻                  | `CreateRootCAOptions.notBefore` と同じ。                                                                                |
| `serialNumber` | `SerialNumber`         | —    | CSPRNG 由来 16-byte random    | `CreateRootCAOptions.serialNumber` と同じ。                                                                             |

#### `ImportCertificateAuthorityOptions`

`importCertificateAuthority` の引数。永続化された CA 情報 (cert PEM + 秘密鍵 `CryptoKey`、必要なら親 chain) を再構成して `CertificateAuthority` instance に戻すための入力。新規 CA を作るのではなく、保存済み CA を Workers の起動時に読み込んで以降の発行に使う運用で利用する。

| field             | 型          | 必須 | default     | 意味と制約                                                                                                                                                                                                       |
| ----------------- | ----------- | ---- | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `certPem`         | `string`    | ✅   | —           | import する CA certificate PEM。先頭の `BEGIN CERTIFICATE` block を読む。                                                                                                                                       |
| `privateKey`      | `CryptoKey` | ✅   | —           | `certPem` に対応する private `CryptoKey` (ECDSA P-256、`["sign"]` 用途)。public key と sign/verify で一致確認する。一致しない場合は例外。`extractable` は呼び出し側の選択。format 変換 (PEM → CryptoKey 等) は呼び出し側で行う。 |
| `issuerChainPem`  | `string`    | —    | `""` (空)   | import 対象が intermediate CA の時、その親 chain の PEM。client cert 発行時の `certChainPem` 構築に使われる。複数 `CERTIFICATE` block を改行で連結して渡す。空文字列の場合 root として扱われる。                            |

### Results

#### `CertificateAuthority`

CA を「秘密鍵 + 自 cert + 上位 chain」の 3 点で 1 つにまとめた instance 型。`createRootCA` / `issueIntermediateCA` / `importCertificateAuthority` の戻り値で、そのまま `issueIntermediateCA` / `issueClientCert` の `ca` 引数に渡せる。発行関数が必要とする状態をすべて 1 つに束ねたハンドルとして扱う。永続化する時は `certPem` / `privateKey` (caller 側で `subtle.exportKey` する) / `issuerChainPem` を保存し、復元時は再 import した `CryptoKey` と `certPem` を `importCertificateAuthority` に渡す。

| field            | 型           | 意味                                                                                |
| ---------------- | ------------ | ----------------------------------------------------------------------------------- |
| `certPem`        | `string`     | 自 CA certificate の PEM (`CERTIFICATE` block)。                                    |
| `certDer`        | `Uint8Array` | 自 CA certificate の DER bytes。`certPem` を decode したものと等価。                  |
| `privateKey`     | `CryptoKey`  | WebCrypto `CryptoKey` instance。`["sign"]` 用途。                                   |
| `publicKey`      | `CryptoKey`  | WebCrypto `CryptoKey` instance。`["verify"]` 用途。                                 |
| `issuerChainPem` | `string`     | 上位 CA chain の PEM。root CA では `""`。intermediate CA では root の PEM。複数 CA を含む場合は改行区切り。 |

#### `IssuedClientCertificate`

`issueClientCert` の戻り値。発行された client cert を「秘密鍵 + cert + 完全 chain」の 3 点で返す型。CA 用途は想定されないため、追加発行に使い回すことはできない (再 import すると `CertificateAuthority` にはなるが、`issueClientCert` が出力するのは leaf cert なので発行 issuer として機能しない)。verifier に提示する完成形 chain が `certChainPem` に入っている。

| field           | 型           | 意味                                                                              |
| --------------- | ------------ | --------------------------------------------------------------------------------- |
| `certPem`       | `string`     | client certificate の PEM。                                                       |
| `certDer`       | `Uint8Array` | client cert の DER bytes。                                                         |
| `privateKey`    | `CryptoKey`  | WebCrypto `CryptoKey`。`["sign"]` 用途。                                          |
| `publicKey`     | `CryptoKey`  | WebCrypto `CryptoKey`。`["verify"]` 用途。                                        |
| `certChainPem`  | `string`     | leaf + issuer + issuerChain を改行で連結した完全 chain。intermediate 経由で発行した場合は `client + intermediate + root` の順。 |

#### `IssuedDocumentSigningCertificate`

`issueDocumentSigningCert` の戻り値。構造は `IssuedClientCertificate` と同一の 5 field だが、interface 名を分けることで「埋め込み EKU が `id-kp-documentSigning` (RFC 9336) であって `clientAuth` ではない」ことを意味論的に示す。leaf は任意 document への署名 (CAdES、CMS、ASiC-E など、本 library 外で生成) を意図しており、TLS handshake で提示することは想定しない。

| field           | 型           | 意味                                                                              |
| --------------- | ------------ | --------------------------------------------------------------------------------- |
| `certPem`       | `string`     | 文書署名 certificate の PEM。                                                     |
| `certDer`       | `Uint8Array` | 文書署名 cert の DER bytes。                                                       |
| `privateKey`    | `CryptoKey`  | WebCrypto `CryptoKey`。`["sign"]` 用途。                                          |
| `publicKey`     | `CryptoKey`  | WebCrypto `CryptoKey`。`["verify"]` 用途。                                        |
| `certChainPem`  | `string`     | leaf + issuer + issuerChain を改行で連結した完全 chain。intermediate 経由で発行した場合は `signing-leaf + intermediate + root` の順。 |

### `SubjectAttribute`

`Subject` を構成する 1 entry。X.509 cert の Subject DN (Distinguished Name) は複数の attribute を順番に並べた構造で、その 1 つを `{ type, value }` で表現する。EdgCA は `CN=foo,O=Example` のような DN 文字列入力を受け付けず、必ずこの structured な配列で渡す設計。multi-valued RDN (1 つの RDN に複数 attribute) も非対応で、1 entry = 1 RDN。

| field   | 型                     | 必須 | 意味と制約                                                                                                                                                                                                                                                                                                            |
| ------- | ---------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`  | `SubjectAttributeType` | ✅   | attribute の種別。短縮名 (`CN`, `O`, `OU`, `C`, `ST`, `L`, `E`, `DC`, `SERIALNUMBER`, `STREET`, `POSTALCODE`, `TITLE`, `GIVENNAME`, `SURNAME`, `UID`) または dotted OID 文字列 (`1.2.3.4.5`)。未対応の短縮名・不正な OID は例外。                                                                                          |
| `value` | `string`               | ✅   | attribute の値。OID に応じて string type を選択 (`C` → PrintableString、emailAddress → IA5String、他 → UTF8String)。短縮名と等価な dotted OID でも同じ規則。`C` の値が PrintableString として不正な場合は例外。emailAddress の値が IA5 (ASCII) として不正な場合も例外。                                                            |

### `SerialNumber` 入力形式

`SerialNumber` は cert の serial number を呼び出し側で明示する時に使う union 型 alias (`bigint | number | string | Uint8Array`)。明示する場面は限られ、通常は省略して library の random 生成 (16-byte) に任せる。決定的な値を要求する監査要件、再現性が必要なテスト、外部システムが採番する serial を引き継ぐ場合などで指定する。入力型ごとの解釈は次のとおり。

| 入力型                | 解釈                                       | 制約                            |
| --------------------- | ------------------------------------------ | ------------------------------- |
| 省略                  | 16-byte random、MSB を clear して正値化   | —                               |
| `bigint`              | そのまま integer encode                   | DER encode 後 20 octet 以内     |
| `number`              | そのまま integer encode                   | 同上                            |
| `string` (`/^\d+$/`) | decimal として `BigInt` 変換              | 同上                            |
| `string` (hex)        | 偶数桁化して bytes として読む             | 同上                            |
| `Uint8Array`          | bytes 列として直接利用                    | 1 byte 以上、20 byte 以内       |

## Non-Goals

EdgCA は限定的な chain validation を提供しますが、次は提供しません。

- server certificate 発行。leaf scope は mTLS client cert と文書署名 cert のみ。
- 文書署名 leaf の CSR 経由発行 (`issueDocumentSigningCertForPublicKey` は v1 では存在しない)。
- 文書署名 leaf への SAN (`dnsNames` / `ipAddresses` / `emailAddresses`)。
- CAdES / CMS / PAdES / XAdES / ASiC の builder や verifier。EdgCA は文書署名 cert を発行するだけで、document を含む署名 container の生成は別の関心事。
- 公開 certificate parsing API。
- unordered な certificate 候補群からの PKI path building / issuer 自動探索、AIA からの intermediate 取得。
- OS / runtime trust store の参照。trusted root は caller が明示する。
- intermediate を 2 本以上含む CA hierarchy / chain 検証。最大 `root → intermediate → leaf`。
- Cloudflare 固有の textual time parser。certificate DER 内の `UTCTime` / `GeneralizedTime` は verify module が parse するが、`cf.tlsClientAuth.certNotBefore` / `certNotAfter` の文字列変換は application 側。
- CRL、OCSP、失効 DB、失効確認。
- TLS handshake の `CertificateVerify` と TLS connection 自体への proof-of-possession binding。
- nonce、challenge、HTTP message canonicalization、保存、一回限りの消費、リプレイ防止を含む application-layer proof-of-possession protocol。`verifyCertificateSignature` は caller が渡した byte 列の署名検証だけを行う。
- server certificate の hostname / SAN identity 検証。
- 鍵の保管、暗号化保存、Cloudflare storage 連携。
- key の format 変換 (PEM ↔ CryptoKey、JWK ↔ CryptoKey 等)。永続化形式の選択と変換は呼び出し側で WebCrypto API を直接使って行う。
