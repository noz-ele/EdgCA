# EdgCA API

この文書は `edgca` から export される public API のドラフトです。

```ts
import {
  createRootCA,
  issueIntermediateCA,
  issueClientCert,
  importCertificateAuthority,
  certificateToPem,
  pemToDer,
  privateKeyToPem,
  publicKeyToPem
} from "edgca";
```

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

各 subject entry は single-valued RDN として encode されます。入力順序は保持されます。値は UTF8String として encode され、`C` のみ PrintableString になります。

DN 文字列入力と multi-valued RDN は対応しません。

### `CertificateAuthority`

```ts
interface CertificateAuthority {
  certPem: string;
  privateKeyPem: string;
  publicKeyPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  issuerChainPem: string;
}
```

`issuerChainPem` は、その CA より上位の PEM chain です。root CA では空文字列です。root から発行した intermediate CA では root certificate PEM が入ります。

EdgCA が扱う CA 階層は最大で `root CA -> intermediate CA -> client certificate` です。intermediate CA からさらに intermediate CA を発行する chain は対象外です。

### `IssuedClientCertificate`

```ts
interface IssuedClientCertificate {
  certPem: string;
  privateKeyPem: string;
  publicKeyPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  certChainPem: string;
}
```

`certChainPem` は `leaf + issuer + issuerChain` の順で出力されます。root から作成した intermediate で client certificate を発行した場合は、`client + intermediate + root` になります。

### `SerialNumber`

```ts
type SerialNumber = bigint | number | string | Uint8Array;
```

省略時は、正のランダムな 16-byte serial number を生成します。

決定的な serial number が必要な場合は、`bigint`、`number`、または `Uint8Array` の利用を推奨します。`string` は decimal digits または hexadecimal text として扱われます。

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
}): Promise<CertificateAuthority>;
```

発行される証明書には次を含めます。

- `basicConstraints CA=true`、critical。
- `keyUsage keyCertSign,cRLSign`、critical。
- Subject Key Identifier。
- Authority Key Identifier。

root certificate は self-signed です。返却値の `issuerChainPem` は `""` です。

`pathLenConstraint` 省略時は `1` です。指定できる値は `0` または `1` です。`0` の root CA は client certificate だけを発行でき、intermediate CA は発行できません。

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

### `importCertificateAuthority(options)`

CA certificate と private key を import し、後続の発行に使える `CertificateAuthority` として返します。

```ts
function importCertificateAuthority(options: {
  certPem: string;
  privateKeyPem: string;
  issuerChainPem?: string;
}): Promise<CertificateAuthority>;
```

private key は certificate の public key と対応している必要があります。返却値は `createRootCA()` や `issueIntermediateCA()` と同じ `CertificateAuthority` 形状です。

intermediate CA を再 import する場合は、`issuerChainPem` に parent chain を渡します。この chain は client certificate 発行時の `certChainPem` 構築に使われます。

### `certificateToPem(der)`

DER certificate bytes を PEM certificate block に encode します。

```ts
function certificateToPem(der: Uint8Array): string;
```

### `pemToDer(pem)`

文字列内の最初の PEM block を DER bytes に decode します。

```ts
function pemToDer(pem: string): Uint8Array;
```

### `privateKeyToPem(key)`

private `CryptoKey` を PKCS#8 PEM として export します。

```ts
function privateKeyToPem(key: CryptoKey): Promise<string>;
```

対象 key は extractable である必要があります。

### `publicKeyToPem(key)`

public `CryptoKey` を SPKI PEM として export します。

```ts
function publicKeyToPem(key: CryptoKey): Promise<string>;
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

公開 verification result type はありません。証明書検証は public API の責務ではありません。

## Non-Goals

EdgCA は次を提供しません。

- server certificate 発行。
- 公開 certificate parsing API。
- certificate chain validation。
- runtime certificate verification。
- CRL、OCSP、失効 DB、失効確認。
- 鍵の保管、暗号化保存、Cloudflare storage 連携。
- 汎用 PKI path building。
