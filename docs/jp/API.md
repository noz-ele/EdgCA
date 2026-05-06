# EdgCA API

> 日本語 | [English](../en/API.md)

この文書は `edgca` から export される public API のドラフトです。

```ts
import {
  createRootCA,
  issueIntermediateCA,
  issueClientCert,
  importCertificateAuthority,
  verifyClientCertificateIssuedBy,
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

各 subject entry は single-valued RDN として encode されます。入力順序は保持されます。値の ASN.1 string type は属性 OID で決まります。`C` (`2.5.4.6`) は PrintableString、emailAddress (`1.2.840.113549.1.9.1`) は IA5String、それ以外は UTF8String です。短縮名 (`CN`, `O`, ...) と等価な dotted OID 入力でも同じ string type が選ばれます。

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
  privateKeyPem?: string;
}): Promise<CertificateAuthority>;
```

発行される証明書には次を含めます。

- `basicConstraints CA=true`、critical。
- `keyUsage keyCertSign,cRLSign`、critical。
- Subject Key Identifier。
- Authority Key Identifier。

root certificate は self-signed です。返却値の `issuerChainPem` は `""` です。

`pathLenConstraint` 省略時は `1` です。指定できる値は `0` または `1` です。`0` の root CA は client certificate だけを発行でき、intermediate CA は発行できません。

`privateKeyPem` を渡すと、その秘密鍵で root CA を発行します。鍵管理を呼び出し側に寄せるため、長期保管されている鍵を渡す利用形態が推奨です。省略時は内部で鍵を生成します (テスト・PoC 用途)。形式は PKCS#8 PEM (P-256 ECDSA、非暗号化)。

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
  privateKeyPem?: string;
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

`privateKeyPem` を渡すと、その秘密鍵で intermediate CA を発行します。`createRootCA` と同じく、保管済みの鍵を渡す形が推奨です。省略時は内部で鍵を生成します。形式は PKCS#8 PEM (P-256 ECDSA、非暗号化)。

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

private key は certificate の public key と対応している必要があります。正しくない `certPem` (期限切れ・壊れた署名・想定外の extension など) を渡しても error にはならず、入力に従ってそのまま誤った証明書が発行される仕様です。返却値は `createRootCA()` や `issueIntermediateCA()` と同じ `CertificateAuthority` 形状です。

intermediate CA を再 import する場合は、`issuerChainPem` に parent chain を渡します。この chain は client certificate 発行時の `certChainPem` 構築に使われます。

### `verifyClientCertificateIssuedBy(options)`

`options.ca` が `options.certPem` を発行した issuer か判定します。Cloudflare Workers で `request.cf.tlsClientAuth.certRFC9440` を decode した PEM を受け取り、自分の自己 CA が発行した cert かを application 側で確認するための post-handshake な発行元 check です。

> ⚠ **これは mTLS の検証ではなく、提示者の認証もしません。** 単に「証明書が指定 CA で発行されたか」を判定するだけです。client certificate は誰にでも提示できる情報で内容は容易にコピーできるため、証明書情報を持っていることは正当な持ち主であることの根拠になりません。Proof-of-possession には対応する秘密鍵による署名検証が必要ですが、Cloudflare Workers runtime はその署名を公開しません。非 Enterprise プランでは自前 CA に対して `request.cf.tlsClientAuth.certVerified === "SUCCESS"` にもなりません。コピーした証明書を提示する攻撃者はこの check を通過します。本物の認証には Cloudflare Enterprise mTLS、または application 層の challenge-response (nonce を秘密鍵で署名させる) を重ねてください。詳細は [README.md → Verify](README.md#verify-cloudflare-worker) を参照。

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
- `certPem` の signature を `ca.publicKey` で verify できる (ECDSA P-256 / SHA-256)。

PEM や DER として parse 不能な入力は `Error` を投げます (CA 不一致 = `false`、入力破損 = throw、と扱いを分ける)。

#### `validity` option

省略可能な時刻有効性 check。指定された場合のみ評価します。値はすべて呼び出し側が `cf.tlsClientAuth.certNotBefore` / `certNotAfter` から `Date` または epoch milliseconds に変換して渡します (library は cert の `notBefore` / `notAfter` field を参照しません)。

| field | 型 | 必須 | default | 意味と制約 |
| --- | --- | --- | --- | --- |
| `notBefore` | `Date \| number` | ✅ | — | この時刻より前は invalid。`Date` または epoch ms。`NaN` / 非有限値は例外。 |
| `notAfter` | `Date \| number` | ✅ | — | この時刻より後は invalid。同上の制約。`notBefore > notAfter` は例外。 |
| `now` | `Date \| number` | — | `Date.now()` | 比較する現在時刻。テスト・past-time 検証用に明示できる。 |

時刻ウィンドウ外なら identity check を実行せず即 `false` を返します (cert parse・signature verify を skip して expensive な crypto を節約)。`validity` を省略した場合は時刻判定をしません。

#### 使い方 (Cloudflare Worker)

```ts
import { verifyClientCertificateIssuedBy } from "edgca";

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

`verifyClientCertificateIssuedBy` は CA 局判定の `boolean` を返します。それ以外の検証 (時刻、chain、revocation) を表す result type は提供しません。

## Field Reference

このセクションは `types.ts` から export される interface の field を 1 つずつ表で解説します。雛形を作る時、IDE 上で型 signature だけでは default や制約が読み取れないため、ここに参照情報をまとめます。

凡例:

- **必須** 列の `✅` は `?` なし field、`—` は optional field。
- **default** 列は optional 時に内部で適用される値。`—` は「未指定の場合 field 自体が encode されない」を意味する。
- 制約は library が呼び出し時に検査する条件。違反時は `Error` を投げる。

### Options

#### `CreateRootCAOptions`

`createRootCA` の引数。自己署名 root CA を 1 本作るための入力一式を表す。subject DN と有効期間が最低限必要で、配下に intermediate を置くか (`pathLenConstraint`) と既存秘密鍵の持ち込み (`privateKeyPem`) を任意で指定する。新規発行と再現発行 (持ち込み鍵) の両方を 1 つの interface で扱う。

| field | 型 | 必須 | default | 意味と制約 |
| --- | --- | --- | --- | --- |
| `subject` | `Subject` | ✅ | — | root CA の subject DN。配列順序は保持。self-signed のため issuer DN にも同値が入る。詳細は § `Subject` 参照。空配列は不可。 |
| `days` | `number` | ✅ | — | `notBefore` からの有効日数。正の有限数のみ。1 日 = `86_400_000ms` の単純加算 (閏秒なし)。上限の check なし。 |
| `notBefore` | `Date` | — | 呼び出し時刻 (`new Date()`) | validity の開始時刻。1950–2049 は `UTCTime`、それ以外は `GeneralizedTime` で encode。 |
| `serialNumber` | `SerialNumber` | — | CSPRNG 由来 16-byte random (正値、MSB cleared、CAB BR 7.1 の ≥64 bit entropy 要件を満たす) | 発行 cert を issuer 内で識別する integer の**呼び出し側明示指定**。通常は省略して default の random に任せ (Workers の stateless 性と業界標準準拠を両立)、監査・テスト再現性・外部システムからの採番引き継ぎ等で決定的な値が要る時だけ渡す。入力型は § `SerialNumber` 参照。DER encode 後 20 octet を超えると例外。 |
| `pathLenConstraint` | `number` | — | `1` | root CA の下に作れる intermediate の段数。`0` または `1` のみ許容。`0` の root は intermediate を発行できず client cert 専用になる。 |
| `privateKeyPem` | `string` | — | 内部生成 (P-256 ECDSA) | 持ち込み秘密鍵。形式は PKCS#8 PEM、非暗号化。長期保管されている鍵を渡すのが推奨ルート。省略時は WebCrypto で生成 (テスト・PoC 用途の簡便動作)。 |

#### `IssueIntermediateCAOptions`

`issueIntermediateCA` の引数。既存 root CA から intermediate CA を 1 本発行するための入力。`CreateRootCAOptions` との違いは、親となる root を `ca` で渡す点と、intermediate のさらに下に intermediate を置けない設計のため `pathLenConstraint` が実質 `0` 固定である点。

| field | 型 | 必須 | default | 意味と制約 |
| --- | --- | --- | --- | --- |
| `ca` | `CertificateAuthority` | ✅ | — | 親となる root CA。intermediate を親にすると例外。`pathLenConstraint=0` の root を親にしても例外。`isCA=false` または `keyCertSign` なしの cert を渡しても例外。 |
| `subject` | `Subject` | ✅ | — | 発行する intermediate CA の subject DN。 |
| `days` | `number` | ✅ | — | `CreateRootCAOptions.days` と同じ。加えて、issuer の `notAfter` を超える指定をしても library は止めない (verifier 側で reject される cert ができる)。 |
| `notBefore` | `Date` | — | 呼び出し時刻 | `CreateRootCAOptions.notBefore` と同じ。 |
| `serialNumber` | `SerialNumber` | — | CSPRNG 由来 16-byte random | `CreateRootCAOptions.serialNumber` と同じ。 |
| `pathLenConstraint` | `number` | — | `0` | 発行される intermediate の `pathLenConstraint` は常に `0`。明示する場合は `0` のみ許容、`1` 以上は例外。 |
| `privateKeyPem` | `string` | — | 内部生成 | `CreateRootCAOptions.privateKeyPem` と同じ (intermediate CA の鍵を渡す)。 |

#### `IssueClientCertOptions`

`issueClientCert` の引数。mTLS 用 client certificate を 1 本発行するための入力。`ca` で issuer を指定する (root / intermediate のどちらでも可)。client cert の秘密鍵は短命利用を前提に常に内部生成されるため、CA 用 options と違って `privateKeyPem` を受け付けない。SAN は任意で、未指定なら extension 自体が省略される。

| field | 型 | 必須 | default | 意味と制約 |
| --- | --- | --- | --- | --- |
| `ca` | `CertificateAuthority` | ✅ | — | 発行 issuer。root または intermediate どちらでも可。`isCA=false` または `keyCertSign` なしの cert を渡すと例外。 |
| `subject` | `Subject` | ✅ | — | 発行する client cert の subject DN。 |
| `days` | `number` | ✅ | — | `CreateRootCAOptions.days` と同じ。 |
| `notBefore` | `Date` | — | 呼び出し時刻 | `CreateRootCAOptions.notBefore` と同じ。 |
| `serialNumber` | `SerialNumber` | — | CSPRNG 由来 16-byte random | `CreateRootCAOptions.serialNumber` と同じ。 |
| `dnsNames` | `string[]` | — | `undefined` | SAN dNSName。指定時のみ SAN extension が出力される。RFC 1035 §2.3.1 preferred name syntax: 各 label は `[A-Za-z0-9]` で始終端し内部に `-` 可、label 長 ≤63 chars、全長 ≤253 chars、先頭の `*.` ワイルドカード可。違反は例外。 |
| `ipAddresses` | `string[]` | — | `undefined` | SAN iPAddress。IPv4 / IPv6 文字列。`dnsNames` と併用可。両者未指定なら SAN extension 自体が省略される。 |

`issueClientCert` は client cert の秘密鍵を**常に内部生成**するため、`privateKeyPem` option はない。client cert の鍵は ephemeral 想定。

#### `ImportCertificateAuthorityOptions`

`importCertificateAuthority` の引数。永続化された CA 情報 (cert PEM + 秘密鍵 PEM、必要なら親 chain) を再構成して `CertificateAuthority` instance に戻すための入力。新規 CA を作るのではなく、保存済み CA を Workers の起動時に読み込んで以降の発行に使う運用で利用する。

| field | 型 | 必須 | default | 意味と制約 |
| --- | --- | --- | --- | --- |
| `certPem` | `string` | ✅ | — | import する CA certificate PEM。先頭の `BEGIN CERTIFICATE` block を読む。 |
| `privateKeyPem` | `string` | ✅ | — | `certPem` に対応する PKCS#8 PEM 秘密鍵 (非暗号化)。public key と sign/verify で一致確認する。一致しない場合は例外。 |
| `issuerChainPem` | `string` | — | `""` (空) | import 対象が intermediate CA の時、その親 chain の PEM。client cert 発行時の `certChainPem` 構築に使われる。複数 `CERTIFICATE` block を改行で連結して渡す。空文字列の場合 root として扱われる。 |

### Results

#### `CertificateAuthority`

CA を「秘密鍵 + 自 cert + 上位 chain」の 3 点で 1 つにまとめた instance 型。`createRootCA` / `issueIntermediateCA` / `importCertificateAuthority` の戻り値で、そのまま `issueIntermediateCA` / `issueClientCert` の `ca` 引数に渡せる。発行関数が必要とする状態をすべて 1 つに束ねたハンドルとして扱う。永続化する時は `certPem` / `privateKeyPem` / `issuerChainPem` の 3 つを保存し、復元時は `importCertificateAuthority` に渡す。

| field | 型 | 意味 |
| --- | --- | --- |
| `certPem` | `string` | 自 CA certificate の PEM (`CERTIFICATE` block)。 |
| `privateKeyPem` | `string` | 自 CA 秘密鍵の PKCS#8 PEM、非暗号化。 |
| `publicKeyPem` | `string` | 自 CA 公開鍵の SPKI PEM。 |
| `certDer` | `Uint8Array` | 自 CA certificate の DER bytes。`certPem` を decode したものと等価。 |
| `privateKey` | `CryptoKey` | WebCrypto `CryptoKey` instance。`["sign"]` 用途、extractable。 |
| `publicKey` | `CryptoKey` | WebCrypto `CryptoKey` instance。`["verify"]` 用途。 |
| `issuerChainPem` | `string` | 上位 CA chain の PEM。root CA では `""`。intermediate CA では root の PEM。複数 CA を含む場合は改行区切り。 |

#### `IssuedClientCertificate`

`issueClientCert` の戻り値。発行された client cert を「秘密鍵 + cert + 完全 chain」の 3 点で返す型。CA 用途は想定されないため、追加発行に使い回すことはできない (再 import すると `CertificateAuthority` にはなるが、`issueClientCert` が出力するのは leaf cert なので発行 issuer として機能しない)。verifier に提示する完成形 chain が `certChainPem` に入っている。

| field | 型 | 意味 |
| --- | --- | --- |
| `certPem` | `string` | client certificate の PEM。 |
| `privateKeyPem` | `string` | client 秘密鍵の PKCS#8 PEM、非暗号化。 |
| `publicKeyPem` | `string` | client 公開鍵の SPKI PEM。 |
| `certDer` | `Uint8Array` | client cert の DER bytes。 |
| `privateKey` | `CryptoKey` | WebCrypto `CryptoKey`。`["sign"]` 用途、extractable。 |
| `publicKey` | `CryptoKey` | WebCrypto `CryptoKey`。`["verify"]` 用途。 |
| `certChainPem` | `string` | leaf + issuer + issuerChain を改行で連結した完全 chain。intermediate 経由で発行した場合は `client + intermediate + root` の順。 |

### `SubjectAttribute`

`Subject` を構成する 1 entry。X.509 cert の Subject DN (Distinguished Name) は複数の attribute を順番に並べた構造で、その 1 つを `{ type, value }` で表現する。EdgCA は `CN=foo,O=Example` のような DN 文字列入力を受け付けず、必ずこの structured な配列で渡す設計。multi-valued RDN (1 つの RDN に複数 attribute) も非対応で、1 entry = 1 RDN。

| field | 型 | 必須 | 意味と制約 |
| --- | --- | --- | --- |
| `type` | `SubjectAttributeType` | ✅ | attribute の種別。短縮名 (`CN`, `O`, `OU`, `C`, `ST`, `L`, `E`, `DC`, `SERIALNUMBER`, `STREET`, `POSTALCODE`, `TITLE`, `GIVENNAME`, `SURNAME`, `UID`) または dotted OID 文字列 (`1.2.3.4.5`)。未対応の短縮名・不正な OID は例外。 |
| `value` | `string` | ✅ | attribute の値。OID に応じて string type を選択 (`C` → PrintableString、emailAddress → IA5String、他 → UTF8String)。短縮名と等価な dotted OID でも同じ規則。`C` の値が PrintableString として不正な場合は例外。emailAddress の値が IA5 (ASCII) として不正な場合も例外。 |

### `SerialNumber` 入力形式

`SerialNumber` は cert の serial number を呼び出し側で明示する時に使う union 型 alias (`bigint | number | string | Uint8Array`)。明示する場面は限られ、通常は省略して library の random 生成 (16-byte) に任せる。決定的な値を要求する監査要件、再現性が必要なテスト、外部システムが採番する serial を引き継ぐ場合などで指定する。入力型ごとの解釈は次のとおり。

| 入力型 | 解釈 | 制約 |
| --- | --- | --- |
| 省略 | 16-byte random、MSB を clear して正値化 | — |
| `bigint` | そのまま integer encode | DER encode 後 20 octet 以内 |
| `number` | そのまま integer encode | 同上 |
| `string` (`/^\d+$/`) | decimal として `BigInt` 変換 | 同上 |
| `string` (hex) | 偶数桁化して bytes として読む | 同上 |
| `Uint8Array` | bytes 列として直接利用 | 1 byte 以上、20 byte 以内 |

## Non-Goals

EdgCA は次を提供しません。

- server certificate 発行。
- 公開 certificate parsing API。
- certificate chain validation (chain 遡及・PKI path building)。`verifyClientCertificateIssuedBy` は直接の発行者 1 本に対する identity 確認に限定。
- cert からの時刻 field の抽出。`verifyClientCertificateIssuedBy` の `validity` option は時刻 check を提供するが、`notBefore` / `notAfter` は呼び出し側が外から渡す (`cf.tlsClientAuth.certNotBefore` / `certNotAfter` を `Date` に変換するのは application 側)。
- CRL、OCSP、失効 DB、失効確認。
- 鍵の保管、暗号化保存、Cloudflare storage 連携。
