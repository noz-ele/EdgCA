# EdgCA

EdgCA は、Cloudflare Workers 互換の runtime で、利用者自身が管理する自己 CA から mTLS 用 client certificate を発行するための小さな TypeScript ライブラリです。

目的は明確に絞っています。

- 自己署名 root CA を作る。
- root CA から intermediate CA を発行する。
- intermediate CA から mTLS 用 client certificate と秘密鍵を発行する。
- 受け取った client certificate が自分の CA から発行されたかを判定する。
- 証明書と鍵を PEM/DER で入出力する。
- 暗号演算は `globalThis.crypto.subtle` に委譲する。

EdgCA は汎用 PKI ライブラリではありません。server certificate 発行、証明書チェーン検証 API、失効情報管理、鍵の保管方法は提供しません。

## Install

この package は現時点ではこのリポジトリ内のローカル package です。

```sh
npm install
npm run build
```

## Quick Start

```ts
import {
  createRootCA,
  issueIntermediateCA,
  issueClientCert
} from "edgca";

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

console.log(client.certPem);
console.log(client.privateKeyPem);
console.log(client.certChainPem);
```

基本形は次の構造です。

```text
root CA -> intermediate CA -> mTLS client certificate
```

EdgCA の CA 階層はこの形を最大とし、intermediate CA からさらに intermediate CA を発行する chain は対象外です。

`client.certChainPem` は次の順で出力されます。

```text
client certificate
issuer certificate
issuer chain
```

EdgCA で作成した intermediate から client certificate を発行した場合は、`client + intermediate + root` の順になります。

## Verify (Cloudflare Worker)

このセクションは、**Cloudflare 側で client certificate が抽出済み**で、その値が `request.cf.tlsClientAuth` 経由で application に渡される運用を前提にしています。EdgCA は TLS handshake にも cert の DER parse にも関与せず、Cloudflare が露出した値を入力として受け取って identity 判定を行います。

### Cloudflare が抽出した場合に渡される形式

| field | 形式 | 例 |
|---|---|---|
| `certVerified` | mTLS 検証結果の文字列 | `"SUCCESS"` / `"FAILED:..."` / `"NONE"` |
| `certRFC9440` | RFC 9440 Structured Field Item (Byte Sequence)。前後を `:` で囲んだ base64 | `":MIIB...:"` |
| `certNotBefore` / `certNotAfter` | OpenSSL 風 textual 形式 (常に GMT)。単桁日は二重スペース | `"Dec 24 23:59:59 2025 GMT"` / `"Dec  4 23:59:59 2025 GMT"` |
| `certSubjectDN`, `certIssuerDN`, `certSerial` 等 | 文字列 | identity 抽出用 |

EdgCA `verifyClientCertificateIssuedBy` が直接受け取れるのは PEM (`certPem: string`) と `Date` / epoch ms (`validity.notBefore` / `notAfter`) です。上記 Cloudflare 提供の形式とは**一致しないため、application 側で形式変換が必要**です。具体的には:

- `certRFC9440` の `":...:"` → 前後コロンを外して PEM marker で挟む。
- `certNotBefore` / `certNotAfter` の textual 文字列 → `new Date(...)` で `Date` に変換 (V8/Workers runtime はこの形式を parse できる)。

これらの parser を library 側に持たないのは、Cloudflare の出力形式変更に追従しないこと、runtime 依存の `Date.parse` 寛容性に巻き込まれないこと、caller が既に値を保持しているため二重実装する意味がないことが理由です (詳細は [docs/NON_GOALS.md](docs/NON_GOALS.md))。

### 例

```ts
import { importCertificateAuthority, verifyClientCertificateIssuedBy } from "edgca";

// Worker 起動時 (vault 等から読み込んだ CA を一度 import しておく)
const ca = await importCertificateAuthority({
  certPem: env.CA_CERT_PEM,
  privateKeyPem: env.CA_PRIVATE_KEY_PEM
});

export default {
  async fetch(request: Request): Promise<Response> {
    const tls = request.cf?.tlsClientAuth;
    if (!tls || tls.certVerified !== "SUCCESS") {
      return new Response("mTLS required", { status: 401 });
    }

    // Cloudflare 形式 → library 形式への変換
    //   certRFC9440 (":base64:")        → PEM 文字列
    //   certNotBefore / certNotAfter    → Date
    const b64 = tls.certRFC9440.replace(/^:|:$/g, "");
    const certPem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;

    const ok = await verifyClientCertificateIssuedBy({
      ca,
      certPem,
      validity: {
        notBefore: new Date(tls.certNotBefore),
        notAfter:  new Date(tls.certNotAfter)
        // now を省略すると Date.now() が使われる
      }
    });
    if (!ok) {
      return new Response("not issued by us, or expired", { status: 403 });
    }

    // 認可ロジック: cf.tlsClientAuth.certSubjectDN などから identity を抽出して使う
    return new Response(`hello, ${tls.certSubjectDN}`);
  }
};
```

### 補足

- `validity` を省略すると identity 判定 (発行者 DN + AKI/SKI + signature) のみ行います。時刻を library 関数では見ず application 側で 2 行比較する場合も、結果は等価です。
- 「自 CA から発行されてない」「ウィンドウ外」は `false` 戻り値、入力 PEM/DER が壊れている等の不正入力は throw。エラー扱いを 2 段階に分けています。
- `ca` には**直接の発行者 1 本**を渡してください。intermediate を介して発行した leaf を root に対して投げると `false` になります (chain 遡及はしません)。

## Subject

subject は構造化入力のみ受け付けます。`CN=dev-root,O=Example` のような DN 文字列は受け付けません。

```ts
const subject = [
  { type: "CN", value: "dev-root" },
  { type: "O", value: "Example" },
  { type: "1.2.3.4.5", value: "custom-value" }
];
```

対応する短縮名:

```text
CN, O, OU, C, ST, L, E, DC, SERIALNUMBER, STREET,
POSTALCODE, TITLE, GIVENNAME, SURNAME, UID
```

dotted OID 文字列も受け付けます。値の ASN.1 文字列型は UTF8String 固定で、`C` のみ PrintableString です。multi-valued RDN は対象外です。

## Scope

実装対象:

- ECDSA P-256 + SHA-256。
- WebCrypto による鍵生成、署名、digest、key import/export。
- root CA 作成。
- intermediate CA 発行。
- mTLS client certificate 発行。
- 自己 CA からの発行かを判定する identity 確認 API (`verifyClientCertificateIssuedBy`、任意の時刻有効性 check 付き)。
- PEM/DER helper。
- Basic Constraints、Key Usage、Extended Key Usage、Subject Alternative Name、SKI、AKI。

意図的に対象外:

- server certificate 発行。
- 公開 chain validation API。
- cert からの時刻 field の抽出。`verifyClientCertificateIssuedBy` の `validity` option は時刻 check 自体は提供するが、`notBefore` / `notAfter` 値は呼び出し側が `cf.tlsClientAuth` から渡す。
- CRL、OCSP、失効 DB、失効確認。
- 鍵の保管、暗号化保存、ローテーション永続化、KV/D1/R2/Secrets 連携。
- RSA、EdDSA、別 elliptic curve。
- DN 文字列 parsing。
- multi-valued RDN。

## Key Handling

このライブラリは秘密鍵 PEM を返すため、生成鍵は extractable です。

EdgCA は鍵の生成と import/export だけを扱います。鍵をどこに保存するか、保存時にどう暗号化するか、ローテーション状態をどう永続化するか、Cloudflare storage products とどう連携するかは application 側の責務です。

### CA 鍵の持ち込み (推奨)

root CA と intermediate CA は長期保管が前提です。鍵管理を呼び出し側に寄せるため、`createRootCA` と `issueIntermediateCA` は既に保管されている秘密鍵を `privateKeyPem` で受け取れます。鍵のライフサイクル (生成・保管・ローテーション) を呼び出し側の鍵管理基盤で一貫して扱えるため、こちらが推奨ルートです。

```ts
const root = await createRootCA({
  subject: [{ type: "CN", value: "dev-root" }],
  days: 3650,
  privateKeyPem: loadFromVault("root")    // 既に保管されている PKCS#8 PEM
});

const intermediate = await issueIntermediateCA({
  ca: root,
  subject: [{ type: "CN", value: "dev-intermediate" }],
  days: 365,
  privateKeyPem: loadFromVault("intermediate")
});
```

`privateKeyPem` を省略した場合は内部で鍵を生成します。テストや PoC 用途の簡便動作です。client certificate の鍵は ephemeral 想定のため `issueClientCert` では常に内部生成です。

## Development

```sh
npm run typecheck
npm run build
npm run test
npm audit
```

テストは `@cloudflare/vitest-pool-workers` を使い、Workers 互換 runtime 上で WebCrypto の挙動を確認します。

### Property-based tests

低 layer の round-trip 不変条件は `fast-check` を使った property-based test として、対象モジュール 1 ファイルずつ分けて `test/<module>.property.test.ts` に置いています。

- [test/der.property.test.ts](test/der.property.test.ts) — INTEGER / OID / OCTET STRING / BIT STRING / SEQUENCE の TLV round-trip
- [test/bytes.property.test.ts](test/bytes.property.test.ts) — `concatBytes`、`binaryToBytes`/`bytesToBinary`、`bytesEqual`、`cloneBytes`
- [test/ip.property.test.ts](test/ip.property.test.ts) — IPv4 dotted-quad と IPv6（full form / `::` compression）の encode
- [test/pem.property.test.ts](test/pem.property.test.ts) — `certificateToPem` / `privateKeyDerToPem` / `publicKeyDerToPem` と `pemToDer` / `pemToDerWithLabel` / `splitPemBlocks` の round-trip

`vitest.config.ts` の include は `test/**/*.test.ts` なので `npm run test` で同時に走ります。`cert` 組み立て層（`ca.ts` / `x509.ts`）は scope 上 PBT 対象外で、example-based のまま [test/edgca.test.ts](test/edgca.test.ts) に集約しています。

## API Documentation

詳しくは [docs/API.md](docs/API.md) を参照してください。

実装開始時点の計画は [docs/PLAN_HISTORY.md](docs/PLAN_HISTORY.md) に履歴として残しています。
