# EdgCA

EdgCA は、Cloudflare Workers 互換の runtime で、利用者自身が管理する自己 CA から mTLS 用 client certificate を発行するための小さな TypeScript ライブラリです。

目的は明確に絞っています。

- 自己署名 root CA を作る。
- root CA から intermediate CA を発行する。
- intermediate CA から mTLS 用 client certificate と秘密鍵を発行する。
- 証明書と鍵を PEM/DER で入出力する。
- 暗号演算は `globalThis.crypto.subtle` に委譲する。

EdgCA は汎用 PKI ライブラリではありません。server certificate 発行、公開検証 API、証明書チェーン検証 API、失効情報管理、鍵の保管方法は提供しません。

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
- PEM/DER helper。
- Basic Constraints、Key Usage、Extended Key Usage、Subject Alternative Name、SKI、AKI。

意図的に対象外:

- server certificate 発行。
- 公開 certificate verification API。
- 公開 chain validation API。
- CRL、OCSP、失効 DB、失効確認。
- 鍵の保管、暗号化保存、ローテーション永続化、KV/D1/R2/Secrets 連携。
- RSA、EdDSA、別 elliptic curve。
- DN 文字列 parsing。
- multi-valued RDN。

## Key Handling

このライブラリは秘密鍵 PEM を返すため、生成鍵は extractable です。

EdgCA は鍵の生成と import/export だけを扱います。鍵をどこに保存するか、保存時にどう暗号化するか、ローテーション状態をどう永続化するか、Cloudflare storage products とどう連携するかは application 側の責務です。

## Development

```sh
npm run typecheck
npm run build
npm run test
npm audit
```

テストは `@cloudflare/vitest-pool-workers` を使い、Workers 互換 runtime 上で WebCrypto の挙動を確認します。

## API Documentation

詳しくは [docs/API.md](docs/API.md) を参照してください。

実装開始時点の計画は [docs/PLAN_HISTORY.md](docs/PLAN_HISTORY.md) に履歴として残しています。
