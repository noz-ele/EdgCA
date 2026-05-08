# EdgCA

> 日本語 | [English](../../README.md)

EdgCA は、Cloudflare Workers 互換の runtime で、利用者自身が管理する自己 CA から mTLS 用 client certificate を発行するための小さな TypeScript ライブラリです。

目的は明確に絞っています。

- 自己署名 root CA を作る。
- root CA から intermediate CA を発行する。
- intermediate CA から mTLS 用 client certificate と秘密鍵を発行する。
- 受け取った client certificate が自分の CA から発行されたかを判定する。
- 証明書と鍵を PEM/DER で入出力する。
- 発行済み証明書 + 秘密鍵を password 付き PFX (PKCS#12) として OS 証明書ストア取り込み用に出力する (Win11+、macOS 15+、iOS/iPadOS 18+、modern Linux consumer 向け)。
- 暗号演算は `globalThis.crypto.subtle` に委譲する。

> ⚠ **PKI runtime ではありません。** EdgCA は発行 toolkit であり、汎用 PKI library や runtime ではありません。chain validation、失効確認 (CRL/OCSP)、鍵保管、ローテーションは**提供しません**。`verifyClientCertificateIssuedBy` は **mTLS 検証ではなく**、提示者の認証も**しません** — 詳細は下の [Verify](#verify-cloudflare-worker) 参照。CA を安全に運用するのは caller の責任です。完全な対象外 list は [NON_GOALS.md](NON_GOALS.md)。

## Status

EdgCA は **v0.2.x の初期安定化フェーズ**です。作者が実際の Cloudflare Workers 環境で検証している最中で、API が変わる可能性があります。検証に集中するため、**外部からの Issue と PR は一時的に制限**しており、API が落ち着いた後に再開します。read / clone / fork / `npm install` は通常通り可能です。

## Install

```sh
npm install @noz-ele/edgca
```

ESM 専用 (`"type": "module"`) で、`globalThis.crypto.subtle` が動く runtime (Cloudflare Workers、Node.js 20+、modern browser 等) で動作します。CommonJS からの `require` は対象外です。

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

// secrets manager / KV / vault に保管する想定。
// `client.privateKey` は CryptoKey。永続化する場合は
// crypto.subtle.exportKey("pkcs8", client.privateKey) などで自分で取り出し、
// 取り出したバイト列を秘密情報として扱う (log や転送に出さない)。
//   client.certPem        — 公開してよい証明書
//   client.certChainPem   — mTLS で提示する完全 chain
//   client.privateKey     — 秘密の CryptoKey。trusted channel でのみ受け渡す
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

### 発行済み証明書 + 鍵を PFX (PKCS#12) として束ねる

OS の証明書ストア (Windows、macOS、iOS) は password 付きの単一の `.pfx` (= `.p12`) ファイルで「leaf cert + 任意の chain + 暗号化された秘密鍵」を取り込みます。`exportPkcs12` は `IssuedClientCertificate` からその形式を組み立てます。

```ts
import { exportPkcs12 } from "@noz-ele/edgca/pkcs12";

const pfxBytes = await exportPkcs12({
  certDer: client.certDer,
  chainDer: [intermediate.certDer, root.certDer],   // 任意
  privateKey: client.privateKey,                     // CryptoKey、extractable 必須
  password: new TextEncoder().encode(passwordString),
  friendlyName: new TextEncoder().encode("worker-client") // 任意、BMPString として埋め込まれる
});
// pfxBytes は Uint8Array — disk に書き出す、download trigger に渡す、または
// tls.createSecureContext({ pfx: Buffer.from(pfxBytes), passphrase: passwordString }) に渡す。
```

password は UTF-8 の `Uint8Array` で受け取ります (`string` 不可)。秘密のバイト列を JS の immutable な string heap に置かずに済ませるための設計です。PBKDF2 反復回数の default は 600 000、MAC KDF の default は 100 000 で、OWASP と OpenSSL 3 の推奨値に合わせていますが、引数で上書きできます。

実装は環境依存なし (WebCrypto のみ、Node 固有 API なし) なので、PFX の組み立ては **サーバ側、Cloudflare Worker、ブラウザのいずれでも同じコードで動きます**。よくある構成は CA をサーバに置き、ブラウザでは鍵ペアをローカル生成 → CSR をサーバに送って cert をもらう → ブラウザ側で PFX に組み立てる、というもの。秘密鍵と password が通信路に乗りません。

`@noz-ele/edgca/pkcs12` という subpath が用意されているので、PFX 組み立てだけ使いたい consumer は CA / CSR / verify モジュールを引き込まずに import できます。

## Verify (Cloudflare Worker)

> ⚠ **この関数で出来ること・出来ないこと**
>
> `verifyClientCertificateIssuedBy` は **mTLS の検証ではありません** (そもそもこの構成では mTLS 検証自体が成立しません)。せいぜい *発行元検証* に留まります。すなわち「提示された証明書が指定 CA 局で発行されたか」を確認するだけで、これは「証明書を提示した相手が正当な持ち主であるかの認証」とは**まったく別物**です。
>
> client certificate はそもそも誰にでも提示してよい情報なので、内容は容易にコピーできます。**「誰でも client certificate の情報は持ち得る」と仮定しなければなりません**。したがって証明書情報を持っているという事実は、正当な持ち主であることの根拠には**絶対になりません**。
>
> 正当な持ち主であることを確認するには、加えて対応する秘密鍵を所持していることの確認 — すなわち秘密鍵で署名された情報を証明書中の公開鍵で検証する作業 — が必要です。通常の TLS handshake では client が `CertificateVerify` message でこれを行いますが、**Cloudflare Workers の runtime はこの署名を application に公開しません**。また Enterprise プラン以外では Cloudflare 自身の TLS レイヤーも自前 CA を知らないため、EdgCA で発行した証明書に対して `request.cf.tlsClientAuth.certVerified === "SUCCESS"` になることはありません。Workers 上の application code が proof-of-possession を検証する手段は (Enterprise プランを除き) 存在しません。
>
> 実用上の含意: どこかで (log、漏洩 storage、handshake 中のネットワーク観測など) 有効な証明書のコピーを入手した攻撃者は、それを提示してこの check を通過できます。この関数は *最低限の identity check の 1 層* として使うものであり、認証としては使えません。本物の認証には (a) Cloudflare Enterprise で TLS レイヤー mTLS を使うか、(b) server が発行した nonce を client が秘密鍵で署名して返す application layer の challenge-response を追加してください。
>
> その他の対象外 (この関数では検証しません): `BasicConstraints CA=false`、`EKU clientAuth`、失効確認、chain walking。

このセクションは、**Cloudflare 側で client certificate が抽出済み**で、その値が `request.cf.tlsClientAuth` 経由で application に渡される運用を前提にしています。EdgCA は TLS handshake にも cert の DER parse にも関与せず、Cloudflare が露出した値を入力として受け取って上記の発行元判定を行います。

### Cloudflare が抽出した場合に渡される形式

| field | 形式 | 例 |
| --- | --- | --- |
| `certPresented` | 提示の有無 | `"1"` / `"0"` |
| `certVerified` | TLS レイヤーの検証結果文字列。**自前 CA + 非 Enterprise プランでは `"SUCCESS"` にはなりません** (TLS レイヤーが自前 CA を知らないため)。 | `"SUCCESS"` / `"FAILED:..."` / `"NONE"` |
| `certRFC9440` | RFC 9440 Structured Field Item (Byte Sequence)。前後を `:` で囲んだ base64 | `":MIIB...:"` |
| `certNotBefore` / `certNotAfter` | OpenSSL 風 textual 形式 (常に GMT)。単桁日は二重スペース | `"Dec 24 23:59:59 2025 GMT"` / `"Dec  4 23:59:59 2025 GMT"` |
| `certSubjectDN`, `certIssuerDN`, `certSerial` 等 | 文字列 | identity 抽出用 |

EdgCA `verifyClientCertificateIssuedBy` が直接受け取れるのは PEM (`certPem: string`) と `Date` / epoch ms (`validity.notBefore` / `notAfter`) です。上記 Cloudflare 提供の形式とは**一致しないため、application 側で形式変換が必要**です。具体的には:

- `certRFC9440` の `":...:"` → 前後コロンを外して PEM marker で挟む。
- `certNotBefore` / `certNotAfter` の textual 文字列 → `new Date(...)` で `Date` に変換 (V8/Workers runtime はこの形式を parse できる)。

これらの parser を library 側に持たないのは、Cloudflare の出力形式変更に追従しないこと、runtime 依存の `Date.parse` 寛容性に巻き込まれないこと、caller が既に値を保持しているため二重実装する意味がないことが理由です (詳細は [NON_GOALS.md](NON_GOALS.md))。

### 例

```ts
import { importCertificateAuthority, pemToDer, verifyClientCertificateIssuedBy } from "@noz-ele/edgca";

// Worker 起動時 (vault 等から読み込んだ CA を一度 import しておく)。
// 秘密鍵は CryptoKey でしか受け取らないので、永続化形式
// (PKCS#8 PEM、JWK、生バイト列など) を application 側で CryptoKey に変換する。
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
    // 注意: 自前 CA + 非 Enterprise では tls.certVerified !== "SUCCESS" が通常。
    // 発行元判定は下の関数で application 側が行う。

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

    // 念のため: この check が通っても、提示者が秘密鍵を保有しているとは限らない。
    // 本物の認証には別途 nonce を秘密鍵で署名させる challenge-response を重ねる。

    // 認可ロジック: cf.tlsClientAuth.certSubjectDN などから identity を抽出して使う
    return new Response(`hello, ${tls.certSubjectDN}`);
  }
};
```

### 補足

- `validity` を省略すると identity 判定 (発行者 DN + AKI/SKI + signature) のみ行います。時刻を library 関数では見ず application 側で 2 行比較する場合も、結果は等価です。
- 「自 CA から発行されてない」「ウィンドウ外」は `false` 戻り値、入力 PEM/DER が壊れている等の不正入力は throw。エラー扱いを 2 段階に分けています。
- `ca` には**直接の発行者 1 本**を渡してください。intermediate を介して発行した leaf を root に対して投げると `false` になります (chain 遡及はしません)。

## CSR から発行する

client が秘密鍵を自分で管理し PKCS#10 CSR を送ってくる場合、EdgCA は CSR を parse し、所持証明 (POP) 署名を検証し、CSR 内の公開鍵を埋めた証明書を発行できます。CSR が主張する subject / SAN は **library が自動採用しません** — 発行内容は呼び出し側が application 層のポリシーに従って明示的に渡します。

```ts
import {
  issueClientCertForPublicKey,
  parseCertificateSigningRequest,
  verifyCertificateSigningRequestSignature
} from "@noz-ele/edgca";

const csr = await parseCertificateSigningRequest(csrPemFromClient);
if (!await verifyCertificateSigningRequestSignature(csr)) {
  return new Response("CSR proof-of-possession failed", { status: 400 });
}

// CSR の主張は csr.subject / csr.requestedDnsNames / csr.requestedIpAddresses
// で参照できるが、それを発行値として採用するかは application 層のポリシー判断。
const issued = await issueClientCertForPublicKey({
  ca,
  publicKey: csr.publicKey,
  subject: policyDerivedSubject,
  days: 30,
  dnsNames: policyDerivedDnsNames
});
// issued には certPem / certDer / certChainPem のみが入る (privateKey は無い、client が保持しているため)。
```

`ecdsa-with-SHA256` / `ecdsa-with-SHA384` / `ecdsa-with-SHA512` 以外で署名された CSR は parse 時に明示エラーで reject されます。`extensionRequest` 以外の CSR-level attributes は raw DER として `csr.otherAttributes` に、SAN 以外の X.509 extensions は `csr.requestedExtensions` に `{ oid, critical, valueDer }` 形式で露出するので、必要なら呼び出し側で decode します。

POP 検証は **「CSR を作った主体が対応する秘密鍵を持っている」しか証明しません**。発行可否 (subject/SAN の妥当性、enrollment の認可) は EdgCA の範囲外で、application 層と組み合わせて判断してください。

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

- ECDSA NIST P-256 / P-384 / P-521 (それぞれ SHA-256 / SHA-384 / SHA-512 と組み合わせ)。
- WebCrypto による鍵生成、署名、digest、key import/export。
- root CA 作成。
- intermediate CA 発行。
- mTLS client certificate 発行 (内部鍵生成、または持ち込み公開鍵から発行)。
- CSR (PKCS#10) の parse と所持証明 (POP) 署名検証。
- 自己 CA からの発行かを判定する identity 確認 API (`verifyClientCertificateIssuedBy`、任意の時刻有効性 check 付き)。
- PEM/DER helper (証明書のみ — 鍵は CryptoKey でやり取り)。
- 発行済み証明書 + 秘密鍵の PFX (PKCS#12) export。PBES2 (PBKDF2-HMAC-SHA-256 + AES-256-CBC) と HMAC-SHA-256 MAC で構成し、対象は Win11+ / Server 2019+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux consumer。
- Basic Constraints、Key Usage、Extended Key Usage、Subject Alternative Name、SKI、AKI。

意図的に対象外:

- server certificate 発行。
- 公開 chain validation API。
- cert からの時刻 field の抽出。`verifyClientCertificateIssuedBy` の `validity` option は時刻 check 自体は提供するが、`notBefore` / `notAfter` 値は呼び出し側が `cf.tlsClientAuth` から渡す。
- CRL、OCSP、失効 DB、失効確認。
- 鍵の保管、暗号化保存、ローテーション永続化、KV/D1/R2/Secrets 連携。
- RSA、EdDSA、別 elliptic curve (これらで署名された CSR は parse 時に reject)。
- 旧式 PKCS#12 アルゴリズム (3DES、RC2、SHA-1 PBE)、PBMAC1、空 password、crlBag / secretBag / 入れ子 safeContents、上記より古い consumer は意図的に `exportPkcs12` の対象外。
- 一般的な certificate parsing API (Cloudflare が `cf.tlsClientAuth.cert*` で値を提供するので library で重複実装しない)。
- 発行可否ポリシー判定 (CSR の主張 subject/SAN を採用するかなど) — caller の責務。
- DN 文字列 parsing。
- multi-valued RDN。

## Key Handling

EdgCA は鍵を `CryptoKey` でのみ受け渡しします。秘密鍵の string 形式 (PEM、JWK、base64 など) を library から返すことも、入力として受け取ることもありません。秘密素材が JS の string heap に library 境界で残らないよう設計されています。内部生成された鍵は extractable で、永続化が必要な場合は呼び出し側で `crypto.subtle.exportKey` を直接呼んでバイト列を取り出します。永続化形式の選択は呼び出し側の責任です。

EdgCA が扱うのは鍵の生成・署名・公開鍵の SPKI export だけです。鍵をどこに保存するか、保存時にどう暗号化するか、ローテーション状態をどう永続化するか、Cloudflare storage products とどう連携するかはすべて application 側の責務です。

### CA 鍵の持ち込み (推奨)

root CA と intermediate CA は長期保管が前提です。鍵管理を呼び出し側に寄せるため、`createRootCA` と `issueIntermediateCA` は持ち込み鍵ペアを `keyPair: CryptoKeyPair` で受け取れます。鍵のライフサイクル (生成・保管・ローテーション・永続化形式の選択) を呼び出し側の鍵管理基盤で一貫して扱えるため、こちらが推奨ルートです。

```ts
// 永続化形式から CryptoKeyPair を復元する。下は PKCS#8 PEM を vault に
// 保存している場合の一例。JWK や生バイト列で持っているならその経路で
// import すればよい。
async function loadKeyPair(label: string): Promise<CryptoKeyPair> {
  const pkcs8 = pemToDer(loadFromVault(`${label}-private-pem`));
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: "P-256" },
    /* extractable */ false,
    ["sign"]
  );
  // 公開鍵の SPKI も別保存しているなら、それを直接 import するほうが速い。
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

`keyPair` を省略した場合は内部で鍵ペアを生成します。テストや PoC 用途の簡便動作です。client certificate の鍵は ephemeral 想定のため `issueClientCert` では常に内部生成です。

## Development

```sh
npm run typecheck
npm run build
npm run test
npm audit
```

主要 suite (`vitest.config.ts`) は `@cloudflare/vitest-pool-workers` で Workers 互換 runtime 上の WebCrypto 挙動を確認します。もう一つの suite (`vitest.node.config.ts`、ファイルパターン `*.node.test.ts`) は Node 環境で動かし、生成した PFX を `node:tls` の `createSecureContext` で end-to-end 検証します。`npm run test` は両者を逐次実行します。

### Property-based tests

低 layer の round-trip 不変条件は `fast-check` を使った property-based test として、対象モジュール 1 ファイルずつ分けて `test/<module>.property.test.ts` に置いています。

- [test/der.property.test.ts](../../test/der.property.test.ts) — INTEGER / OID / OCTET STRING / BIT STRING / SEQUENCE の TLV round-trip
- [test/bytes.property.test.ts](../../test/bytes.property.test.ts) — `concatBytes`、`binaryToBytes`/`bytesToBinary`、`bytesEqual`、`cloneBytes`
- [test/ip.property.test.ts](../../test/ip.property.test.ts) — IPv4 dotted-quad と IPv6（full form / `::` compression）の encode
- [test/pem.property.test.ts](../../test/pem.property.test.ts) — `certificateToPem` と `pemToDer` / `pemToDerWithLabel` / `splitPemBlocks` の round-trip

`vitest.config.ts` の include は `test/**/*.test.ts` なので `npm run test` で同時に走ります。`cert` 組み立て層（`ca.ts` / `x509.ts`）は scope 上 PBT 対象外で、example-based のまま [test/edgca.test.ts](../../test/edgca.test.ts) に集約しています。

## API Documentation

詳しくは [API.md](API.md) を参照してください。

実装開始時点の計画は [PLAN_HISTORY.md](PLAN_HISTORY.md) に履歴として残しています。
