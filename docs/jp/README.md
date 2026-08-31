# EdgCA

> 日本語 | [English](../../README.md)

EdgCA は、Cloudflare Workers 互換の runtime で、利用者自身が管理する自己 CA から mTLS 用 client certificate と文書署名用 certificate を発行し、明示した trust anchor に対する限定的な証明書検証を行うための小さな TypeScript ライブラリです。

## 特徴

- **WebCrypto のみ・runtime 依存ゼロ。** 暗号演算は全て `globalThis.crypto.subtle` に委譲。Cloudflare Workers / Node.js 20+ / modern browser で polyfill や bundler shim なしに同じコードが動く。
- **軽量。** v0.7.0 — tarball **51.8 kB** / 展開後 **200.1 kB** / 76 files。transitive dependency ゼロ。CLI も `node:util.parseArgs` のみ。(release ごとに再計測)
- **CA 階層 (2 段)。** 自己署名 root CA を作る、必要なら root から intermediate CA を発行する。3 段以上の intermediate は意図的に scope 外。
- **PFX (PKCS#12) bundling。** 証明書 + 秘密鍵 (+ 任意の chain) を password 付き `.pfx` / `.p12` にまとめ OS 証明書ストア (Win11+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux) 取り込み用に書き出す。algorithm 非依存で、任意の PKCS#8 DER bytes (ECDSA / RSA / Ed25519 等) を受ける。
- **mTLS client certificate 発行。** 内部鍵生成、または下の CSR 経由で caller 管理の公開鍵から発行。
- **PKCS#10 CSR サポート。** CSR の生成 (POP 込み)、受け取った CSR の parse (subject、要求 SAN、公開鍵、生 extensions/attributes)、POP 署名検証、CSR の公開鍵を入力とした証明書発行 (秘密鍵は library が一切触らない)。
- **文書署名用 certificate (RFC 9336)。** EKU `id-kp-documentSigning` の leaf を発行。CAdES / CMS / ASiC tool 等の signer cert として使う (container 生成は別 tool)。
- **発行元判定。** 受け取った client certificate が自 CA 発行かを判定 (issuer identity 確認のみ、完全な mTLS 検証ではない)。
- **限定的な chain validation。** caller が順番を明示した `leaf → intermediate → trusted root` の署名、期限、CA 制約、用途を検証。PKI path の自動探索や失効確認は行わない。
- **certificate 公開鍵による任意データの署名検証。** 検証済み certificate から公開鍵を取り出し、ECDSA DER または IEEE P1363 形式の署名を検証する。challenge の生成・保存やリプレイ防止は application の責務。
- **opt-in の任意データ署名。** `@noz-ele/edgca/sign` で caller が保持する ECDSA `CryptoKey` から DER または IEEE P1363 署名を生成する。root entry point からは再 export しない。
- **PEM/DER の encode/decode** (certificate と PKCS#10 CSR)。
- **API 境界での秘密鍵 hygiene。** 秘密鍵は public API 上 `CryptoKey` (発行系) または `Uint8Array` PKCS#8 bytes (`exportPkcs12`) のみで扱い、`string` で受け渡さない。JS の string は immutable で GC まで heap に残り wipe できないため、秘密鍵を string で保持することを設計上避ける。PEM ↔ CryptoKey の変換は caller 側 (string 表現の寿命を caller が制御できるようにするため)。

### 対応アルゴリズム

- **発行 layer**: ECDSA NIST P-256 / P-384 / P-521 (それぞれ標準の SHA-256 / SHA-384 / SHA-512 とペア)。RSA、EdDSA、その他 curve は発行側では意図的に scope 外。
- **検証 layer**: 発行 layer と同じ ECDSA NIST P-256 / P-384 / P-521。汎用 algorithm verifier にはしない。
- **PFX bundling (`exportPkcs12`)**: algorithm 非依存。任意の PKCS#8 DER bytes をそのまま wrap する。

> ⚠ **汎用 PKI runtime ではありません。** chain validation は、caller が順序と trusted root を明示する最大 `root → intermediate → leaf` の範囲だけです。PKI path building、OS trust store、AIA 取得、失効確認 (CRL/OCSP)、鍵保管、ローテーションは提供しません。また certificate の検証は、提示者が秘密鍵を持つことの証明ではありません。詳細は [Verify](#verify-cloudflare-worker) と [NON_GOALS.md](NON_GOALS.md) を参照してください。

## Contents

- [CLI](#cli) — `npx @noz-ele/edgca …` で 5 つの定番作業をワンライナーで実行
- [Quick Start](#quick-start) — root → intermediate → client cert を発行 (PFX 束ね手順も含む)
- [文書署名用 certificate を発行する](#文書署名用-certificate-を発行する) — RFC 9336 `id-kp-documentSigning` の leaf を発行
- [Verify (Cloudflare Worker)](#verify-cloudflare-worker) — 自 CA から発行されたかを判定
- [Certificate chain verification](#certificate-chain-verification) — 明示した chain を trusted root まで検証
- [Certificate signature verification](#certificate-signature-verification) — certificate の公開鍵で任意データの署名を検証
- [Arbitrary-data signing](#arbitrary-data-signing) — opt-in subpath と CLI で任意データを署名
- [CSR から発行する](#csr-から発行する) — client が秘密鍵を保持する構成 (PKCS#10 + POP)
- [Subject](#subject) · [Scope](#scope) · [Key Handling](#key-handling) · [Development](#development) · [API Documentation](#api-documentation)

## Status

EdgCA は **v0.7.x の初期安定化フェーズ**です。作者が実際の Cloudflare Workers 環境で検証している最中で、API が変わる可能性があります。検証に集中するため、**外部からの Issue と PR は一時的に制限**しており、API が落ち着いた後に再開します。read / clone / fork / `npm install` は通常通り可能です。

`@noz-ele/edgca/sign` と `edgca sign-data` は現在の repository HEAD に実装済みですが、まだ npm release には含まれていません。publish 前の `npx @noz-ele/edgca sign-data ...` は npm 上の既存 release を実行するため使えません。local build は `node dist/cli.js sign-data ...` で検証できます。

## Install

```sh
npm install @noz-ele/edgca
```

ESM 専用 (`"type": "module"`) で、`globalThis.crypto.subtle` が動く runtime (Cloudflare Workers、Node.js 20+、modern browser 等) で動作します。CommonJS からの `require` は対象外です。

### Package entry points

v0.7.0 の root `@noz-ele/edgca` は後方互換のため現行 public API を再 export します。用途別 subpath を使うと、発行だけを使う bundle に検証実装が入ることを tree-shaking の成否に依存せず避けられます。

```ts
// CA 作成・証明書発行だけ
import { createRootCA, issueClientCert } from "@noz-ele/edgca/issuer";

// 公開証明書による検証だけ (CA 秘密鍵は不要)
import {
  verifyCertificateChain,
  verifyCertificateSignature
} from "@noz-ele/edgca/verify";

// PFX 組み立てだけ
import { exportPkcs12 } from "@noz-ele/edgca/pkcs12";
```

`./issuer` は CA の作成・import・intermediate / leaf 発行を担当します。`./verify` は直接 issuer と chain の検証を担当し、発行 module を静的 import しません。`package.json` の `sideEffects: false` も維持します。

任意データ署名は `@noz-ele/edgca/sign` だけから opt-in で公開します。root entry point からは再 export せず、`./issuer`、`./verify`、`./pkcs12` から sign module への static import も作りません。そのため、明示的に次を import した application だけが public signing module を dependency / bundle に含めます。

```ts
import { signData } from "@noz-ele/edgca/sign";
```

同一 npm package の tarball に `dist/sign.*` が入ることは許容します。インストールファイル自体の分離を目的とした別 package は作りません。

## CLI

EdgCA には、5 つの定番ワンショット作業向けの小さな zero-dependency CLI (`bin: edgca`) が同梱されています。library API を薄くラップしただけのもので、`node:util.parseArgs` を使っているため CLI を使わない consumer の依存にも何も増えません。

> `npx` は CLI を **インストールせずに** 実行します。パッケージは npm のローカルキャッシュにダウンロードされ、`bin` が実行され、プロジェクトの `node_modules` / `package.json` には何も追加されません。1 回だけ試したい用途 (ローカル開発用 CA を作る、PFX を組む等) はこれで済みます。繰り返し使うなら `npm install -g @noz-ele/edgca` で global install し、以降は `edgca …` を直接呼べます。

出力ファイルはすべて **現在のディレクトリ** に書き出されます。ファイル名は `--name` から導出され (default は `root` / `intermediate` / `client`)、cert は `<name>.crt.pem`、private key は PKCS#8 PEM の `<name>.key.pem`、chain (必要な場合) は `<name>.chain.pem` です。

```sh
# 1. root CA を作成 (default: P-256、3650 日)
npx @noz-ele/edgca create-root-ca --subject "CN=My Test Root,O=Acme,C=JP"
# → ./root.crt.pem, ./root.key.pem

# 2. その root から intermediate CA を発行
npx @noz-ele/edgca issue-intermediate-ca \
  --ca-cert root.crt.pem --ca-key root.key.pem \
  --subject "CN=My Intermediate,O=Acme"
# → ./intermediate.crt.pem, ./intermediate.key.pem, ./intermediate.chain.pem

# 3. intermediate から mTLS client cert を発行
npx @noz-ele/edgca issue-client \
  --ca-cert intermediate.crt.pem --ca-key intermediate.key.pem \
  --ca-chain intermediate.chain.pem \
  --subject "CN=alice" \
  --dns-name alice.example.test --ip 10.0.0.1 \
  --days 365
# → ./client.crt.pem, ./client.key.pem, ./client.chain.pem

# 4. cert + key (+ 任意の chain) を password 付き PFX にまとめる
npx @noz-ele/edgca pem-to-pfx \
  --cert client.crt.pem --key client.key.pem --chain client.chain.pem \
  --password "hunter2"
# → ./client.pfx   (--out 省略時は --cert と同じディレクトリの <cert-basename>.pfx)
```

フラグ一覧 (端末で見るには `npx @noz-ele/edgca --help`):

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
```

入力 bytes を ECDSA 秘密鍵で署名し、HTTP header へそのまま渡せる unpadded base64url 1 行を stdout へ出力する `sign-data` command も利用できます。

```text
edgca sign-data --key <private-key.pem>
                 (--data-file <path> | --data-base64url <value>)
                 --signature-format <der|ieee-p1363>
```

curl 等の shell client では、専用 JavaScript helper を置かず次の形で使えます。

```sh
signature=$(edgca sign-data \
  --key "$client_key" \
  --data-base64url "$signing_input" \
  --signature-format ieee-p1363)
```

`npx @noz-ele/edgca sign-data ...` と `edgca sign-data ...` は同じ CLI command を実行します。前者は `npx` がnpm package を cache へ取得して `bin: edgca` を起動する呼び出し方、後者は local / global install 済みの同じ `bin` を直接起動する呼び出し方です。

`--subject` は OpenSSL 互換の DN 文字列 (`"CN=foo,O=bar,C=JP"`) を受け取ります。短縮名は大文字小文字を区別せず (`CN`/`O`/`OU`/`C`/`ST`/`L`/`E`/`DC`/`SERIALNUMBER`/`STREET`/`POSTALCODE`/`TITLE`/`GIVENNAME`/`SURNAME`/`UID`)、dotted OID 形式 (`1.2.840.113549.1.9.1=...`) もそのまま受理します。秘密鍵は PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) として読み書きします。SEC1 (`EC PRIVATE KEY`) は非対応です。

> ⚠ CLI はローカル検証やワンショット運用作業向けの便利 wrapper です。server / Worker / browser 上のプログラム利用では library API を直接呼び出してください。そちらなら秘密鍵は `CryptoKey` のままで disk を一切経由しません。背景は [Key Handling](#key-handling) を参照。

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
  // exportPkcs12 は PKCS#8 DER bytes (algorithm 非依存) を受ける。CryptoKey ではない。
  // CryptoKey を持っている場合は bytes を取り出して渡す:
  privateKey: new Uint8Array(await crypto.subtle.exportKey("pkcs8", client.privateKey)),
  password: new TextEncoder().encode(passwordString),
  friendlyName: new TextEncoder().encode("worker-client") // 任意、BMPString として埋め込まれる
});
// pfxBytes は Uint8Array — disk に書き出す、download trigger に渡す、または
// tls.createSecureContext({ pfx: Buffer.from(pfxBytes), passphrase: passwordString }) に渡す。
```

password は UTF-8 の `Uint8Array` で受け取ります (`string` 不可)。秘密のバイト列を JS の immutable な string heap に置かずに済ませるための設計です。PBKDF2 反復回数の default は 600 000、MAC KDF の default は 100 000 で、OWASP と OpenSSL 3 の推奨値に合わせていますが、引数で上書きできます。

実装は環境依存なし (WebCrypto のみ、Node 固有 API なし) なので、PFX の組み立ては **サーバ側、Cloudflare Worker、ブラウザのいずれでも同じコードで動きます**。よくある構成は CA をサーバに置き、ブラウザでは鍵ペアをローカル生成 → CSR をサーバに送って cert をもらう → ブラウザ側で PFX に組み立てる、というもの。秘密鍵と password が通信路に乗りません。

`@noz-ele/edgca/pkcs12` という subpath が用意されているので、PFX 組み立てだけ使いたい consumer は CA / CSR / verify モジュールを引き込まずに import できます。

## 文書署名用 certificate を発行する

`issueDocumentSigningCert` は、任意 document への署名 (CAdES detached、CMS、ASiC-E container 等。これらの container 生成は EdgCA の対象外で別 tooling で行う) に使う leaf を発行します。**mTLS client certificate ではありません**。EKU は `id-kp-documentSigning` (RFC 9336)、`keyUsage` は `digitalSignature, contentCommitment` (mTLS leaf の `digitalSignature` のみと違う)。SAN は意図的に受け取りません。署名者の identity は Subject DN で示します。

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

// signer.certPem        — 署名用 certificate
// signer.certChainPem   — 署名と一緒に埋める完全 chain (signer + intermediate + root)
// signer.privateKey     — 秘密 CryptoKey。文書署名 tool が使う
```

戻り値は `IssuedDocumentSigningCertificate` (構造は `IssuedClientCertificate` と同一だが、interface 名で EKU profile を区別)。signer cert + 鍵を PKCS#12 として束ねたい場合は、mTLS leaf と同じく `exportPkcs12` flow がそのまま使えます。

`issueDocumentSigningCertForPublicKey` (CSR variant) は v1 では提供しません。CAdES / CMS / ASiC container の生成も EdgCA は行いません — 詳細は [docs/jp/NON_GOALS.md](NON_GOALS.md) を参照してください。

## Verify (Cloudflare Worker)

> ⚠ **この関数で出来ること・出来ないこと**
>
> `verifyClientCertificateIssuedBy` は **mTLS の検証ではありません** (そもそもこの構成では mTLS 検証自体が成立しません)。せいぜい *発行元検証* に留まります。すなわち「提示された証明書が指定 CA 局で発行されたか」を確認するだけで、これは「証明書を提示した相手が正当な持ち主であるかの認証」とは**まったく別物**です。
>
> client certificate はそもそも誰にでも提示してよい情報なので、内容は容易にコピーできます。**「誰でも client certificate の情報は持ち得る」と仮定しなければなりません**。したがって証明書情報を持っているという事実は、正当な持ち主であることの根拠には**絶対になりません**。
>
> 正当な持ち主であることを確認するには、加えて対応する秘密鍵を所持していることの確認 — すなわち秘密鍵で署名された情報を証明書中の公開鍵で検証する作業 — が必要です。通常の TLS handshake では client が `CertificateVerify` message でこれを行いますが、**Cloudflare Workers の runtime はこの署名を application に公開しないため、Worker は TLS handshake 自体の proof-of-possession を再検証できません**。また Enterprise プラン以外では Cloudflare 自身の TLS レイヤーも自前 CA を知らないため、EdgCA で発行した証明書に対して `request.cf.tlsClientAuth.certVerified === "SUCCESS"` になることはありません。一方、application layer で server が nonce を発行し、client が対応する秘密鍵で署名した別のデータは、`verifyCertificateSignature` を使って certificate の公開鍵で検証できます。
>
> 実用上の含意: どこかで (log、漏洩 storage、handshake 中のネットワーク観測など) 有効な証明書のコピーを入手した攻撃者は、それを提示してこの check を通過できます。この関数は *最低限の identity check の 1 層* として使うものであり、認証としては使えません。本物の認証には (a) Cloudflare Enterprise で TLS レイヤー mTLS を使うか、(b) server が発行した nonce を client が秘密鍵で署名して返す application layer の challenge-response を追加してください。
>
> その他の対象外 (この関数では検証しません): `BasicConstraints CA=false`、`EKU clientAuth`、失効確認、chain walking。

このセクションは、**Cloudflare 側で client certificate が抽出済み**で、その値が `request.cf.tlsClientAuth` 経由で application に渡される運用を前提にしています。EdgCA は TLS handshake には関与しません。application が Cloudflare の値を PEM に変換した後、既存 API は発行元判定に必要な証明書 field だけを DER から読み取ります。

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

## Certificate chain verification

新しい `@noz-ele/edgca/verify` surface は CA 秘密鍵を要求せず、公開証明書だけで直接 issuer または chain を検証します。

```ts
import { verifyCertificateChain } from "@noz-ele/edgca/verify";

const result = await verifyCertificateChain({
  certificatePem: clientPem,
  // target の直接 issuer から順番。EdgCA では 0 または 1 本。
  intermediateCertificatesPem: [intermediatePem],
  // OS trust store は参照せず、信頼する root を明示する。
  trustedRootCertificatesPem: [rootPem],
  purpose: "clientAuth"
});

if (!result.valid) {
  return new Response(
    `invalid certificate chain: ${result.reason}`,
    { status: 403 }
  );
}
```

検証範囲:

- 各 child / issuer 間の issuer DN、AKI / SKI、署名。
- target、intermediate、root の DER 内有効期間。
- issuer の `BasicConstraints CA=true`、`KeyUsage keyCertSign`、`pathLenConstraint`。
- `purpose` に応じた target の CA / mTLS client / document-signing profile。
- 重複 extension、未対応 critical extension、署名 algorithm の不整合。
- chain の終点が caller の明示した trusted root certificate と一致すること。

これは汎用的な PKI path builder ではありません。intermediate の順序は caller が指定し、最大 `root → intermediate → leaf` に限定します。AIA download、OS trust store、CRL / OCSP、server hostname 照合は行いません。また chain が valid でも、提示者が leaf の秘密鍵を持つことは証明されません。

既存の `verifyClientCertificateIssuedBy` は後方互換のため残し、引数と挙動を変えません。新規コードでは、1 link だけなら `verifyCertificateIssuedBy`、trusted root まで確認するなら `verifyCertificateChain` を使います。詳細な契約と失敗理由は [API Documentation](API.md) を参照してください。

## Certificate signature verification

`verifyCertificateSignature` は、certificate 内の公開鍵で caller が渡した任意の byte 列の ECDSA 署名を検証します。certificate chain、期限、Key Usage、EKU、失効状態はこの関数では検証しません。認証用途では、先に `verifyCertificateChain({ purpose: "clientAuth" })` を成功させ、その同じ leaf certificate を渡します。

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
  // nonce、HTTP method、URI、body digest 等を application が結合した
  // 署名対象そのもの。事前 hash ではなく、署名時と同じ生 byte 列を渡す。
  data: signatureBase,
  signature: signatureBytes,
  // RFC 9421 の ECDSA signature は固定長 r || s 形式。
  signatureFormat: "ieee-p1363"
});
```

ECDSA signature は 2 つの整数 `(r, s)` から成り、同じ署名でも byte 表現に次の 2 形式があります。

| `signatureFormat` | 表現 | 用途 |
| --- | --- | --- |
| `"der"` | ASN.1 `SEQUENCE { INTEGER r, INTEGER s }`。整数 encode により全体長が変わる。 | X.509、DER 出力を選んだ C# / OpenSSL 等 |
| `"ieee-p1363"` | curve ごとの固定長 `r || s`。P-256 は 64 bytes、P-384 は 96 bytes、P-521 は 132 bytes。 | RFC 9421、WebCrypto の ECDSA signature 表現 |

形式は自動判定せず、caller が必ず指定します。RFC 9421 の標準 ECDSA algorithm は P-256/SHA-256 と P-384/SHA-384 です。EdgCA 自体の署名検証は既存の algorithm 範囲に合わせて P-521/SHA-512 も扱いますが、P-521 を RFC 9421 algorithm として扱う意味ではありません。

この関数が返す `true` は「指定された `data` が、その certificate の公開鍵に対応する秘密鍵で署名された」ことだけを示します。次は caller が別途保証します。

- nonce と challenge ID の生成、期限、保存、一回限りの消費。
- HTTP method、URI、authority、body digest 等を署名対象へ結び付ける処理。
- RFC 9421 の `Accept-Signature`、`Signature-Input`、`Signature` の parse・正規化。
- 初回 request と再送 request の certificate fingerprint 一致確認。
- certificate と利用者・端末・権限の対応付け。

したがって関数名は `verifyProofOfPossession` ではありません。nonce の新鮮性やリプレイ防止を含む application protocol が成立して初めて、全体として proof-of-possession になります。

## Arbitrary-data signing

`signData` は caller が保持する ECDSA `CryptoKey` で任意の生 byte 列を署名します。Node.js、Cloudflare Workers、modern browser で同じ API を使えるよう、署名本体は `globalThis.crypto.subtle`、`CryptoKey`、`Uint8Array` だけで実装します。

```ts
import { signData } from "@noz-ele/edgca/sign";

const signature = await signData({
  privateKey,
  // 事前 hash ではなく署名対象そのもの。
  data: signingInput,
  signatureFormat: "ieee-p1363"
});
```

- ECDSA NIST P-256 / P-384 / P-521 のみを受け、それぞれ SHA-256 / SHA-384 / SHA-512 を使います。
- `signatureFormat` は `"der"` または `"ieee-p1363"` の必須指定で、形式は推測しません。
- library API は PEM string や key path を受けません。`CryptoKey` の生成・import・保管は caller が担当します。PEM file を直接扱う利用者には Node.js 専用の `edgca sign-data` CLI を提供します。
- `signData` は nonce、challenge、HTTP request canonicalization、期限、保存、リプレイ防止を扱いません。渡された bytes への署名だけを行います。

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
- 文書署名用 certificate 発行。EKU `id-kp-documentSigning` (RFC 9336)、`keyUsage digitalSignature, contentCommitment`、内部鍵生成のみ、SAN なし。
- CSR (PKCS#10) の parse と所持証明 (POP) 署名検証。
- 自己 CA からの発行かを判定する identity 確認 API (`verifyClientCertificateIssuedBy`、任意の時刻有効性 check 付き)。
- 公開証明書だけを使う直接 issuer 検証 (`verifyCertificateIssuedBy`)。
- caller が順序と trusted root を明示する最大 `root → intermediate → leaf` の chain validation (`verifyCertificateChain`)。DER 内の時刻、CA / Key Usage / EKU / path length、critical extension を検証する。
- certificate の公開鍵による任意データの ECDSA 署名検証 (`verifyCertificateSignature`)。DER / IEEE P1363 形式を caller が明示する。
- 発行・検証の用途別 subpath (`@noz-ele/edgca/issuer` / `@noz-ele/edgca/verify`)。
- PEM/DER helper (証明書のみ — 鍵は CryptoKey でやり取り)。
- 発行済み証明書 + 秘密鍵の PFX (PKCS#12) export。PBES2 (PBKDF2-HMAC-SHA-256 + AES-256-CBC) と HMAC-SHA-256 MAC で構成し、対象は Win11+ / Server 2019+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux consumer。
- Basic Constraints、Key Usage、Extended Key Usage、Subject Alternative Name、SKI、AKI。

- caller が渡した `CryptoKey` による任意データの ECDSA 署名 (`signData`)。DER / IEEE P1363 形式を caller が明示する。
- root からは再 export しない opt-in subpath `@noz-ele/edgca/sign`。
- PKCS#8 PEM を読み、渡された file bytes または base64url bytes を署名し、base64url で出力する `edgca sign-data` CLI。

意図的に対象外:

- server certificate 発行。leaf scope は mTLS client cert と文書署名 cert のみ。
- 文書署名 cert を持ち込み公開鍵から発行する API (`issueDocumentSigningCertForPublicKey`) — v1 では提供しない。
- 文書署名 leaf への SAN (`dnsNames` / `ipAddresses` / `emailAddresses`)。
- CAdES / CMS / PAdES / XAdES / ASiC の文書署名や container 生成。EdgCA は signer cert を発行するだけで、文書署名 container の生成は別の関心事。
- unordered な certificate 群からの PKI path building / issuer 自動探索、AIA download。
- OS / runtime trust store の参照。root は caller が明示する。
- intermediate を 2 本以上含む CA hierarchy / chain 検証。最大 `root → intermediate → leaf`。
- Cloudflare 固有 textual time の parse。verify module は certificate DER 内の時刻だけを parse する。
- CRL、OCSP、失効 DB、失効確認。
- TLS handshake の `CertificateVerify` と TLS connection 自体への proof-of-possession binding。
- nonce、challenge、HTTP message 正規化、リプレイ防止を含む application-layer proof-of-possession protocol。EdgCA が扱うのは caller が構築した byte 列の署名生成 (`signData`) と certificate 公開鍵による署名検証 (`verifyCertificateSignature`) まで。
- server certificate の hostname / SAN identity 検証。
- 鍵の保管、暗号化保存、ローテーション永続化、KV/D1/R2/Secrets 連携。
- 発行・CSR・certificate 検証における RSA、EdDSA、別 elliptic curve。
- 旧式 PKCS#12 アルゴリズム (3DES、RC2、SHA-1 PBE)、PBMAC1、空 password、crlBag / secretBag / 入れ子 safeContents、上記より古い consumer は意図的に `exportPkcs12` の対象外。
- 一般的な公開 certificate parsing API。certificate parser は検証内部でのみ使う。
- 発行可否ポリシー判定 (CSR の主張 subject/SAN を採用するかなど) — caller の責務。
- DN 文字列 parsing。
- multi-valued RDN。

## Key Handling

EdgCA は鍵を `CryptoKey` でのみ受け渡しします。秘密鍵の string 形式 (PEM、JWK、base64 など) を library から返すことも、入力として受け取ることもありません。秘密素材が JS の string heap に library 境界で残らないよう設計されています。内部生成された鍵は extractable で、永続化が必要な場合は呼び出し側で `crypto.subtle.exportKey` を直接呼んでバイト列を取り出します。永続化形式の選択は呼び出し側の責任です。

EdgCA が扱うのは鍵の生成・署名・公開鍵の SPKI export だけです。鍵をどこに保存するか、保存時にどう暗号化するか、ローテーション状態をどう永続化するか、Cloudflare storage products とどう連携するかはすべて application 側の責務です。

### CA 鍵の持ち込み (推奨)

root CA と intermediate CA は長期保管が前提です。鍵管理を呼び出し側に寄せるため、`createRootCA` と `issueIntermediateCA` は持ち込み鍵ペアを `keyPair: CryptoKeyPair` で受け取れます。鍵のライフサイクル (生成・保管・ローテーション・永続化形式の選択) を呼び出し側の鍵管理基盤で一貫して扱えるため、こちらが推奨ルートです。

持ち込んだ秘密鍵と公開鍵は署名・検証 round-trip で対応を確認し、不一致なら発行前に throw します。秘密鍵は non-extractable でも構いません。公開鍵は証明書の SubjectPublicKeyInfo に埋め込むため、SPKI export 可能である必要があります。

```ts
// 永続化形式から CryptoKeyPair を復元する。秘密鍵の PKCS#8 PEM と
// 公開鍵の SPKI PEM を対で vault に保存している場合の例。
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

  // non-extractable な秘密鍵から公開鍵を export することはできないため、
  // 対になる公開鍵を保存済みの SPKI から復元する。
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
