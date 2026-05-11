# Plan History

この文書は、EdgCA の実装開始時点で合意した計画を履歴として残すものです。

現在の public API の詳細は [API.md](API.md) を参照してください。

## 2026-05-04: Initial Implementation Plan

### Summary

- Cloudflare Workers 上で、自己 root CA から intermediate CA を発行し、その intermediate CA から mTLS 用 client certificate と秘密鍵を発行する。
- 公開機能は CA 階層の作成、client certificate 発行、PEM/DER/key 入出力に絞る。
- サーバー証明書発行、公開検証 API、チェーン検証 API、失効情報管理、鍵の保管方法は提供しない。
- 暗号演算は ECDSA P-256 + SHA-256 を対象にし、`globalThis.crypto.subtle` に委譲する。

### Public API

生成 API:

- `createRootCA(options): Promise<CertificateAuthority>`
- `issueIntermediateCA(options): Promise<CertificateAuthority>`
- `issueClientCert(options): Promise<IssuedClientCertificate>`

入出力 API:

- `importCertificateAuthority({ certPem, privateKeyPem, issuerChainPem? }): Promise<CertificateAuthority>`
- `certificateToPem(der): string`
- `pemToDer(pem): Uint8Array`
- `privateKeyToPem(key): Promise<string>`
- `publicKeyToPem(key): Promise<string>`

`CertificateAuthority` は `certPem`, `privateKeyPem`, `publicKeyPem`, `certDer`, `privateKey`, `publicKey`, `issuerChainPem` を持つ。root の `issuerChainPem` は空文字列。

`issueIntermediateCA` は root または intermediate を issuer として受け取り、新しい CA の `issuerChainPem` に parent certificate chain を保存する。

`issueClientCert` は root または intermediate を issuer として受け取り、`certPem`, `privateKeyPem`, `publicKeyPem`, `certDer`, `privateKey`, `publicKey`, `certChainPem` を返す。`certChainPem` は leaf + issuer + issuerChain の順で、mTLS 登録用の提出チェーンとして利用者がそのまま使える形にする。

`subject` は `Array<{ type: SubjectAttributeType; value: string }>` の構造化入力に限定する。

`type` は `CN`, `O`, `OU`, `C`, `ST`, `L`, `E`, `DC`, `SERIALNUMBER`, `STREET`, `POSTALCODE`, `TITLE`, `GIVENNAME`, `SURNAME`, `UID` の短縮名、または dotted OID 文字列を受ける。

subject 値の ASN.1 文字列型は UTF8String 固定とし、`C` のみ PrintableString にする。利用者が文字列型を選ぶ API は提供しない。

multi-valued RDN と DN 文字列入力は対象外にする。

### Implementation

- 空の `C:\Users\tomiy\Documents\GitHub\EdgCA` に、`src/`、`test/`、`package.json`、`tsconfig.json`、`vitest.config.ts` を持つ TypeScript package を作る。
- Node 固有 API や `Buffer` に依存せず、Workers runtime と通常の bundler で使える実装にする。
- 生成する全鍵は PEM export を前提に `extractable: true` で作る。CA 秘密鍵は `sign`、公開鍵は `verify`、client 鍵も PEM 出力可能にする。
- ライブラリは鍵を生成・import/export するだけで、保管先、暗号化保存、ローテーション永続化、KV/D1/R2/Secrets 連携などの storage policy は実装しない。
- ASN.1/DER は root CA、intermediate CA、client certificate 発行に必要な範囲だけ自前実装する。
- Subject `Name` は入力配列の順序を保持し、各要素を single-valued RDN として DER encode する。短縮名は既定 OID にマップし、dotted OID はそのまま OID として encode する。
- WebCrypto の ECDSA raw `r || s` 署名と、X.509 の DER `ECDSA-Sig-Value` を相互変換する。

発行する証明書:

- Root CA: self-signed、`basicConstraints CA=true` critical、`keyUsage keyCertSign,cRLSign` critical、SKI/AKI 付与。
- Intermediate CA: issuer CA 署名、`basicConstraints CA=true` critical、`keyUsage keyCertSign,cRLSign` critical、SKI/AKI 付与。既定の `pathLenConstraint` は `0`。
- Client leaf: issuer CA 署名、`basicConstraints CA=false`、`keyUsage digitalSignature` critical、EKU `clientAuth`。

`pathLenConstraint=0` の CA からさらに intermediate CA を発行しようとした場合は、`issueIntermediateCA` が例外を投げる。

SAN は client 証明書で必要な場合だけ `dnsNames` / `ipAddresses` として指定できる補助項目にする。

CRL、OCSP、失効 DB、失効 API は非目標として設計から除外する。

### Test Plan

- Vitest と `@cloudflare/vitest-pool-workers` で Workers runtime 互換のテストを実行できる構成にする。
- Root -> Intermediate -> Client を生成し、PEM round-trip、DER parse、Basic Constraints、Key Usage、EKU、SKI/AKI、issuer/subject の関係を確認する。
- subject は短縮名、dotted OID、入力順序、`C` の PrintableString、それ以外の UTF8String、multi-valued RDN 非対応を確認する。
- テスト専用 parser/verifier は `test/helpers/` に置き、公開 API や `src/index.ts` には混ぜない。
- WebCrypto で root 自己署名、root による intermediate 署名、intermediate による client 署名が検証できることを確認する。
- `importCertificateAuthority` が `CertificateAuthority` と同形の戻り値を返し、`issuerChainPem` を保持して client の `certChainPem` に反映できることを確認する。
- `pathLenConstraint=0` の intermediate から追加 intermediate を発行しようとすると失敗することを確認する。
- server leaf、公開チェーン検証、用途検証、期限検証、失効検証、鍵保管のテストは書かない。

### Assumptions

- 目的は mTLS で使う client certificate と秘密鍵を、root 直下ではなく intermediate CA から発行すること。
- root CA は信頼アンカー、intermediate CA は実際の発行 CA として扱う。
- 秘密鍵 PEM を返すため、生成鍵はすべて exportable / extractable とする。
- 鍵の保存、暗号化、ローテーション運用、Cloudflare storage 連携は利用者側の責務とする。
- ライブラリは証明書を検証するものではなく、mTLS 用証明書と CA 階層を発行・署名するための薄い toolkit とする。

## 2026-05-11: Document-Signing Leaf Extension

### Summary

- mTLS leaf に加えて、文書署名用 leaf を発行できるように leaf scope を広げる。EdgCA 本体は cert を発行するだけで、CAdES / CMS / ASiC など署名 container の生成は別 package の責務とし、本リポジトリには持ち込まない。
- 追加する公開関数は `issueDocumentSigningCert` 1 本のみ。CSR 経由の発行 (`issueDocumentSigningCertForPublicKey`) と SAN 受け入れは v1 では対象外。

### Public API additions

```ts
function issueDocumentSigningCert(options: {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
}): Promise<IssuedDocumentSigningCertificate>;

interface IssuedDocumentSigningCertificate {
  certPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  certChainPem: string;
}
```

`IssueDocumentSigningCertOptions` を新設する。`IssuedDocumentSigningCertificate` は `IssuedClientCertificate` と構造同一だが、interface 名で EKU profile を区別する (構造的型のため alias でも実質同等だが、自己説明性を優先)。

### Issued certificate profile

- `basicConstraints CA=false` critical。
- `keyUsage digitalSignature, contentCommitment` critical。`contentCommitment` (= 旧 non-repudiation、RFC 5280 §4.2.1.3) を併用するのは、文書署名鍵に対する慣行。
- `extendedKeyUsage` に `id-kp-documentSigning` (OID `1.3.6.1.5.5.7.3.36`、RFC 9336) のみ、non-critical。`clientAuth` は **入れない** (mTLS leaf と用途を分けるため)。
- Subject Key Identifier、Authority Key Identifier。
- SAN は出力しない。文書署名 leaf における署名者 identity は Subject DN で示すという方針。

### Implementation Plan

- `src/oids.ts` に `documentSigning: "1.3.6.1.5.5.7.3.36"` を追加。
- `src/x509.ts`:
  - `KEY_USAGE_BITS` に `contentCommitment: 1` を追加し、`KeyUsageBit` に export。
  - `extendedKeyUsageDocumentSigningExtension(): Uint8Array` を追加 (`extendedKeyUsageClientAuthExtension` と同形)。
- `src/types.ts` に `IssueDocumentSigningCertOptions` と `IssuedDocumentSigningCertificate` を追加。
- `src/ca.ts`:
  - 既存の `buildClientCertificate` を一般化はせず、`issueDocumentSigningCert` を別関数として実装する (枝分かれ条件分岐より、profile ごとに独立した小さな関数の並列の方が読みやすいため)。実装は `issueClientCert` から SAN を外し、KU を `["digitalSignature", "contentCommitment"]` に、EKU を documentSigning ext に差し替えたもの。
- `src/index.ts` に `issueDocumentSigningCert` と新型を export 追加。

### Test Plan

- `test/edgca.test.ts` に `issueDocumentSigningCert` の suite を追加 (mTLS suite の隣)。
  - root → intermediate → document-signing leaf の発行が成功し、leaf の signature が intermediate の公開鍵で verify できる。
  - 発行 cert の DER に `id-kp-documentSigning` OID が出現し、`clientAuth` OID が出現しない。
  - 発行 cert の KeyUsage bit string が `digitalSignature + contentCommitment` を立て、それ以外を立てない。
  - `basicConstraints CA=false` (空 SEQUENCE) であること。
  - SAN extension が出力されないこと。
  - `certChainPem` が `signing-leaf + intermediate + root` の順で連結されること。
  - 不正 issuer (leaf cert を `ca` に渡す) で例外が発生すること。

### Out of v1 scope (記録)

- `issueDocumentSigningCertForPublicKey` (CSR 経由)。文書署名鍵は CA host / HSM 側で生成・保持される flow が一般的。
- 文書署名 leaf への SAN (rfc822Name 等を含む)。Subject DN だけで識別する設計。
- CAdES / CMS / PAdES / XAdES / ASiC の builder や verifier。EdgCA 本体には持ち込まない。
- 失効確認、TSA、LTV、eIDAS 適格性判定など、文書署名検証側の機能一式。
