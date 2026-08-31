# EdgCA — やらないことの仕様

> 日本語 | [English](../en/NON_GOALS.md)

EdgCA は、証明書の発行と、明示的に与えられた trust anchor に対する限定的な証明書検証を提供する stateless library。汎用 PKI runtime にはしない。以下は **意図的に実装しない**。バグ報告・改善提案を受け取った時はこの一覧を先に当てる。

## 1. 検証系

検証 surface は `@noz-ele/edgca/verify` に分離する。次の限定的な機能は**提供する範囲**に含める。

- `verifyCertificateIssuedBy`: certificate と直接の issuer 1 本について、issuer DN / subject DN、AKI / SKI、署名、DER 内の有効期間、issuer の CA 制約を確認する。
- `verifyCertificateChain`: caller が leaf の直接 issuer から順番に渡した chain を、明示的に渡した trusted root まで検証する。
- `verifyCertificateSignature`: certificate 内の公開鍵を取得し、caller が渡した任意の byte 列に対する ECDSA DER / IEEE P1363 signature を検証する。certificate の信頼性や challenge の意味はこの関数では判断しない。
- chain 検証では DER の `UTCTime` / `GeneralizedTime`、Basic Constraints、Key Usage、Extended Key Usage、`pathLenConstraint`、既知の critical extension、署名 algorithm の整合性を検査する。
- well-formed だが信頼条件を満たさない certificate は理由付きの失敗結果、PEM / DER として処理不能な入力や未対応 algorithm は例外として扱う。

以下は引き続き実装しない。

- **PKI path building / issuer 自動探索**。unordered な certificate 群から経路を探さない。AIA URL から intermediate を取得しない。caller が `leaf → intermediate → root` になる順序を明示する。
- **OS / runtime の trust store 参照**。trust anchor は `trustedRootCertificatesPem` で明示する。subject DN の一致だけでは root を信頼せず、渡された root certificate 自体との一致を要求する。
- **intermediate を 2 本以上含む chain の検証**。発行機能と同じく最大 `root → intermediate → leaf` に限定する。
- **CRL / OCSP / 失効 DB / 失効確認**。network access を伴う検証も行わない。
- **TLS handshake の `CertificateVerify` 検証**。Cloudflare が終端した TLS connection の handshake signature や exporter を application から取得せず、TLS connection 自体への cryptographic binding は提供しない。
- **application-layer proof-of-possession protocol**。nonce / challenge ID の生成、期限、保存、原子的な一回限りの消費、HTTP message への binding、RFC 9421 header の parse / canonicalization は行わない。`verifyCertificateSignature` は caller が構築した byte 列の署名が certificate 公開鍵で検証できるかだけを返す。
- **server identity / hostname 検証**。SAN dNSName と接続先 hostname の照合は行わない。検証用途は EdgCA が発行対象とする mTLS client cert と文書署名 cert に限定する。
- **Cloudflare 固有文字列の parser**。`cf.tlsClientAuth.certNotBefore` / `certNotAfter` の `"Dec  4 23:59:59 2025 GMT"` のような文字列は application が変換する。verify module が parse するのは certificate DER 内の `UTCTime` / `GeneralizedTime`。
- **`certificateToPem(der)` での DER 妥当性検査**。先頭 byte が `0x30` (SEQUENCE) かどうかの shallow check も実装しない。本物の cert との区別はつかず、誤った安心感を与えるだけ。本気でやるなら `parseCertificateDer` 全実行が必要で、encoder の責務を超える。低 level encoder のまま。
- **発行時 import の自動検証**。`importCertificateAuthority` は `issuerChainPem` の署名・期限・制約を自動検証しない。発行前に確認したい caller が `verifyCertificateChain` を明示的に呼ぶ。verify module に渡された certificate は厳格に解析するが、issuer module の import 方針は変えない。
- **公開 certificate parsing API**。certificate parser は verify module の internal implementation とし、任意 X.509 情報を取り出す汎用 API にはしない。

## 2. 状態管理系

- **serialNumber の一意性管理**。同一 issuer に対し同じ `serialNumber` を 2 回指定しても library は止めない。RFC 5280 §4.1.2.2 の一意性保証は呼び出し側責務。発行履歴も持たない。
- **発行履歴・audit log・カウンタ**。stateless。
- **鍵の保管・暗号化保存・KV/D1/R2 連携**。
- **challenge / nonce store とリプレイ防止**。Durable Object、KV、D1 等への保存や compare-and-consume は application / protocol library の責務。
- **expiry 監視・rotation**。

## 3. 入力 "配慮" 系

誤入力は throw が正解。便利のための trim・dedup・補完はしない。silent な正規化は caller の意図ミスを隠す。

- **SAN dnsNames / ipAddresses の dedup なし**。同値が複数現れたら throw（「よく重複指定するから 1 件に潰す」はしない）。
- **trailing-dot FQDN の trim なし**。`"example.com."` は SAN dNSName として不正なので throw（「よく typo するから末尾 `.` を落とす」はしない）。
- **case 正規化なし**。dnsName を小文字化しない。caller が渡したまま encode。
- **Unicode normalization (NFC/NFKC) なし**。Subject 属性 value は与えられた code points をそのまま UTF-8 encode。`café` (合成) と `café` (分解) は別 DN になる。
- **DN 文字列入力 (`"CN=foo,O=Bar"`) の parser なし**。Subject は必ず `{type, value}[]` の structured 形で渡す。
- **multi-valued RDN なし**。1 entry = 1 RDN。

## 4. 機能スコープ

- **server certificate 発行なし**。leaf は mTLS client cert (`issueClientCert` / `issueClientCertForPublicKey`) と文書署名用 cert (`issueDocumentSigningCert`、RFC 9336 `id-kp-documentSigning`) を対象とし、TLS server cert は対象外。
- **文書署名 leaf に SAN なし**。`issueDocumentSigningCert` は `dnsNames` / `ipAddresses` / `emailAddresses` を受け取らない。文書署名 cert における署名者の identity は Subject DN で示すという方針。下流 profile が SAN を要求する場合は library を拡張する側の責任で、v1 では持たない。
- **文書署名の CSR 経由発行なし (v1)**。`issueDocumentSigningCertForPublicKey` は提供しない。内部鍵生成のみ。mTLS 側に CSR 版があるのは「client が自分の秘密鍵を保持する flow」が一般的だからで、文書署名 leaf は CA host / HSM 側で鍵保管したまま発行する flow が一般的なため、対称性は v1 では入れない。
- **CAdES / CMS / PAdES / XAdES / ASiC の builder や verifier なし**。EdgCA は文書署名用 cert を発行するだけ。文書を包んで署名する (CAdES detached、ASiC-E container 等) のは別の関心事で、本 package の外。
- **公開 certificate parsing API なし**。`parser.ts` は verify / issuance 内部でのみ使う。一方 **CSR parser は scope 内** (`parseCertificateSigningRequest`)。CSR は client から application layer 経由で来る入力で、Cloudflare 側に等価機能がない。
- **3 段以上の CA 階層なし**。最大 `root → intermediate → client`。intermediate のさらに下に intermediate は作れない。
- **発行・検証 layer は RSA / Ed25519 / 非 NIST curve なし**。発行 API、CSR API、certificate 検証 API は ECDSA NIST P-256 / P-384 / P-521 (それぞれ SHA-256 / SHA-384 / SHA-512 の標準ペアリング) のみ受け、それ以外は境界で reject する。**`exportPkcs12` は別**: algorithm 非依存の PKCS#12 packer であり、任意の PKCS#8 DER bytes (RSA / Ed25519 / 任意 curve の ECDSA など) を受ける。PKCS#12 wrapping は byte-level で、内部 algorithm を見る必要がないため。
- **発行可否ポリシーなし**。CSR を parse して subject/SAN と POP を取り出すが、その CSR を honor するかは library が判断しない。発行 cert に何の subject/SAN を入れるかは caller が決める。
- **暗号化された PKCS#8 PEM (encrypted private key) なし**。秘密鍵を含めて password 暗号化して取り出す形式は PFX (PKCS#12) を `exportPkcs12` で提供する。単独の `BEGIN ENCRYPTED PRIVATE KEY` PEM は提供しない。
- **旧式 PKCS#12 algorithm / 非 modern consumer なし**。`exportPkcs12` は両 bag を PBES2 + PBKDF2-HMAC-SHA-256 + AES-256-CBC、外側 MAC は HMAC-SHA-256 で emit し、対象は Win11+ / Server 2019+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux PKCS#12 consumer。3DES / RC2 / SHA-1 PBE algorithm、PBMAC1、crlBag、secretBag、入れ子 safeContents、envelopedData、空 password、Windows 10 (以前) は意図的に scope 外。
- **X.509 v1 / v2 の受け入れなし**。`importCertificateAuthority` は v3 (`[0] EXPLICIT INTEGER 2`) のみ accept。version field 不在 (v1) や `INTEGER 1` (v2) の cert は throw。EdgCA 自身は常に v3 を emit する。外部由来の旧 version cert を import するユースケースはサポートしない。

## 5. これらの方針が変わる条件

- 明示的な certificate と caller が構築した byte 列だけで完結し、stateless・WebCrypto-only・最大 2-level CA hierarchy を維持できる検証は追加を検討できる。
- issuer 自動探索、外部取得、永続状態、失効基盤が必要な要求は EdgCA ではなく専用 PKI library / runtime に委ねる。
- 「外部入力 → 出力 cert」の単一 path で「同じ入力なのに違う／想定外の DER が出る」は **bug**。これは修正対象。
- 「caller が嘘・重複入力を渡したら結果が嘘」「caller が状態を共有しないと壊れる」は **設計通り**。修正対象ではない。
