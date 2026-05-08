# EdgCA — やらないことの仕様

> 日本語 | [English](../en/NON_GOALS.md)

EdgCA は「与えられた入力に従って cert を出力する」だけの stateless issuance library。以下は **意図的に実装しない**。バグ報告・改善提案を受け取った時はこの一覧を先に当てる。

## 1. 検証系

EdgCA が**提供する**唯一の検証 API は `verifyClientCertificateIssuedBy` (発行 issuer 1 本に対する identity 確認: 発行 DN match + AKI/SKI match + signature verify) のみ。それ以外の検証は以下のとおり実装しない。

- **certificate chain validation**。`importCertificateAuthority` の `issuerChainPem` が `certPem` を実際に発行したかの cryptographic 検証はしない。caller が嘘の chain を渡せば嘘の chain が出力される。「検証できるから検証すべき」は採用しない。
- **chain 遡及・PKI path building**。`verifyClientCertificateIssuedBy` も**直接の発行者 1 本**に対する判定のみ。intermediate を介して root から発行された leaf を root に対して verify する用途は対象外。
- **cert 自身からの時刻 field 抽出**。`verifyClientCertificateIssuedBy` の `validity` option は時刻 check を提供するが、`notBefore` / `notAfter` の値は**呼び出し側が外から渡す** (cert は parse しない)。`cf.tlsClientAuth.certNotBefore` / `certNotAfter` の文字列を `Date` に変換するのは application の責務。library 内に X.509 テキスト形式 (`"Dec  4 23:59:59 2025 GMT"` 等) や DER の `UTCTime` / `GeneralizedTime` の parser は持たない。
- **CRL / OCSP / 失効 DB / 失効確認**。
- **`certificateToPem(der)` での DER 妥当性検査**。先頭 byte が `0x30` (SEQUENCE) かどうかの shallow check も実装しない。本物の cert との区別はつかず、誤った安心感を与えるだけ。本気でやるなら `parseCertificateDer` 全実行が必要で、encoder の責務を超える。低 level encoder のまま。
- **import した cert の RFC 適合検査**。期限切れ・壊れた署名・想定外 extension・複数 basicConstraints 等を含む `certPem` を渡しても error にはせず、入力に従ってそのまま発行する。

## 2. 状態管理系

- **serialNumber の一意性管理**。同一 issuer に対し同じ `serialNumber` を 2 回指定しても library は止めない。RFC 5280 §4.1.2.2 の一意性保証は呼び出し側責務。発行履歴も持たない。
- **発行履歴・audit log・カウンタ**。stateless。
- **鍵の保管・暗号化保存・KV/D1/R2 連携**。
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

- **server certificate 発行なし**。client cert (mTLS) に専念。
- **公開 certificate parsing API なし**。`parser.ts` は internal — Cloudflare 側が `cf.tlsClientAuth.cert*` で parse 済み値を提供するため library で重複実装する意味がない。一方 **CSR parser は scope 内** (`parseCertificateSigningRequest`)。CSR は client から application layer 経由で来る入力で、Cloudflare 側に等価機能がない。
- **3 段以上の CA 階層なし**。最大 `root → intermediate → client`。intermediate のさらに下に intermediate は作れない。
- **RSA / Ed25519 / 非 NIST curve なし**。ECDSA NIST P-256 / P-384 / P-521 をサポート (それぞれ SHA-256 / SHA-384 / SHA-512 の標準ペアリング)。それ以外のアルゴリズム — CSR 内も含め — は reject。
- **発行可否ポリシーなし**。CSR を parse して subject/SAN と POP を取り出すが、その CSR を honor するかは library が判断しない。発行 cert に何の subject/SAN を入れるかは caller が決める。
- **暗号化された PKCS#8 PEM (encrypted private key) なし**。秘密鍵を含めて password 暗号化して取り出す形式は PFX (PKCS#12) を `exportPkcs12` で提供する。単独の `BEGIN ENCRYPTED PRIVATE KEY` PEM は提供しない。
- **旧式 PKCS#12 algorithm / 非 modern consumer なし**。`exportPkcs12` は両 bag を PBES2 + PBKDF2-HMAC-SHA-256 + AES-256-CBC、外側 MAC は HMAC-SHA-256 で emit し、対象は Win11+ / Server 2019+ / macOS 15+ / iOS/iPadOS 18+ / modern Linux PKCS#12 consumer。3DES / RC2 / SHA-1 PBE algorithm、PBMAC1、crlBag、secretBag、入れ子 safeContents、envelopedData、空 password、Windows 10 (以前) は意図的に scope 外。
- **X.509 v1 / v2 の受け入れなし**。`importCertificateAuthority` は v3 (`[0] EXPLICIT INTEGER 2`) のみ accept。version field 不在 (v1) や `INTEGER 1` (v2) の cert は throw。EdgCA 自身は常に v3 を emit する。外部由来の旧 version cert を import するユースケースはサポートしない。

## 5. これらの方針が変わる条件

- 「Cloudflare 側でも検証できないが、application 側でしかできない identity 検証」が増えた時のみ、検証系の追加を検討する。
- 「外部入力 → 出力 cert」の単一 path で「同じ入力なのに違う／想定外の DER が出る」は **bug**。これは修正対象。
- 「caller が嘘・重複入力を渡したら結果が嘘」「caller が状態を共有しないと壊れる」は **設計通り**。修正対象ではない。
