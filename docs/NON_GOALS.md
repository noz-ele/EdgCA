# EdgCA — やらないことの仕様

EdgCA は「与えられた入力に従って cert を出力する」だけの stateless issuance library。以下は **意図的に実装しない**。バグ報告・改善提案を受け取った時はこの一覧を先に当てる。

## 1. 検証系

- **certificate chain validation**。`importCertificateAuthority` の `issuerChainPem` が `certPem` を実際に発行したかの cryptographic 検証はしない。caller が嘘の chain を渡せば嘘の chain が出力される。「検証できるから検証すべき」は採用しない。
- **runtime certificate verification**。public verification API は提供しない。検証は Cloudflare 側 (mTLS handshake) または別 layer の責務。
- **CRL / OCSP / 失効 DB / 失効確認**。
- **chain 検査・PKI path building**。
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
- **公開 certificate parsing API なし**。`parser.ts` は internal。
- **3 段以上の CA 階層なし**。最大 `root → intermediate → client`。intermediate のさらに下に intermediate は作れない。
- **RSA / Ed25519 / P-384 など他鍵種なし**。P-256 ECDSA 固定。
- **暗号化された PKCS#8 PEM (encrypted private key) なし**。

## 5. これらの方針が変わる条件

- 「Cloudflare 側でも検証できないが、application 側でしかできない identity 検証」が増えた時のみ、検証系の追加を検討する。
- 「外部入力 → 出力 cert」の単一 path で「同じ入力なのに違う／想定外の DER が出る」は **bug**。これは修正対象。
- 「caller が嘘・重複入力を渡したら結果が嘘」「caller が状態を共有しないと壊れる」は **設計通り**。修正対象ではない。
