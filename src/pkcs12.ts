import { arrayBufferFromBytes, concatBytes, randomBytes } from "./bytes.js";
import { digestSha256, keyIdentifierFromSpki } from "./crypto.js";
import {
  contextPrimitive,
  der,
  explicit,
  integer,
  nullValue,
  octetString,
  oid,
  sequence,
  set
} from "./der.js";
import { OID } from "./oids.js";
import { extractCertificateSpkiDer } from "./parser.js";

export interface ExportPkcs12Input {
  certDer: Uint8Array;
  chainDer?: Uint8Array[];
  privateKey: Uint8Array;
  password: Uint8Array;
  friendlyName?: Uint8Array;
  iterations?: number;
  macIterations?: number;
}

const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const DEFAULT_MAC_ITERATIONS = 100_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 16;
const MAC_KEY_LENGTH = 32;
const SHA256_BLOCK_SIZE = 64;
const PKCS12_KDF_ID_MAC = 3;

export async function exportPkcs12(input: ExportPkcs12Input): Promise<Uint8Array> {
  const iterations = input.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  const macIterations = input.macIterations ?? DEFAULT_MAC_ITERATIONS;
  validateInput(input, iterations, macIterations);

  const spkiDer = extractCertificateSpkiDer(input.certDer);
  const localKeyId = await keyIdentifierFromSpki(spkiDer);

  const friendlyNameAttr = input.friendlyName !== undefined && input.friendlyName.length > 0
    ? buildFriendlyNameAttr(input.friendlyName)
    : undefined;
  const localKeyIdAttr = buildLocalKeyIdAttr(localKeyId);

  const leafAttrs = friendlyNameAttr ? [localKeyIdAttr, friendlyNameAttr] : [localKeyIdAttr];

  const certBags: Uint8Array[] = [buildCertSafeBag(input.certDer, leafAttrs)];
  if (input.chainDer) {
    for (const c of input.chainDer) {
      certBags.push(buildCertSafeBag(c, []));
    }
  }
  const certSafeContents = sequence(...certBags);

  // Import the password into a non-extractable PBKDF2 baseKey once and reuse
  // it across both cert-bag and key-bag encryption. This halves the number of
  // password-byte ArrayBuffer copies handed to WebCrypto (which we cannot
  // wipe) from two to one.
  const pbkdf2BaseKey = await crypto.subtle.importKey(
    "raw",
    arrayBufferFromBytes(input.password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const certEncrypted = await pbes2EncryptAesCbc(certSafeContents, pbkdf2BaseKey, iterations);
  const certContentInfo = sequence(
    oid(OID.encryptedData),
    explicit(0, sequence(
      integer(0n),
      sequence(
        oid(OID.data),
        certEncrypted.algorithm,
        contextPrimitive(0, certEncrypted.ciphertext)
      )
    ))
  );

  const keyEncrypted = await pbes2EncryptAesCbc(input.privateKey, pbkdf2BaseKey, iterations);

  const epki = sequence(keyEncrypted.algorithm, octetString(keyEncrypted.ciphertext));
  const keyBag = buildKeySafeBag(epki, leafAttrs);
  const keySafeContents = sequence(keyBag);
  const keyContentInfo = sequence(
    oid(OID.data),
    explicit(0, octetString(keySafeContents))
  );

  const authenticatedSafe = sequence(certContentInfo, keyContentInfo);

  const macSalt = randomBytes(SALT_LENGTH);
  const passwordUtf16 = utf8ToUtf16BeWithTerminator(input.password);
  const macKey = await pkcs12V1KdfMacKey(passwordUtf16, macSalt, macIterations);
  wipe(passwordUtf16);

  const macKeyHandle = await crypto.subtle.importKey(
    "raw",
    arrayBufferFromBytes(macKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  wipe(macKey);
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", macKeyHandle, arrayBufferFromBytes(authenticatedSafe))
  );

  const macData = sequence(
    sequence(
      sequence(oid(OID.sha256), nullValue()),
      octetString(mac)
    ),
    octetString(macSalt),
    integer(BigInt(macIterations))
  );

  const pfxAuthSafeContentInfo = sequence(
    oid(OID.data),
    explicit(0, octetString(authenticatedSafe))
  );

  return sequence(integer(3n), pfxAuthSafeContentInfo, macData);
}

function validateInput(input: ExportPkcs12Input, iterations: number, macIterations: number): void {
  if (!(input.certDer instanceof Uint8Array) || input.certDer.length === 0) {
    throw new Error("certDer must be a non-empty Uint8Array of certificate DER bytes");
  }
  if (input.chainDer !== undefined) {
    if (!Array.isArray(input.chainDer)) {
      throw new Error("chainDer must be an array of Uint8Array");
    }
    for (const entry of input.chainDer) {
      if (!(entry instanceof Uint8Array) || entry.length === 0) {
        throw new Error("chainDer entries must be non-empty Uint8Array");
      }
    }
  }
  if (!(input.password instanceof Uint8Array) || input.password.length === 0) {
    throw new Error("password must be a non-empty Uint8Array of UTF-8 bytes");
  }
  if (!(input.privateKey instanceof Uint8Array) || input.privateKey.length === 0) {
    throw new Error("privateKey must be a non-empty Uint8Array of PKCS#8 DER bytes");
  }
  if (!Number.isInteger(iterations) || iterations < 1) {
    throw new Error("iterations must be a positive integer");
  }
  if (!Number.isInteger(macIterations) || macIterations < 1) {
    throw new Error("macIterations must be a positive integer");
  }
  if (input.friendlyName !== undefined && !(input.friendlyName instanceof Uint8Array)) {
    throw new Error("friendlyName must be a Uint8Array of UTF-8 bytes");
  }
}

function buildCertSafeBag(certDer: Uint8Array, attrs: Uint8Array[]): Uint8Array {
  const certBagInner = sequence(
    oid(OID.x509Certificate),
    explicit(0, octetString(certDer))
  );
  return safeBag(OID.certBag, certBagInner, attrs);
}

function buildKeySafeBag(encryptedPrivateKeyInfo: Uint8Array, attrs: Uint8Array[]): Uint8Array {
  return safeBag(OID.pkcs8ShroudedKeyBag, encryptedPrivateKeyInfo, attrs);
}

function safeBag(bagOid: string, bagValue: Uint8Array, attrs: Uint8Array[]): Uint8Array {
  const parts: Uint8Array[] = [oid(bagOid), explicit(0, bagValue)];
  if (attrs.length > 0) {
    parts.push(canonicalSetOf(attrs));
  }
  return sequence(...parts);
}

// X.690 §11.6: SET OF components are encoded in ascending order of their
// encoded octet strings, with the shorter component padded with trailing
// 0-octets for the comparison. Used for bagAttributes.
function canonicalSetOf(children: Uint8Array[]): Uint8Array {
  const sorted = [...children].sort(derSetCompare);
  return set(...sorted);
}

function derSetCompare(a: Uint8Array, b: Uint8Array): number {
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    const av = i < a.length ? a[i]! : 0;
    const bv = i < b.length ? b[i]! : 0;
    if (av !== bv) return av - bv;
  }
  return 0;
}

function buildLocalKeyIdAttr(localKeyId: Uint8Array): Uint8Array {
  return sequence(oid(OID.localKeyId), set(octetString(localKeyId)));
}

function buildFriendlyNameAttr(friendlyNameUtf8: Uint8Array): Uint8Array {
  return sequence(oid(OID.friendlyName), set(bmpString(friendlyNameUtf8)));
}

function bmpString(utf8: Uint8Array): Uint8Array {
  const utf16 = utf8ToUtf16Be(utf8);
  return der(0x1e, utf16);
}

async function pbes2EncryptAesCbc(
  plaintext: Uint8Array,
  pbkdf2BaseKey: CryptoKey,
  iterations: number
): Promise<{ algorithm: Uint8Array; ciphertext: Uint8Array }> {
  const salt = randomBytes(SALT_LENGTH);
  const iv = randomBytes(IV_LENGTH);

  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: arrayBufferFromBytes(salt), iterations, hash: "SHA-256" },
    pbkdf2BaseKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"]
  );
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-CBC", iv: arrayBufferFromBytes(iv) },
      aesKey,
      arrayBufferFromBytes(plaintext)
    )
  );

  return {
    algorithm: algorithmIdentifierPbes2(salt, iterations, iv),
    ciphertext
  };
}

function algorithmIdentifierPbes2(salt: Uint8Array, iterations: number, iv: Uint8Array): Uint8Array {
  const pbkdf2Params = sequence(
    octetString(salt),
    integer(BigInt(iterations)),
    sequence(oid(OID.hmacWithSha256), nullValue())
  );
  const keyDerivationFunc = sequence(oid(OID.pbkdf2), pbkdf2Params);
  const encryptionScheme = sequence(oid(OID.aes256Cbc), octetString(iv));
  return sequence(oid(OID.pbes2), sequence(keyDerivationFunc, encryptionScheme));
}

// PKCS#12 v1 KDF (RFC 7292 App.B) producing an HMAC-SHA-256 key (32 bytes).
// Specialized for ID=3, n=u=32, v=64. Single-block output: no I update needed.
async function pkcs12V1KdfMacKey(
  passwordUtf16: Uint8Array,
  salt: Uint8Array,
  iterations: number
): Promise<Uint8Array> {
  const v = SHA256_BLOCK_SIZE;

  const D = new Uint8Array(v).fill(PKCS12_KDF_ID_MAC);

  const sLen = Math.ceil(salt.length / v) * v;
  const S2 = new Uint8Array(sLen);
  for (let i = 0; i < sLen; i += 1) {
    S2[i] = salt[i % salt.length]!;
  }

  const pLen = Math.ceil(passwordUtf16.length / v) * v;
  const P2 = new Uint8Array(pLen);
  for (let i = 0; i < pLen; i += 1) {
    P2[i] = passwordUtf16[i % passwordUtf16.length]!;
  }

  const I = concatBytes([S2, P2]);

  // T_0 holds D || S2 || P2 (raw password bytes embedded in P2).
  // Each digestSha256 returns a fresh 32-byte buffer; the previous T's buffer
  // becomes unreachable but, without an explicit wipe, would sit on the JS
  // heap until GC. Zero it before reassigning. Successive Ts are H^j(D||I)
  // values, which let an attacker reach H^c(D||I) = MAC key by continuing the
  // chain — they're as sensitive as the MAC key itself.
  let T = concatBytes([D, I]);
  for (let j = 0; j < iterations; j += 1) {
    const next = await digestSha256(T);
    T.fill(0);
    T = next;
  }

  wipe(D, S2, P2, I);
  return T.subarray(0, MAC_KEY_LENGTH);
}

// Convert UTF-8 bytes to UTF-16BE bytes plus a 0x00 0x00 terminator,
// without going through any JavaScript string. Walks code points by hand.
function utf8ToUtf16BeWithTerminator(utf8: Uint8Array): Uint8Array {
  const utf16 = utf8ToUtf16Be(utf8);
  const out = new Uint8Array(utf16.length + 2);
  out.set(utf16, 0);
  wipe(utf16);
  return out;
}

// Two-pass to avoid an intermediate `number[]` that would retain
// password-derived bytes on the JS heap until GC. Pass 1 sizes the output;
// pass 2 writes directly into a tight Uint8Array. Both passes share the same
// boundary checks so an invalid leader byte fails fast in pass 1.
function utf8ToUtf16Be(utf8: Uint8Array): Uint8Array {
  let outLen = 0;
  let i = 0;
  while (i < utf8.length) {
    const b1 = utf8[i]!;
    if (b1 < 0x80) {
      outLen += 2;
      i += 1;
    } else if ((b1 & 0xe0) === 0xc0 && i + 1 < utf8.length) {
      outLen += 2;
      i += 2;
    } else if ((b1 & 0xf0) === 0xe0 && i + 2 < utf8.length) {
      outLen += 2;
      i += 3;
    } else if ((b1 & 0xf8) === 0xf0 && i + 3 < utf8.length) {
      outLen += 4;
      i += 4;
    } else {
      throw new Error("Invalid UTF-8 sequence");
    }
  }

  const out = new Uint8Array(outLen);
  let oi = 0;
  i = 0;
  while (i < utf8.length) {
    const b1 = utf8[i]!;
    let cp: number;
    if (b1 < 0x80) {
      cp = b1;
      i += 1;
    } else if ((b1 & 0xe0) === 0xc0) {
      cp = ((b1 & 0x1f) << 6) | (utf8[i + 1]! & 0x3f);
      i += 2;
    } else if ((b1 & 0xf0) === 0xe0) {
      cp = ((b1 & 0x0f) << 12) | ((utf8[i + 1]! & 0x3f) << 6) | (utf8[i + 2]! & 0x3f);
      i += 3;
    } else {
      cp = ((b1 & 0x07) << 18)
        | ((utf8[i + 1]! & 0x3f) << 12)
        | ((utf8[i + 2]! & 0x3f) << 6)
        | (utf8[i + 3]! & 0x3f);
      i += 4;
    }

    if (cp < 0x10000) {
      out[oi++] = (cp >> 8) & 0xff;
      out[oi++] = cp & 0xff;
    } else {
      const adj = cp - 0x10000;
      const high = 0xd800 + ((adj >> 10) & 0x3ff);
      const low = 0xdc00 + (adj & 0x3ff);
      out[oi++] = (high >> 8) & 0xff;
      out[oi++] = high & 0xff;
      out[oi++] = (low >> 8) & 0xff;
      out[oi++] = low & 0xff;
    }
  }
  return out;
}

function wipe(...bufs: Uint8Array[]): void {
  for (const b of bufs) {
    b.fill(0);
  }
}
