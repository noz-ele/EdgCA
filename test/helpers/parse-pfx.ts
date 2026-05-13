// Minimal PKCS#12 parser for tests. NOT under test, NOT exported by the
// library. Reads the PFX structure, decrypts the EncryptedData cert bag and
// the pkcs8ShroudedKeyBag with PBES2 (PBKDF2-HMAC-SHA-256 + AES-256-CBC), and
// returns the raw cert / key bag payloads. Used by both pkcs12.node.test.ts
// (focused exportPkcs12 tests) and cli.node.test.ts (CLI-level round-trip).

import { arrayBufferFromBytes } from "../../src/bytes.js";
import {
  decodeInteger,
  decodeOid,
  readChildren,
  readElement,
  readSequenceChildren,
  TAG
} from "../../src/der.js";
import { OID } from "../../src/oids.js";

export interface ParsedSafeBag {
  bagId: string;
  bagValue: Uint8Array;
  localKeyId: Uint8Array | undefined;
  friendlyName: Uint8Array | undefined;
  attrOidsInOrder: string[];
}

export interface PfxParsed {
  keyPkcs8: Uint8Array;
  certBags: ParsedSafeBag[];
  keyBag: ParsedSafeBag;
}

export async function parsePfx(pfx: Uint8Array, password: Uint8Array): Promise<PfxParsed> {
  const root = readElement(pfx);
  const [, authSafeContentInfo] = readSequenceChildren(root);
  if (!authSafeContentInfo) throw new Error("missing authSafe");

  const [, authSafeContent] = readSequenceChildren(authSafeContentInfo);
  if (!authSafeContent || authSafeContent.tag !== 0xa0) throw new Error("missing authSafe content [0]");
  const authSafeOctet = readElement(authSafeContent.value);
  if (authSafeOctet.tag !== TAG.OCTET_STRING) throw new Error("authSafe must be OCTET STRING");
  const authSafe = readElement(authSafeOctet.value);

  const certBags: ParsedSafeBag[] = [];
  let keyBag: ParsedSafeBag | undefined;
  let keyPkcs8: Uint8Array | undefined;

  for (const contentInfo of readSequenceChildren(authSafe)) {
    const ciChildren = readSequenceChildren(contentInfo);
    const ciOid = decodeOid(ciChildren[0]!.value);
    const ciContent = ciChildren[1]!;
    if (ciContent.tag !== 0xa0) throw new Error("ContentInfo content must be [0]");

    if (ciOid === OID.data) {
      const inner = readElement(ciContent.value);
      if (inner.tag !== TAG.OCTET_STRING) throw new Error("Data ContentInfo content must wrap OCTET STRING");
      const safeContents = readElement(inner.value);
      for (const safeBag of readSequenceChildren(safeContents)) {
        const bag = readSafeBag(safeBag);
        if (bag.bagId === OID.pkcs8ShroudedKeyBag) {
          const epki = readElement(bag.bagValue);
          const epkiChildren = readSequenceChildren(epki);
          const algo = epkiChildren[0]!;
          const ct = epkiChildren[1]!;
          if (ct.tag !== TAG.OCTET_STRING) throw new Error("EPKI encryptedData must be OCTET STRING");
          keyPkcs8 = await pbes2Decrypt(algo.raw, ct.value, password);
          keyBag = bag;
        }
      }
    } else if (ciOid === OID.encryptedData) {
      const enc = readElement(ciContent.value);
      const encChildren = readSequenceChildren(enc);
      const eci = readSequenceChildren(encChildren[1]!);
      const algo = eci[1]!;
      const ct = eci[2]!;
      if (ct.tag !== 0x80) throw new Error("encryptedContent must be [0] IMPLICIT OCTET STRING");
      const plaintext = await pbes2Decrypt(algo.raw, ct.value, password);
      const certSafeContents = readElement(plaintext);
      for (const safeBag of readSequenceChildren(certSafeContents)) {
        const bag = readSafeBag(safeBag);
        if (bag.bagId === OID.certBag) {
          certBags.push(bag);
        }
      }
    }
  }

  if (!keyPkcs8 || !keyBag) throw new Error("PFX did not contain a key bag");

  return { keyPkcs8, certBags, keyBag };
}

function readSafeBag(safeBag: { value: Uint8Array; tag: number }): ParsedSafeBag {
  if (safeBag.tag !== TAG.SEQUENCE) throw new Error("SafeBag must be SEQUENCE");
  const children = readChildren(safeBag.value);
  const bagId = decodeOid(children[0]!.value);
  if (children[1]!.tag !== 0xa0) throw new Error("SafeBag bagValue must be [0]");
  const bagValue = children[1]!.value;
  let localKeyId: Uint8Array | undefined;
  let friendlyName: Uint8Array | undefined;
  const attrOidsInOrder: string[] = [];
  if (children[2] && children[2].tag === TAG.SET) {
    for (const attr of readChildren(children[2].value)) {
      const ac = readSequenceChildren(attr);
      const attrOid = decodeOid(ac[0]!.value);
      attrOidsInOrder.push(attrOid);
      const attrSet = readChildren(ac[1]!.value)[0];
      if (!attrSet) continue;
      if (attrOid === OID.localKeyId) {
        localKeyId = attrSet.value;
      } else if (attrOid === OID.friendlyName) {
        friendlyName = attrSet.value;
      }
    }
  }
  return { bagId, bagValue, localKeyId, friendlyName, attrOidsInOrder };
}

async function pbes2Decrypt(
  algorithmDer: Uint8Array,
  ciphertext: Uint8Array,
  password: Uint8Array
): Promise<Uint8Array> {
  const algo = readElement(algorithmDer);
  const algoChildren = readSequenceChildren(algo);
  if (decodeOid(algoChildren[0]!.value) !== OID.pbes2) throw new Error("expected PBES2");
  const params = readSequenceChildren(algoChildren[1]!);
  const kdf = readSequenceChildren(params[0]!);
  if (decodeOid(kdf[0]!.value) !== OID.pbkdf2) throw new Error("expected PBKDF2");
  const kdfParams = readSequenceChildren(kdf[1]!);
  const salt = kdfParams[0]!.value;
  const iterations = Number(decodeInteger(kdfParams[1]!.value));
  const prfChildren = readSequenceChildren(kdfParams[2]!);
  if (decodeOid(prfChildren[0]!.value) !== OID.hmacWithSha256) throw new Error("expected HMAC-SHA-256 prf");

  const enc = readSequenceChildren(params[1]!);
  if (decodeOid(enc[0]!.value) !== OID.aes256Cbc) throw new Error("expected AES-256-CBC");
  const iv = enc[1]!.value;

  const baseKey = await crypto.subtle.importKey(
    "raw",
    arrayBufferFromBytes(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: arrayBufferFromBytes(salt), iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"]
  );
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: arrayBufferFromBytes(iv) },
      aesKey,
      arrayBufferFromBytes(ciphertext)
    )
  );
}
