import { Buffer } from "node:buffer";
import * as tls from "node:tls";
import { describe, expect, it } from "vitest";
import { createRootCA, exportPkcs12, issueClientCert } from "../src/index.js";
import { bytesEqual } from "../src/bytes.js";
import {
  decodeInteger,
  decodeOid,
  readChildren,
  readElement,
  readSequenceChildren,
  TAG
} from "../src/der.js";
import { parseCertificateDer } from "../src/parser.js";

const TEST_ITERATIONS = 2048;
const TEST_MAC_ITERATIONS = 2048;

async function makeCertAndKey() {
  const ca = await createRootCA({
    subject: [{ type: "CN", value: "EdgCA Test Root" }],
    days: 30
  });
  const issued = await issueClientCert({
    ca,
    subject: [{ type: "CN", value: "client" }],
    days: 7
  });
  return { ca, issued };
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

describe("exportPkcs12", () => {
  it("produces a PFX that Node's tls.createSecureContext accepts", async () => {
    const { issued } = await makeCertAndKey();
    const passphrase = "p@ssw0rd-✓";
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password: utf8(passphrase),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase })
    ).not.toThrow();
  });

  it("throws on wrong password when consumed by Node", async () => {
    const { issued } = await makeCertAndKey();
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password: utf8("right"),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase: "wrong" })
    ).toThrow();
  });

  it("round-trips: extracted private key signs, cert public key verifies", async () => {
    const { issued } = await makeCertAndKey();
    const password = utf8("round-trip");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    const importedKey = await crypto.subtle.importKey(
      "pkcs8",
      bufferOf(parsed.keyPkcs8),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    const data = utf8("hello");
    const sig = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, importedKey, bufferOf(data))
    );
    const cert = await parseCertificateDer(issued.certDer);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      cert.publicKey,
      bufferOf(sig),
      bufferOf(data)
    );
    expect(ok).toBe(true);
  });

  it("emits matching localKeyID on cert bag and key bag", async () => {
    const { issued } = await makeCertAndKey();
    const password = utf8("local-key-id");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    expect(parsed.certLocalKeyId).toBeDefined();
    expect(parsed.keyLocalKeyId).toBeDefined();
    expect(parsed.certLocalKeyId!.length).toBe(20);
    expect(bytesEqual(parsed.certLocalKeyId!, parsed.keyLocalKeyId!)).toBe(true);
  });
});

// --- minimal PKCS#12 parser (test helper, not under test) -------------------

const OID_DATA = "1.2.840.113549.1.7.1";
const OID_ENCRYPTED_DATA = "1.2.840.113549.1.7.6";
const OID_PBES2 = "1.2.840.113549.1.5.13";
const OID_PBKDF2 = "1.2.840.113549.1.5.12";
const OID_AES_256_CBC = "2.16.840.1.101.3.4.1.42";
const OID_HMAC_SHA256 = "1.2.840.113549.2.9";
const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";
const OID_KEY_BAG_SHROUDED = "1.2.840.113549.1.12.10.1.2";
const OID_LOCAL_KEY_ID = "1.2.840.113549.1.9.21";

interface PfxParsed {
  keyPkcs8: Uint8Array;
  certLocalKeyId: Uint8Array | undefined;
  keyLocalKeyId: Uint8Array | undefined;
}

async function parsePfx(pfx: Uint8Array, password: Uint8Array): Promise<PfxParsed> {
  const root = readElement(pfx);
  const [, authSafeContentInfo] = readSequenceChildren(root);
  if (!authSafeContentInfo) throw new Error("missing authSafe");

  const [, authSafeContent] = readSequenceChildren(authSafeContentInfo);
  if (!authSafeContent || authSafeContent.tag !== 0xa0) throw new Error("missing authSafe content [0]");
  const authSafeOctet = readElement(authSafeContent.value);
  if (authSafeOctet.tag !== TAG.OCTET_STRING) throw new Error("authSafe must be OCTET STRING");
  const authSafe = readElement(authSafeOctet.value);

  let certLocalKeyId: Uint8Array | undefined;
  let keyLocalKeyId: Uint8Array | undefined;
  let keyPkcs8: Uint8Array | undefined;

  for (const contentInfo of readSequenceChildren(authSafe)) {
    const ciChildren = readSequenceChildren(contentInfo);
    const ciOid = decodeOid(ciChildren[0]!.value);
    const ciContent = ciChildren[1]!;
    if (ciContent.tag !== 0xa0) throw new Error("ContentInfo content must be [0]");

    if (ciOid === OID_DATA) {
      const inner = readElement(ciContent.value);
      if (inner.tag !== TAG.OCTET_STRING) throw new Error("Data ContentInfo content must wrap OCTET STRING");
      const safeContents = readElement(inner.value);
      for (const safeBag of readSequenceChildren(safeContents)) {
        const bag = readSafeBag(safeBag);
        if (bag.bagId === OID_KEY_BAG_SHROUDED) {
          const epki = readElement(bag.bagValue);
          const epkiChildren = readSequenceChildren(epki);
          const algo = epkiChildren[0]!;
          const ct = epkiChildren[1]!;
          if (ct.tag !== TAG.OCTET_STRING) throw new Error("EPKI encryptedData must be OCTET STRING");
          keyPkcs8 = await pbes2Decrypt(algo.raw, ct.value, password);
          keyLocalKeyId = bag.localKeyId;
        }
      }
    } else if (ciOid === OID_ENCRYPTED_DATA) {
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
        if (bag.bagId === OID_CERT_BAG && bag.localKeyId !== undefined && certLocalKeyId === undefined) {
          certLocalKeyId = bag.localKeyId;
        }
      }
    }
  }

  if (!keyPkcs8) throw new Error("PFX did not contain a key bag");

  return { keyPkcs8, certLocalKeyId, keyLocalKeyId };
}

interface SafeBag {
  bagId: string;
  bagValue: Uint8Array;
  localKeyId: Uint8Array | undefined;
}

function readSafeBag(safeBag: { value: Uint8Array; tag: number }): SafeBag {
  if (safeBag.tag !== TAG.SEQUENCE) throw new Error("SafeBag must be SEQUENCE");
  const children = readChildren(safeBag.value);
  const bagId = decodeOid(children[0]!.value);
  if (children[1]!.tag !== 0xa0) throw new Error("SafeBag bagValue must be [0]");
  const bagValue = children[1]!.value;
  let localKeyId: Uint8Array | undefined;
  if (children[2] && children[2].tag === TAG.SET) {
    for (const attr of readChildren(children[2].value)) {
      const ac = readSequenceChildren(attr);
      if (decodeOid(ac[0]!.value) === OID_LOCAL_KEY_ID) {
        const setEl = readChildren(ac[1]!.value)[0]!;
        localKeyId = setEl.value;
      }
    }
  }
  return { bagId, bagValue, localKeyId };
}

async function pbes2Decrypt(
  algorithmDer: Uint8Array,
  ciphertext: Uint8Array,
  password: Uint8Array
): Promise<Uint8Array> {
  const algo = readElement(algorithmDer);
  const algoChildren = readSequenceChildren(algo);
  if (decodeOid(algoChildren[0]!.value) !== OID_PBES2) throw new Error("expected PBES2");
  const params = readSequenceChildren(algoChildren[1]!);
  const kdf = readSequenceChildren(params[0]!);
  if (decodeOid(kdf[0]!.value) !== OID_PBKDF2) throw new Error("expected PBKDF2");
  const kdfParams = readSequenceChildren(kdf[1]!);
  const salt = kdfParams[0]!.value;
  const iterations = Number(decodeInteger(kdfParams[1]!.value));
  const prfChildren = readSequenceChildren(kdfParams[2]!);
  if (decodeOid(prfChildren[0]!.value) !== OID_HMAC_SHA256) throw new Error("expected HMAC-SHA-256 prf");

  const enc = readSequenceChildren(params[1]!);
  if (decodeOid(enc[0]!.value) !== OID_AES_256_CBC) throw new Error("expected AES-256-CBC");
  const iv = enc[1]!.value;

  const baseKey = await crypto.subtle.importKey(
    "raw",
    bufferOf(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: bufferOf(salt), iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"]
  );
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-CBC", iv: bufferOf(iv) }, aesKey, bufferOf(ciphertext))
  );
}

function bufferOf(b: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(b.length);
  out.set(b);
  return out.buffer;
}
