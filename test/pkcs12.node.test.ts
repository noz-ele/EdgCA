import { Buffer } from "node:buffer";
import * as tls from "node:tls";
import { describe, expect, it } from "vitest";
import {
  createRootCA,
  exportPkcs12,
  issueClientCert,
  issueIntermediateCA
} from "../src/index.js";
import { arrayBufferFromBytes, bytesEqual } from "../src/bytes.js";
import {
  decodeInteger,
  decodeOid,
  readChildren,
  readElement,
  readSequenceChildren,
  TAG
} from "../src/der.js";
import { OID } from "../src/oids.js";
import { parseCertificateDer } from "../src/parser.js";

const TEST_ITERATIONS = 2048;
const TEST_MAC_ITERATIONS = 2048;

async function makeRootAndLeaf() {
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
    const { issued } = await makeRootAndLeaf();
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
    const { issued } = await makeRootAndLeaf();
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
    const { issued } = await makeRootAndLeaf();
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
      arrayBufferFromBytes(parsed.keyPkcs8),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    const data = utf8("hello");
    const sig = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, importedKey, arrayBufferFromBytes(data))
    );
    const cert = await parseCertificateDer(issued.certDer);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      cert.publicKey,
      arrayBufferFromBytes(sig),
      arrayBufferFromBytes(data)
    );
    expect(ok).toBe(true);
  });

  it("emits matching localKeyID on cert bag and key bag", async () => {
    const { issued } = await makeRootAndLeaf();
    const password = utf8("local-key-id");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    const leafLocalKeyId = parsed.certBags[0]?.localKeyId;
    expect(leafLocalKeyId).toBeDefined();
    expect(parsed.keyBag.localKeyId).toBeDefined();
    expect(leafLocalKeyId!.length).toBe(20);
    expect(bytesEqual(leafLocalKeyId!, parsed.keyBag.localKeyId!)).toBe(true);
  });

  it("rejects an empty password", async () => {
    const { issued } = await makeRootAndLeaf();
    await expect(
      exportPkcs12({
        certDer: issued.certDer,
        privateKey: issued.privateKey,
        password: new Uint8Array(0),
        iterations: TEST_ITERATIONS,
        macIterations: TEST_MAC_ITERATIONS
      })
    ).rejects.toThrow(/password/);
  });

  it("rejects a non-extractable private key", async () => {
    const { issued } = await makeRootAndLeaf();
    const sealed = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
    await expect(
      exportPkcs12({
        certDer: issued.certDer,
        privateKey: sealed.privateKey,
        password: utf8("p"),
        iterations: TEST_ITERATIONS,
        macIterations: TEST_MAC_ITERATIONS
      })
    ).rejects.toThrow(/extractable/);
  });

  it("rejects a non-ECDSA private key", async () => {
    const { issued } = await makeRootAndLeaf();
    const rsa = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );
    await expect(
      exportPkcs12({
        certDer: issued.certDer,
        privateKey: rsa.privateKey,
        password: utf8("p"),
        iterations: TEST_ITERATIONS,
        macIterations: TEST_MAC_ITERATIONS
      })
    ).rejects.toThrow(/ECDSA/);
  });

  it("includes chain certificates and Node accepts the chained PFX", async () => {
    const root = await createRootCA({
      subject: [{ type: "CN", value: "EdgCA Test Root" }],
      days: 30,
      pathLenConstraint: 1
    });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: [{ type: "CN", value: "EdgCA Test Intermediate" }],
      days: 14
    });
    const leaf = await issueClientCert({
      ca: intermediate,
      subject: [{ type: "CN", value: "client" }],
      days: 7
    });

    const passphrase = "chain";
    const pfx = await exportPkcs12({
      certDer: leaf.certDer,
      chainDer: [intermediate.certDer],
      privateKey: leaf.privateKey,
      password: utf8(passphrase),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase })
    ).not.toThrow();

    const parsed = await parsePfx(pfx, utf8(passphrase));
    expect(parsed.certBags.length).toBe(2);
    expect(parsed.certBags[0]!.localKeyId).toBeDefined();
    expect(parsed.certBags[1]!.localKeyId).toBeUndefined();
    expect(parsed.certBags[1]!.friendlyName).toBeUndefined();
  });

  it("emits friendlyName as BMPString on leaf cert bag and key bag only", async () => {
    const { issued } = await makeRootAndLeaf();
    const password = utf8("name");
    const friendlyName = utf8("EdgCA Test Client");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      friendlyName,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    expect(parsed.certBags[0]!.friendlyName).toBeDefined();
    expect(parsed.keyBag.friendlyName).toBeDefined();

    // Re-encode the input as UTF-16BE (without terminator) and compare.
    const expected = utf16Be("EdgCA Test Client");
    expect(bytesEqual(parsed.certBags[0]!.friendlyName!, expected)).toBe(true);
    expect(bytesEqual(parsed.keyBag.friendlyName!, expected)).toBe(true);
  });

  it("handles a password whose UTF-8 produces a UTF-16 surrogate pair", async () => {
    const { issued } = await makeRootAndLeaf();
    // U+1F510 (🔐) is 4 bytes in UTF-8 and a surrogate pair in UTF-16BE.
    const passphrase = "lock-🔐";
    const password = utf8(passphrase);
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    // Node uses the PKCS#12 v1 KDF on the BMPString-encoded password, which
    // is exactly what our exporter feeds to the MAC. Acceptance proves that
    // both the PBES2 (UTF-8) and the MAC (UTF-16BE with surrogate pair) paths
    // round-trip correctly.
    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase })
    ).not.toThrow();

    // Wrong-password path with the same surrogate-bearing exporter still
    // rejects, proving the MAC is not silently degenerate.
    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase: "lock-🔐 " })
    ).toThrow();
  });
});

// --- helpers --------------------------------------------------------------

function utf16Be(s: string): Uint8Array {
  // Build UTF-16BE bytes (no terminator) for comparison with the BMPString
  // payload extracted from the PFX. Test-only — uses JS string indexing.
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    out.push((code >> 8) & 0xff, code & 0xff);
  }
  return new Uint8Array(out);
}

// --- minimal PKCS#12 parser (test helper, not under test) ------------------

interface ParsedSafeBag {
  bagId: string;
  bagValue: Uint8Array;
  localKeyId: Uint8Array | undefined;
  friendlyName: Uint8Array | undefined;
}

interface PfxParsed {
  keyPkcs8: Uint8Array;
  certBags: ParsedSafeBag[];
  keyBag: ParsedSafeBag;
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
  if (children[2] && children[2].tag === TAG.SET) {
    for (const attr of readChildren(children[2].value)) {
      const ac = readSequenceChildren(attr);
      const attrOid = decodeOid(ac[0]!.value);
      const attrSet = readChildren(ac[1]!.value)[0];
      if (!attrSet) continue;
      if (attrOid === OID.localKeyId) {
        localKeyId = attrSet.value;
      } else if (attrOid === OID.friendlyName) {
        friendlyName = attrSet.value;
      }
    }
  }
  return { bagId, bagValue, localKeyId, friendlyName };
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
