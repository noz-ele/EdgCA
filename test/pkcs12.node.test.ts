import { Buffer } from "node:buffer";
import * as tls from "node:tls";
import { describe, expect, it } from "vitest";
import {
  createRootCA,
  exportPkcs12,
  issueClientCert,
  issueClientCertForPublicKey,
  issueIntermediateCA
} from "../src/index.js";
import { arrayBufferFromBytes, bytesEqual, concatBytes } from "../src/bytes.js";
import { generateKeyPair, type SupportedCurve } from "../src/crypto.js";
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
import { parsePfx } from "./helpers/parse-pfx.js";

const TEST_ITERATIONS = 2048;
const TEST_MAC_ITERATIONS = 2048;

const HASH_BY_CURVE: Record<SupportedCurve, "SHA-256" | "SHA-384" | "SHA-512"> = {
  "P-256": "SHA-256",
  "P-384": "SHA-384",
  "P-521": "SHA-512"
};

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

async function signRoundTripsViaPfx(
  certDer: Uint8Array,
  password: Uint8Array,
  pfx: Uint8Array
): Promise<boolean> {
  const parsed = await parsePfx(pfx, password);
  const cert = await parseCertificateDer(certDer);
  const namedCurve = (cert.publicKey.algorithm as { namedCurve?: SupportedCurve }).namedCurve;
  if (!namedCurve) throw new Error("cert has no namedCurve");
  const hash = HASH_BY_CURVE[namedCurve];
  const importedKey = await crypto.subtle.importKey(
    "pkcs8",
    arrayBufferFromBytes(parsed.keyPkcs8),
    { name: "ECDSA", namedCurve },
    false,
    ["sign"]
  );
  const data = utf8("hello");
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash }, importedKey, arrayBufferFromBytes(data))
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash },
    cert.publicKey,
    arrayBufferFromBytes(sig),
    arrayBufferFromBytes(data)
  );
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

  it("round-trips: extracted private key signs, cert public key verifies (P-256)", async () => {
    const { issued } = await makeRootAndLeaf();
    const password = utf8("round-trip");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    expect(await signRoundTripsViaPfx(issued.certDer, password, pfx)).toBe(true);
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

  it("rejects a non-Uint8Array password (caller passed a string)", async () => {
    const { issued } = await makeRootAndLeaf();
    await expect(
      exportPkcs12({
        certDer: issued.certDer,
        privateKey: issued.privateKey,
        // intentionally wrong runtime type
        password: "raw-string" as unknown as Uint8Array,
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

  it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    "rejects iterations=%s",
    async (bad) => {
      const { issued } = await makeRootAndLeaf();
      await expect(
        exportPkcs12({
          certDer: issued.certDer,
          privateKey: issued.privateKey,
          password: utf8("p"),
          iterations: bad,
          macIterations: TEST_MAC_ITERATIONS
        })
      ).rejects.toThrow(/iterations/);
    }
  );

  it.each([0, -1, 1.5, Number.NaN])(
    "rejects macIterations=%s",
    async (bad) => {
      const { issued } = await makeRootAndLeaf();
      await expect(
        exportPkcs12({
          certDer: issued.certDer,
          privateKey: issued.privateKey,
          password: utf8("p"),
          iterations: TEST_ITERATIONS,
          macIterations: bad
        })
      ).rejects.toThrow(/macIterations/);
    }
  );

  it("rejects a non-Uint8Array friendlyName", async () => {
    const { issued } = await makeRootAndLeaf();
    await expect(
      exportPkcs12({
        certDer: issued.certDer,
        privateKey: issued.privateKey,
        password: utf8("p"),
        // intentionally wrong runtime type
        friendlyName: "label" as unknown as Uint8Array,
        iterations: TEST_ITERATIONS,
        macIterations: TEST_MAC_ITERATIONS
      })
    ).rejects.toThrow(/friendlyName/);
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

  it("emits 3 cert bags when chainDer has 2 entries (intermediate + root)", async () => {
    // EdgCA only permits pathLenConstraint 0 or 1 on a root, so we cannot
    // produce a real 3-level chain here. exportPkcs12 doesn't validate the
    // chain anyway — it just emits one CertBag per DER. Including the root
    // alongside the intermediate is realistic ("export the whole chain")
    // and exercises the chainDer.length >= 2 path.
    const root = await createRootCA({
      subject: [{ type: "CN", value: "Multi Root" }],
      days: 30,
      pathLenConstraint: 1
    });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: [{ type: "CN", value: "Multi Intermediate" }],
      days: 14
    });
    const leaf = await issueClientCert({
      ca: intermediate,
      subject: [{ type: "CN", value: "multi-leaf" }],
      days: 7
    });

    const password = utf8("multi");
    const pfx = await exportPkcs12({
      certDer: leaf.certDer,
      chainDer: [intermediate.certDer, root.certDer],
      privateKey: leaf.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    expect(parsed.certBags.length).toBe(3);
    expect(parsed.certBags[0]!.localKeyId).toBeDefined();
    expect(parsed.certBags[1]!.localKeyId).toBeUndefined();
    expect(parsed.certBags[2]!.localKeyId).toBeUndefined();
    expect(parsed.certBags[1]!.friendlyName).toBeUndefined();
    expect(parsed.certBags[2]!.friendlyName).toBeUndefined();
  });

  it("treats chainDer=[] as no chain", async () => {
    const { issued } = await makeRootAndLeaf();
    const password = utf8("empty-chain");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      chainDer: [],
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    expect(parsed.certBags.length).toBe(1);
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

    const expected = utf16Be("EdgCA Test Client");
    expect(bytesEqual(parsed.certBags[0]!.friendlyName!, expected)).toBe(true);
    expect(bytesEqual(parsed.keyBag.friendlyName!, expected)).toBe(true);
  });

  it("treats friendlyName=Uint8Array(0) as no friendlyName", async () => {
    const { issued } = await makeRootAndLeaf();
    const password = utf8("blank-name");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      friendlyName: new Uint8Array(0),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    expect(parsed.certBags[0]!.friendlyName).toBeUndefined();
    expect(parsed.keyBag.friendlyName).toBeUndefined();
  });

  it("emits bagAttributes in canonical DER SET OF order (short friendlyName comes first)", async () => {
    // Encoded sizes: Attribute(friendlyName="x") = 19 bytes total, attr(localKeyID 20B SHA-1) = 37 bytes.
    // X.690 §11.6 picks the lex-smaller (and 0-padded shorter) component first → friendlyName precedes localKeyID.
    const { issued } = await makeRootAndLeaf();
    const password = utf8("canon");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      friendlyName: utf8("x"),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const parsed = await parsePfx(pfx, password);
    expect(parsed.certBags[0]!.attrOidsInOrder).toEqual([OID.friendlyName, OID.localKeyId]);
    expect(parsed.keyBag.attrOidsInOrder).toEqual([OID.friendlyName, OID.localKeyId]);
  });

  it("handles a 2-byte UTF-8 password (e.g. café)", async () => {
    const { issued } = await makeRootAndLeaf();
    const passphrase = "café";
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

  it("handles a password whose UTF-8 produces a UTF-16 surrogate pair", async () => {
    const { issued } = await makeRootAndLeaf();
    const passphrase = "lock-🔐";
    const password = utf8(passphrase);
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });
    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase })
    ).not.toThrow();
    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase: "lock-🔐 " })
    ).toThrow();
  });

  it("rejects a password containing an invalid UTF-8 sequence", async () => {
    const { issued } = await makeRootAndLeaf();
    // 0xc2 is a 2-byte UTF-8 leader with no continuation byte.
    const password = new Uint8Array([0x70, 0xc2]);
    await expect(
      exportPkcs12({
        certDer: issued.certDer,
        privateKey: issued.privateKey,
        password,
        iterations: TEST_ITERATIONS,
        macIterations: TEST_MAC_ITERATIONS
      })
    ).rejects.toThrow(/UTF-8/);
  });

  it("round-trips with a P-384 key", async () => {
    const root = await createRootCA({
      subject: [{ type: "CN", value: "EdgCA P-384 Root" }],
      days: 30
    });
    const leafKp = await generateKeyPair("P-384");
    const issued = await issueClientCertForPublicKey({
      ca: root,
      publicKey: leafKp.publicKey,
      subject: [{ type: "CN", value: "p384-client" }],
      days: 7
    });
    const password = utf8("p384");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: leafKp.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase: "p384" })
    ).not.toThrow();
    expect(await signRoundTripsViaPfx(issued.certDer, password, pfx)).toBe(true);
  });

  it("round-trips with a P-521 key", async () => {
    const root = await createRootCA({
      subject: [{ type: "CN", value: "EdgCA P-521 Root" }],
      days: 30
    });
    const leafKp = await generateKeyPair("P-521");
    const issued = await issueClientCertForPublicKey({
      ca: root,
      publicKey: leafKp.publicKey,
      subject: [{ type: "CN", value: "p521-client" }],
      days: 7
    });
    const password = utf8("p521");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: leafKp.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase: "p521" })
    ).not.toThrow();
    expect(await signRoundTripsViaPfx(issued.certDer, password, pfx)).toBe(true);
  });

  it("works with iterations=1 and macIterations=1 (minimum boundary)", async () => {
    const { issued } = await makeRootAndLeaf();
    const passphrase = "min";
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password: utf8(passphrase),
      iterations: 1,
      macIterations: 1
    });
    expect(() =>
      tls.createSecureContext({ pfx: Buffer.from(pfx), passphrase })
    ).not.toThrow();
  });

  it("handles a password whose UTF-16BE form spans multiple PKCS#12 v-blocks", async () => {
    // 50 ASCII chars → 100 B UTF-16BE + 2 B terminator = 102 B.
    // ceil(102 / 64) * 64 = 128 B → P2 spans two v-blocks (not one).
    const { issued } = await makeRootAndLeaf();
    const passphrase = "x".repeat(50);
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

  it("emits PBES2 with explicit hmacWithSha256 + NULL prf parameters (defends against default-prf trap)", async () => {
    const { issued } = await makeRootAndLeaf();
    const password = utf8("prf");
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    // Both the cert bag and the key bag carry their own PBES2 algorithm
    // identifier; check both — a default-prf bug could affect just one.
    for (const algoDer of extractAllPbes2Algorithms(pfx)) {
      const prf = readPrfElements(algoDer);
      expect(prf.length).toBe(2);
      expect(decodeOid(prf[0]!.value)).toBe(OID.hmacWithSha256);
      expect(prf[1]!.tag).toBe(TAG.NULL);
      expect(prf[1]!.length).toBe(0);
    }
  });

  it("does not mutate the caller's password buffer", async () => {
    const { issued } = await makeRootAndLeaf();
    const password = utf8("immutable-password");
    const snapshot = new Uint8Array(password);
    await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });
    expect(bytesEqual(password, snapshot)).toBe(true);
  });

  it("does not mutate the caller's friendlyName buffer", async () => {
    const { issued } = await makeRootAndLeaf();
    const friendlyName = utf8("Stable Name");
    const snapshot = new Uint8Array(friendlyName);
    await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password: utf8("p"),
      friendlyName,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });
    expect(bytesEqual(friendlyName, snapshot)).toBe(true);
  });

  it("does not mutate the caller's certDer buffer", async () => {
    const { issued } = await makeRootAndLeaf();
    const snapshot = new Uint8Array(issued.certDer);
    await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password: utf8("p"),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });
    expect(bytesEqual(issued.certDer, snapshot)).toBe(true);
  });

  it("does not mutate the caller's chainDer entries", async () => {
    const root = await createRootCA({
      subject: [{ type: "CN", value: "Imm Root" }],
      days: 30,
      pathLenConstraint: 1
    });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: [{ type: "CN", value: "Imm Intermediate" }],
      days: 14
    });
    const leaf = await issueClientCert({
      ca: intermediate,
      subject: [{ type: "CN", value: "imm-client" }],
      days: 7
    });
    const chainEntry = intermediate.certDer;
    const snapshot = new Uint8Array(chainEntry);
    await exportPkcs12({
      certDer: leaf.certDer,
      chainDer: [chainEntry],
      privateKey: leaf.privateKey,
      password: utf8("p"),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });
    expect(bytesEqual(chainEntry, snapshot)).toBe(true);
  });

  it("uses distinct salt and IV between cert-bag and key-bag PBES2 (no shared randomness)", async () => {
    // Defends against a regression where the salt/IV were inadvertently
    // shared between the two PBES2 invocations (e.g. a future caching of
    // randomBytes() output for "performance"). Node would still accept the
    // PFX, so behavioural tests cannot catch this.
    const { issued } = await makeRootAndLeaf();
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password: utf8("salt-uniqueness"),
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const algos = extractAllPbes2Algorithms(pfx);
    expect(algos.length).toBe(2);
    const [cert, key] = algos.map(extractSaltAndIv);
    expect(bytesEqual(cert!.salt, key!.salt)).toBe(false);
    expect(bytesEqual(cert!.iv, key!.iv)).toBe(false);
  });

  it("computes the MAC over the authSafe OCTET STRING value, not its TLV header", async () => {
    const { issued } = await makeRootAndLeaf();
    const passphrase = "mac-range";
    const password = utf8(passphrase);
    const pfx = await exportPkcs12({
      certDer: issued.certDer,
      privateKey: issued.privateKey,
      password,
      iterations: TEST_ITERATIONS,
      macIterations: TEST_MAC_ITERATIONS
    });

    const info = extractMacInfo(pfx);

    // Independently derive the MAC key with a separate KDF implementation.
    const passwordUtf16Term = utf16BeWithNullTerminator(passphrase);
    const macKeyBytes = await independentPkcs12MacKey(
      passwordUtf16Term,
      info.macSalt,
      info.macIterations
    );
    const macKey = await crypto.subtle.importKey(
      "raw",
      arrayBufferFromBytes(macKeyBytes),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const valueMac = new Uint8Array(
      await crypto.subtle.sign("HMAC", macKey, arrayBufferFromBytes(info.authSafeOctetValue))
    );
    const rawMac = new Uint8Array(
      await crypto.subtle.sign("HMAC", macKey, arrayBufferFromBytes(info.authSafeOctetRaw))
    );

    // The OCTET STRING *value* must reproduce the stored MAC.
    expect(bytesEqual(valueMac, info.mac)).toBe(true);
    // The OCTET STRING *with* its TLV header must NOT — proves the MAC range
    // is the inside of the OCTET STRING, not the OCTET STRING as a whole.
    expect(bytesEqual(rawMac, info.mac)).toBe(false);
  });
});

// --- helpers --------------------------------------------------------------

function utf16Be(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    out.push((code >> 8) & 0xff, code & 0xff);
  }
  return new Uint8Array(out);
}

function utf16BeWithNullTerminator(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2 + 2);
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    out[i * 2] = (code >> 8) & 0xff;
    out[i * 2 + 1] = code & 0xff;
  }
  return out;
}

// Independent re-implementation of PKCS#12 v1 KDF (RFC 7292 App.B) with
// ID=3, u=32, v=64, used to verify the MAC range against a second source.
async function independentPkcs12MacKey(
  passwordUtf16Term: Uint8Array,
  salt: Uint8Array,
  iterations: number
): Promise<Uint8Array> {
  const v = 64;
  const D = new Uint8Array(v).fill(3);
  const sLen = Math.ceil(salt.length / v) * v;
  const S2 = new Uint8Array(sLen);
  for (let i = 0; i < sLen; i += 1) S2[i] = salt[i % salt.length]!;
  const pLen = Math.ceil(passwordUtf16Term.length / v) * v;
  const P2 = new Uint8Array(pLen);
  for (let i = 0; i < pLen; i += 1) P2[i] = passwordUtf16Term[i % passwordUtf16Term.length]!;

  let T = concatBytes([D, S2, P2]);
  for (let j = 0; j < iterations; j += 1) {
    T = new Uint8Array(await crypto.subtle.digest("SHA-256", arrayBufferFromBytes(T)));
  }
  return T.slice(0, 32);
}

// Walk the PFX top-level to expose macData fields and the authSafe OCTET
// STRING boundaries. Used by the MAC-range test.
function extractMacInfo(pfx: Uint8Array): {
  mac: Uint8Array;
  macSalt: Uint8Array;
  macIterations: number;
  authSafeOctetValue: Uint8Array;
  authSafeOctetRaw: Uint8Array;
} {
  const root = readElement(pfx);
  const children = readSequenceChildren(root);
  const authSafeContentInfo = children[1]!;
  const macData = children[2]!;
  if (macData.tag !== TAG.SEQUENCE) throw new Error("missing macData");

  const [, authSafeContent] = readSequenceChildren(authSafeContentInfo);
  if (!authSafeContent || authSafeContent.tag !== 0xa0) throw new Error("missing authSafe content [0]");
  const authSafeOctet = readElement(authSafeContent.value);
  if (authSafeOctet.tag !== TAG.OCTET_STRING) throw new Error("authSafe must be OCTET STRING");

  const macDataChildren = readSequenceChildren(macData);
  const digestInfo = macDataChildren[0]!;
  const macSalt = macDataChildren[1]!.value;
  const macIterations = Number(decodeInteger(macDataChildren[2]!.value));
  const digestInfoChildren = readSequenceChildren(digestInfo);
  const mac = digestInfoChildren[1]!.value;

  return {
    mac,
    macSalt,
    macIterations,
    authSafeOctetValue: authSafeOctet.value,
    authSafeOctetRaw: authSafeOctet.raw
  };
}

// Find every PBES2 AlgorithmIdentifier inside the PFX (cert bag + key bag).
function extractAllPbes2Algorithms(pfx: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = [];
  const root = readElement(pfx);
  const [, authSafeContentInfo] = readSequenceChildren(root);
  const [, authSafeContent] = readSequenceChildren(authSafeContentInfo!);
  const authSafe = readElement(readElement(authSafeContent!.value).value);

  for (const contentInfo of readSequenceChildren(authSafe)) {
    const ciChildren = readSequenceChildren(contentInfo);
    const ciOid = decodeOid(ciChildren[0]!.value);
    const ciContent = ciChildren[1]!;
    if (ciOid === OID.encryptedData) {
      const enc = readElement(ciContent.value);
      const encChildren = readSequenceChildren(enc);
      const eci = readSequenceChildren(encChildren[1]!);
      out.push(eci[1]!.raw);
    } else if (ciOid === OID.data) {
      const inner = readElement(ciContent.value);
      const safeContents = readElement(inner.value);
      for (const safeBag of readSequenceChildren(safeContents)) {
        const sbChildren = readChildren(safeBag.value);
        if (decodeOid(sbChildren[0]!.value) === OID.pkcs8ShroudedKeyBag) {
          const epki = readElement(sbChildren[1]!.value);
          const epkiChildren = readSequenceChildren(epki);
          out.push(epkiChildren[0]!.raw);
        }
      }
    }
  }
  if (out.length === 0) throw new Error("no PBES2 algorithm identifier found");
  return out;
}

// Read the PBKDF2 salt and AES-CBC IV from a PBES2 AlgorithmIdentifier DER.
function extractSaltAndIv(pbes2AlgorithmDer: Uint8Array): { salt: Uint8Array; iv: Uint8Array } {
  const algo = readElement(pbes2AlgorithmDer);
  const algoChildren = readSequenceChildren(algo);
  const params = readSequenceChildren(algoChildren[1]!);
  const kdf = readSequenceChildren(params[0]!);
  const kdfParams = readSequenceChildren(kdf[1]!);
  const salt = kdfParams[0]!.value;
  const enc = readSequenceChildren(params[1]!);
  const iv = enc[1]!.value;
  return { salt, iv };
}

// Read prf children from a PBES2 AlgorithmIdentifier DER:
//   PBES2-AlgId SEQ { pbes2 OID, PBES2-params SEQ { kdf, encScheme } }
//   kdf SEQ { pbkdf2 OID, PBKDF2-params SEQ { salt, iters, prf SEQ { OID, params } } }
function readPrfElements(pbes2AlgorithmDer: Uint8Array) {
  const algo = readElement(pbes2AlgorithmDer);
  const algoChildren = readSequenceChildren(algo);
  const params = readSequenceChildren(algoChildren[1]!);
  const kdf = readSequenceChildren(params[0]!);
  const kdfParams = readSequenceChildren(kdf[1]!);
  return readSequenceChildren(kdfParams[2]!);
}

