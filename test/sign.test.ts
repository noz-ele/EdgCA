import { describe, expect, it } from "vitest";
import { createRootCA } from "../src/ca.js";
import { generateKeyPair } from "../src/crypto.js";
import { signData } from "../src/sign.js";
import { verifyCertificateSignature } from "../src/verify.js";

describe("signData", () => {
  for (const [curve, p1363Length] of [
    ["P-256", 64],
    ["P-384", 96],
    ["P-521", 132]
  ] as const) {
    it(`signs ${curve} data in DER and IEEE P1363 formats`, async () => {
      const keyPair = await generateKeyPair(curve);
      const certificate = await createRootCA({
        subject: [{ type: "CN", value: `${curve} signer` }],
        days: 30,
        keyPair
      });
      const data = new TextEncoder().encode(`signData ${curve}`);
      const originalData = new Uint8Array(data);

      const p1363 = await signData({
        privateKey: keyPair.privateKey,
        data,
        signatureFormat: "ieee-p1363"
      });
      expect(p1363).toHaveLength(p1363Length);
      await expect(verifyCertificateSignature({
        certificatePem: certificate.certPem,
        data,
        signature: p1363,
        signatureFormat: "ieee-p1363"
      })).resolves.toBe(true);

      const der = await signData({
        privateKey: keyPair.privateKey,
        data,
        signatureFormat: "der"
      });
      expect(der[0]).toBe(0x30);
      await expect(verifyCertificateSignature({
        certificatePem: certificate.certPem,
        data,
        signature: der,
        signatureFormat: "der"
      })).resolves.toBe(true);

      expect(data).toEqual(originalData);
    });
  }

  it("produces a signature that fails for modified data", async () => {
    const keyPair = await generateKeyPair("P-256");
    const certificate = await createRootCA({
      subject: [{ type: "CN", value: "modified-data signer" }],
      days: 30,
      keyPair
    });
    const signature = await signData({
      privateKey: keyPair.privateKey,
      data: new TextEncoder().encode("original"),
      signatureFormat: "ieee-p1363"
    });

    await expect(verifyCertificateSignature({
      certificatePem: certificate.certPem,
      data: new TextEncoder().encode("modified"),
      signature,
      signatureFormat: "ieee-p1363"
    })).resolves.toBe(false);
  });

  it("rejects a public key", async () => {
    const keyPair = await generateKeyPair("P-256");
    await expect(signData({
      privateKey: keyPair.publicKey,
      data: new Uint8Array([1, 2, 3]),
      signatureFormat: "ieee-p1363"
    })).rejects.toThrow("privateKey must be a private CryptoKey");
  });

  it("rejects a private key without sign usage", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    await expect(signData({
      privateKey: keyPair.privateKey,
      data: new Uint8Array([1, 2, 3]),
      signatureFormat: "der"
    })).rejects.toThrow('privateKey usages must include "sign"');
  });

  it("rejects a non-ECDSA private signing key", async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );
    await expect(signData({
      privateKey: keyPair.privateKey,
      data: new Uint8Array([1, 2, 3]),
      signatureFormat: "der"
    })).rejects.toThrow("Expected ECDSA key");
  });

  it("rejects malformed options", async () => {
    const keyPair = await generateKeyPair("P-256");
    await expect(signData(null as unknown as Parameters<typeof signData>[0]))
      .rejects.toThrow("options must be an object");
    await expect(signData({
      privateKey: keyPair.privateKey,
      data: [1, 2, 3] as unknown as Uint8Array,
      signatureFormat: "der"
    })).rejects.toThrow("data must be a Uint8Array");
    await expect(signData({
      privateKey: keyPair.privateKey,
      data: new Uint8Array([1, 2, 3]),
      signatureFormat: "auto" as "der"
    })).rejects.toThrow("signatureFormat must be der or ieee-p1363");
  });
});
