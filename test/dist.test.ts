import { describe, expect, it } from "vitest";

async function exportSpkiBytes(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("spki", key));
}

async function exportPkcs8Bytes(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("pkcs8", key));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

describe("published dist API", () => {
  it("exposes isolated issuer and verify entry points", async () => {
    const issuer = await import("../dist/issuer.js");
    const verifier = await import("../dist/verify.js");
    expect("verifyCertificateChain" in issuer).toBe(false);
    expect("verifyCertificateSignature" in issuer).toBe(false);
    expect("createRootCA" in verifier).toBe(false);

    const root = await issuer.createRootCA({
      subject: [{ type: "CN", value: "entrypoint-root" }],
      days: 3650
    });
    const client = await issuer.issueClientCert({
      ca: root,
      subject: [{ type: "CN", value: "entrypoint-client" }],
      days: 30
    });
    await expect(verifier.verifyCertificateChain({
      certificatePem: client.certPem,
      trustedRootCertificatesPem: [root.certPem],
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });

    const data = new TextEncoder().encode("published-signature-verifier");
    const dataBuffer = new Uint8Array(data).buffer;
    const signature = new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      client.privateKey,
      dataBuffer
    ));
    await expect(verifier.verifyCertificateSignature({
      certificatePem: client.certPem,
      data,
      signature,
      signatureFormat: "ieee-p1363"
    })).resolves.toBe(true);
  });

  it("honors caller-provided CA private keys", async () => {
    const edgca = await import("../dist/index.js");
    const rootSubject = [{ type: "CN" as const, value: "published-root" }];
    const intermediateSubject = [{ type: "CN" as const, value: "published-intermediate" }];

    const rootSeed = await edgca.createRootCA({ subject: rootSubject, days: 365 });
    const reissuedRoot = await edgca.createRootCA({
      subject: rootSubject,
      days: 365,
      keyPair: { privateKey: rootSeed.privateKey, publicKey: rootSeed.publicKey }
    });
    expect(
      bytesEqual(
        await exportPkcs8Bytes(reissuedRoot.privateKey),
        await exportPkcs8Bytes(rootSeed.privateKey)
      )
    ).toBe(true);
    expect(
      bytesEqual(
        await exportSpkiBytes(reissuedRoot.publicKey),
        await exportSpkiBytes(rootSeed.publicKey)
      )
    ).toBe(true);

    const issuer = await edgca.createRootCA({ subject: rootSubject, days: 3650 });
    const intermediateSeed = await edgca.createRootCA({ subject: intermediateSubject, days: 365 });
    const intermediate = await edgca.issueIntermediateCA({
      ca: issuer,
      subject: intermediateSubject,
      days: 365,
      keyPair: { privateKey: intermediateSeed.privateKey, publicKey: intermediateSeed.publicKey }
    });
    expect(
      bytesEqual(
        await exportPkcs8Bytes(intermediate.privateKey),
        await exportPkcs8Bytes(intermediateSeed.privateKey)
      )
    ).toBe(true);
    expect(
      bytesEqual(
        await exportSpkiBytes(intermediate.publicKey),
        await exportSpkiBytes(intermediateSeed.publicKey)
      )
    ).toBe(true);
  });
});
