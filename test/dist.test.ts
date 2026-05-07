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
