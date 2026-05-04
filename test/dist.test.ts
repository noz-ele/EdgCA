import { describe, expect, it } from "vitest";

describe("published dist API", () => {
  it("honors caller-provided CA private keys", async () => {
    const edgca = await import("../dist/index.js");
    const rootSubject = [{ type: "CN" as const, value: "published-root" }];
    const intermediateSubject = [{ type: "CN" as const, value: "published-intermediate" }];

    const rootSeed = await edgca.createRootCA({ subject: rootSubject, days: 365 });
    const reissuedRoot = await edgca.createRootCA({
      subject: rootSubject,
      days: 365,
      privateKeyPem: rootSeed.privateKeyPem
    });
    expect(reissuedRoot.privateKeyPem).toBe(rootSeed.privateKeyPem);
    expect(reissuedRoot.publicKeyPem).toBe(rootSeed.publicKeyPem);

    const issuer = await edgca.createRootCA({ subject: rootSubject, days: 3650 });
    const intermediateSeed = await edgca.createRootCA({ subject: intermediateSubject, days: 365 });
    const intermediate = await edgca.issueIntermediateCA({
      ca: issuer,
      subject: intermediateSubject,
      days: 365,
      privateKeyPem: intermediateSeed.privateKeyPem
    });
    expect(intermediate.privateKeyPem).toBe(intermediateSeed.privateKeyPem);
    expect(intermediate.publicKeyPem).toBe(intermediateSeed.publicKeyPem);
  });
});
