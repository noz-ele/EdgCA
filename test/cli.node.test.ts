import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createRootCA,
  generateKeyPair,
  issueClientCert,
  type SupportedCurve
} from "../src/index.js";
import { pemToPfxCommand } from "../src/cli/commands/pem-to-pfx.js";
import {
  cryptoKeyToPkcs8Pem,
  defaultPfxPath,
  importPkcs8PrivateKeyFromPem
} from "../src/cli/io.js";

let tempDir: string;
let logSpy: ReturnType<typeof vi.spyOn>;

beforeEach(async () => {
  tempDir = await mkdtemp(path.join(tmpdir(), "edgca-cli-"));
  logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(async () => {
  logSpy.mockRestore();
  await rm(tempDir, { recursive: true, force: true });
});

describe("CLI io helpers: PKCS#8 PEM round-trip", () => {
  for (const curve of ["P-256", "P-384", "P-521"] as const) {
    it(`exports and re-imports a ${curve} private key via PEM`, async () => {
      const keyPair = await generateKeyPair(curve);
      const keyPem = await cryptoKeyToPkcs8Pem(keyPair.privateKey);

      expect(keyPem.startsWith("-----BEGIN PRIVATE KEY-----\n")).toBe(true);
      expect(keyPem.trimEnd().endsWith("-----END PRIVATE KEY-----")).toBe(true);

      const reimported = await importPkcs8PrivateKeyFromPem(keyPem);
      expect((reimported.algorithm as EcKeyAlgorithm).namedCurve).toBe(curve);

      const hash = ({ "P-256": "SHA-256", "P-384": "SHA-384", "P-521": "SHA-512" } as const)[curve];
      const data = new TextEncoder().encode("round-trip-payload");
      const sig = await crypto.subtle.sign({ name: "ECDSA", hash }, reimported, data);
      const ok = await crypto.subtle.verify({ name: "ECDSA", hash }, keyPair.publicKey, sig, data);
      expect(ok).toBe(true);
    });
  }

  it("throws when given a PEM without a PRIVATE KEY label", async () => {
    await expect(
      importPkcs8PrivateKeyFromPem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    ).rejects.toThrow(/PRIVATE KEY/);
  });

  it("rejects an RSA PKCS#8 PEM (only ECDSA P-256/P-384/P-521 supported)", async () => {
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
    const rsaPem = await cryptoKeyToPkcs8Pem(rsa.privateKey);
    await expect(importPkcs8PrivateKeyFromPem(rsaPem)).rejects.toThrow(/ECDSA/);
  });
});

describe("CLI io helpers: defaultPfxPath", () => {
  it("strips .crt.pem and appends .pfx in the same directory", () => {
    const result = defaultPfxPath(path.join("dir", "client.crt.pem"));
    expect(result).toBe(path.join("dir", "client.pfx"));
  });

  it("strips a plain .pem suffix", () => {
    const result = defaultPfxPath(path.join("dir", "client.pem"));
    expect(result).toBe(path.join("dir", "client.pfx"));
  });

  it("leaves an extensionless name as-is and appends .pfx", () => {
    expect(defaultPfxPath("client")).toBe("client.pfx");
  });
});

describe("pem-to-pfx command", () => {
  async function writeIssuedClientToTemp(curve: SupportedCurve = "P-256"): Promise<{
    certPath: string;
    keyPath: string;
    chainPath: string;
  }> {
    const rootKeyPair = await generateKeyPair(curve);
    const root = await createRootCA({
      subject: [{ type: "CN", value: "CLI Test Root" }],
      days: 30,
      keyPair: rootKeyPair
    });
    const issued = await issueClientCert({
      ca: root,
      subject: [{ type: "CN", value: "cli-client" }],
      days: 7,
      dnsNames: ["client.example.test"]
    });

    const certPath = path.join(tempDir, "client.crt.pem");
    const keyPath = path.join(tempDir, "client.key.pem");
    const chainPath = path.join(tempDir, "client.chain.pem");
    await Promise.all([
      writeFile(certPath, issued.certPem, "utf8"),
      writeFile(keyPath, await cryptoKeyToPkcs8Pem(issued.privateKey), "utf8"),
      writeFile(chainPath, issued.certChainPem, "utf8")
    ]);
    return { certPath, keyPath, chainPath };
  }

  it("writes a non-empty PFX to the explicit --out path", async () => {
    const { certPath, keyPath } = await writeIssuedClientToTemp();
    const outPath = path.join(tempDir, "explicit.pfx");

    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--out", outPath,
      "--password", "dev"
    ]);

    const info = await stat(outPath);
    expect(info.size).toBeGreaterThan(100);
    // PFX is a top-level ASN.1 SEQUENCE → first byte 0x30.
    const head = await readFile(outPath);
    expect(head[0]).toBe(0x30);
  });

  it("defaults --out to <cert-basename>.pfx alongside the cert when omitted", async () => {
    const { certPath, keyPath } = await writeIssuedClientToTemp();
    const expectedOut = path.join(tempDir, "client.pfx");

    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--password", "dev"
    ]);

    const info = await stat(expectedOut);
    expect(info.size).toBeGreaterThan(100);
  });

  it("includes a --chain PEM when supplied", async () => {
    const { certPath, keyPath, chainPath } = await writeIssuedClientToTemp();
    const withChain = path.join(tempDir, "with-chain.pfx");
    const withoutChain = path.join(tempDir, "no-chain.pfx");

    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--chain", chainPath,
      "--password", "dev",
      "--out", withChain
    ]);
    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--password", "dev",
      "--out", withoutChain
    ]);

    const [withChainSize, withoutChainSize] = await Promise.all([
      stat(withChain).then((s) => s.size),
      stat(withoutChain).then((s) => s.size)
    ]);
    expect(withChainSize).toBeGreaterThan(withoutChainSize);
  });

  it("rejects --cert / --key paths that don't exist", async () => {
    await expect(
      pemToPfxCommand([
        "--cert", path.join(tempDir, "missing.crt.pem"),
        "--key", path.join(tempDir, "missing.key.pem"),
        "--password", "dev"
      ])
    ).rejects.toThrow();
  });

  it("rejects when --cert is omitted", async () => {
    await expect(
      pemToPfxCommand(["--key", path.join(tempDir, "k.pem"), "--password", "dev"])
    ).rejects.toThrow(/--cert/);
  });

  it("rejects when --password is omitted", async () => {
    const { certPath, keyPath } = await writeIssuedClientToTemp();
    await expect(
      pemToPfxCommand(["--cert", certPath, "--key", keyPath])
    ).rejects.toThrow(/--password/);
  });

  it("accepts a P-384 key+cert pair", async () => {
    const rootKp = await generateKeyPair("P-384");
    const root = await createRootCA({
      subject: [{ type: "CN", value: "P384 Root" }],
      days: 30,
      keyPair: rootKp
    });
    const issued = await issueClientCert({
      ca: root,
      subject: [{ type: "CN", value: "p384-client" }],
      days: 7
    });
    const certPath = path.join(tempDir, "p384.crt.pem");
    const keyPath = path.join(tempDir, "p384.key.pem");
    await writeFile(certPath, issued.certPem, "utf8");
    await writeFile(keyPath, await cryptoKeyToPkcs8Pem(issued.privateKey), "utf8");

    const outPath = path.join(tempDir, "p384.pfx");
    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--password", "dev",
      "--out", outPath
    ]);

    const info = await stat(outPath);
    expect(info.size).toBeGreaterThan(100);
  });
});
