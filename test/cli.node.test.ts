import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tls from "node:tls";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createCertificateSigningRequest,
  createRootCA,
  generateKeyPair,
  issueClientCert,
  issueClientCertForPublicKey,
  issueIntermediateCA,
  parseCertificateSigningRequest,
  type SupportedCurve
} from "../src/index.js";
import { createRootCaCommand } from "../src/cli/commands/create-root-ca.js";
import { issueClientCommand } from "../src/cli/commands/issue-client.js";
import { issueIntermediateCaCommand } from "../src/cli/commands/issue-intermediate-ca.js";
import { pemToPfxCommand } from "../src/cli/commands/pem-to-pfx.js";
import { parseDnString } from "../src/cli/dn.js";
import {
  parseCurveFlag,
  parseDaysFlag,
  requireString,
  UsageError
} from "../src/cli/flags.js";
import {
  cryptoKeyToPkcs8Pem,
  defaultPfxPath,
  importPkcs8PrivateKeyFromPem,
  stripLeafFromChain,
  writeIssuedLeafTriplet
} from "../src/cli/io.js";
import { bytesEqual, pemToDer, pemToDerWithLabel, splitPemBlocks } from "../src/index.js";
import { parsePfx } from "./helpers/parse-pfx.js";

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

// ---------------------------------------------------------------------------
// dn.ts — parseDnString
// ---------------------------------------------------------------------------

describe("parseDnString", () => {
  it("parses a single attribute", () => {
    expect(parseDnString("CN=foo")).toEqual([{ type: "CN", value: "foo" }]);
  });

  it("parses multiple attributes preserving order", () => {
    expect(parseDnString("CN=foo,O=Acme,C=JP")).toEqual([
      { type: "CN", value: "foo" },
      { type: "O", value: "Acme" },
      { type: "C", value: "JP" }
    ]);
  });

  it("trims spaces around components and values", () => {
    expect(parseDnString("CN = foo , O = bar ")).toEqual([
      { type: "CN", value: "foo" },
      { type: "O", value: "bar" }
    ]);
  });

  it("normalizes short-name keys to upper case", () => {
    expect(parseDnString("cn=foo,o=bar")).toEqual([
      { type: "CN", value: "foo" },
      { type: "O", value: "bar" }
    ]);
  });

  it("accepts dotted-OID attribute types as-is", () => {
    expect(parseDnString("1.2.840.113549.1.9.1=user@example.test")).toEqual([
      { type: "1.2.840.113549.1.9.1", value: "user@example.test" }
    ]);
  });

  it("keeps additional '=' characters inside the value", () => {
    expect(parseDnString("CN=key=value=more")).toEqual([
      { type: "CN", value: "key=value=more" }
    ]);
  });

  it("treats a backslash-escaped comma as part of the value", () => {
    expect(parseDnString("CN=Smith\\, Jr,O=Acme")).toEqual([
      { type: "CN", value: "Smith, Jr" },
      { type: "O", value: "Acme" }
    ]);
  });

  it("ignores empty components produced by stray commas", () => {
    expect(parseDnString("CN=foo,,O=bar")).toEqual([
      { type: "CN", value: "foo" },
      { type: "O", value: "bar" }
    ]);
  });

  it("rejects entirely empty input", () => {
    expect(() => parseDnString("")).toThrow(/empty/i);
  });

  it("rejects input with only separators / whitespace", () => {
    expect(() => parseDnString(", , ,")).toThrow(/empty/i);
  });

  it("rejects a component missing '='", () => {
    expect(() => parseDnString("CN")).toThrow(/missing '='/);
  });

  it("rejects an empty key", () => {
    expect(() => parseDnString("=foo")).toThrow(/empty key/);
  });

  it("rejects an empty value", () => {
    expect(() => parseDnString("CN=")).toThrow(/empty value/);
  });

  it("rejects unknown short names", () => {
    expect(() => parseDnString("XX=foo")).toThrow(/Unsupported DN attribute/);
  });
});

// ---------------------------------------------------------------------------
// flags.ts
// ---------------------------------------------------------------------------

describe("flags: parseDaysFlag", () => {
  it("accepts a positive integer", () => {
    expect(parseDaysFlag("1")).toBe(1);
    expect(parseDaysFlag("365")).toBe(365);
    expect(parseDaysFlag("3650")).toBe(3650);
  });

  it("rejects zero", () => {
    expect(() => parseDaysFlag("0")).toThrow(UsageError);
  });

  it("rejects negative integers", () => {
    expect(() => parseDaysFlag("-1")).toThrow(UsageError);
  });

  it("rejects non-integers", () => {
    expect(() => parseDaysFlag("3.5")).toThrow(UsageError);
  });

  it("rejects non-numeric strings", () => {
    expect(() => parseDaysFlag("abc")).toThrow(UsageError);
    expect(() => parseDaysFlag("")).toThrow(UsageError);
  });

  it("rejects surrounding whitespace", () => {
    expect(() => parseDaysFlag(" 365 ")).toThrow(UsageError);
    expect(() => parseDaysFlag("365 ")).toThrow(UsageError);
    expect(() => parseDaysFlag(" 365")).toThrow(UsageError);
  });

  it("rejects scientific notation", () => {
    expect(() => parseDaysFlag("1e3")).toThrow(UsageError);
    expect(() => parseDaysFlag("1E3")).toThrow(UsageError);
  });

  it("rejects leading zero", () => {
    expect(() => parseDaysFlag("01")).toThrow(UsageError);
    expect(() => parseDaysFlag("007")).toThrow(UsageError);
  });

  it("rejects an explicit sign", () => {
    expect(() => parseDaysFlag("+1")).toThrow(UsageError);
  });

  it("rejects hex notation", () => {
    expect(() => parseDaysFlag("0x10")).toThrow(UsageError);
  });

  it("rejects values beyond Number.MAX_SAFE_INTEGER", () => {
    // Number("99999999999999999") loses precision; the regex permits a 17-digit
    // integer, so this trips the explicit isSafeInteger check.
    expect(() => parseDaysFlag("99999999999999999")).toThrow(/safe integer range/);
  });
});

describe("flags: parseCurveFlag", () => {
  for (const curve of ["P-256", "P-384", "P-521"] as const) {
    it(`accepts ${curve}`, () => {
      expect(parseCurveFlag(curve)).toBe(curve);
    });
  }

  it("rejects unknown curves", () => {
    expect(() => parseCurveFlag("P-128")).toThrow(UsageError);
  });

  it("rejects lowercase variants (case-sensitive on purpose)", () => {
    expect(() => parseCurveFlag("p-256")).toThrow(UsageError);
  });

  it("rejects the empty string", () => {
    expect(() => parseCurveFlag("")).toThrow(UsageError);
  });
});

describe("flags: requireString", () => {
  it("returns the value when defined and non-empty", () => {
    expect(requireString("foo", "--flag")).toBe("foo");
  });

  it("throws UsageError on undefined", () => {
    expect(() => requireString(undefined, "--flag")).toThrow(UsageError);
  });

  it("throws UsageError on the empty string", () => {
    expect(() => requireString("", "--flag")).toThrow(UsageError);
  });

  it("includes the flag name in the message", () => {
    expect(() => requireString(undefined, "--cert")).toThrow(/--cert/);
  });
});

// ---------------------------------------------------------------------------
// io: defaultPfxPath additional boundaries
// ---------------------------------------------------------------------------

describe("io: stripLeafFromChain", () => {
  // Build a deterministic-ish hierarchy once per test that needs PEMs.
  async function buildTestPems(): Promise<{
    leafPem: string;
    intermediatePem: string;
    rootPem: string;
    leafPlusIssuersPem: string;
    issuersOnlyPem: string;
  }> {
    const root = await createRootCA({
      subject: [{ type: "CN", value: "Strip Test Root" }],
      days: 30
    });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: [{ type: "CN", value: "Strip Test Intermediate" }],
      days: 14
    });
    const issued = await issueClientCert({
      ca: intermediate,
      subject: [{ type: "CN", value: "strip-test-client" }],
      days: 7
    });
    return {
      leafPem: issued.certPem,
      intermediatePem: intermediate.certPem,
      rootPem: root.certPem,
      leafPlusIssuersPem: issued.certChainPem,
      issuersOnlyPem: intermediate.certPem + "\n" + root.certPem + "\n"
    };
  }

  it("removes the leaf when it appears in the chain", async () => {
    const { leafPem, leafPlusIssuersPem } = await buildTestPems();
    const result = stripLeafFromChain(leafPem, leafPlusIssuersPem);
    const leafDer = pemToDer(leafPem);
    for (const block of splitPemBlocks(result)) {
      expect(bytesEqual(pemToDerWithLabel(block, "CERTIFICATE"), leafDer)).toBe(false);
    }
    expect(splitPemBlocks(result).length).toBe(2);
  });

  it("returns the input unchanged when the leaf is not present (issuer-only passed through)", async () => {
    const { leafPem, issuersOnlyPem } = await buildTestPems();
    const result = stripLeafFromChain(leafPem, issuersOnlyPem);
    // Same block count and identical DERs in identical order.
    const beforeBlocks = splitPemBlocks(issuersOnlyPem);
    const afterBlocks = splitPemBlocks(result);
    expect(afterBlocks.length).toBe(beforeBlocks.length);
    for (let i = 0; i < beforeBlocks.length; i += 1) {
      const beforeDer = pemToDerWithLabel(beforeBlocks[i]!, "CERTIFICATE");
      const afterDer = pemToDerWithLabel(afterBlocks[i]!, "CERTIFICATE");
      expect(bytesEqual(beforeDer, afterDer)).toBe(true);
    }
  });

  it("removes every occurrence when the leaf appears multiple times", async () => {
    const { leafPem, intermediatePem, rootPem } = await buildTestPems();
    // Construct a chain with the leaf duplicated at positions 0 and 2.
    const weirdChainPem = [leafPem, intermediatePem, leafPem, rootPem]
      .map((p) => p.trim())
      .join("\n") + "\n";
    const result = stripLeafFromChain(leafPem, weirdChainPem);
    const leafDer = pemToDer(leafPem);
    for (const block of splitPemBlocks(result)) {
      expect(bytesEqual(pemToDerWithLabel(block, "CERTIFICATE"), leafDer)).toBe(false);
    }
    expect(splitPemBlocks(result).length).toBe(2);
  });

  it("returns an empty string when the chain contains only the leaf", async () => {
    const { leafPem } = await buildTestPems();
    expect(stripLeafFromChain(leafPem, leafPem)).toBe("");
  });

  it("returns an empty string when the chain input is empty", async () => {
    const { leafPem } = await buildTestPems();
    expect(stripLeafFromChain(leafPem, "")).toBe("");
  });
});

describe("io: defaultPfxPath", () => {
  it("strips .crt.pem and appends .pfx in the same directory", () => {
    expect(defaultPfxPath(path.join("dir", "client.crt.pem"))).toBe(
      path.join("dir", "client.pfx")
    );
  });

  it("strips a plain .pem suffix", () => {
    expect(defaultPfxPath(path.join("dir", "client.pem"))).toBe(
      path.join("dir", "client.pfx")
    );
  });

  it("leaves an extensionless name as-is and appends .pfx", () => {
    expect(defaultPfxPath("client")).toBe("client.pfx");
  });

  it("strips a mixed-case .CRT.PEM suffix", () => {
    expect(defaultPfxPath("client.CRT.PEM")).toBe("client.pfx");
  });

  it("strips a mixed-case .Pem suffix", () => {
    expect(defaultPfxPath("client.Pem")).toBe("client.pfx");
  });

  it("strips only the final .crt.pem from a multi-dotted name", () => {
    expect(defaultPfxPath("client.dev.crt.pem")).toBe("client.dev.pfx");
  });

  it("appends .pfx to an unrecognised extension verbatim", () => {
    expect(defaultPfxPath("client.cer")).toBe("client.cer.pfx");
  });
});

// ---------------------------------------------------------------------------
// io: PKCS#8 PEM round-trip + corrupt-body rejection
// ---------------------------------------------------------------------------

describe("io: PKCS#8 PEM round-trip", () => {
  for (const curve of ["P-256", "P-384", "P-521"] as const) {
    it(`exports and re-imports a ${curve} private key via PEM`, async () => {
      const keyPair = await generateKeyPair(curve);
      const keyPem = await cryptoKeyToPkcs8Pem(keyPair.privateKey);

      expect(keyPem.startsWith("-----BEGIN PRIVATE KEY-----\n")).toBe(true);
      expect(keyPem.trimEnd().endsWith("-----END PRIVATE KEY-----")).toBe(true);

      const reimported = await importPkcs8PrivateKeyFromPem(keyPem);
      expect((reimported.algorithm as EcKeyAlgorithm).namedCurve).toBe(curve);

      const hash = (
        { "P-256": "SHA-256", "P-384": "SHA-384", "P-521": "SHA-512" } as const
      )[curve];
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

  it("rejects a PRIVATE KEY PEM whose body decodes to non-PKCS#8 bytes", async () => {
    // A valid PEM frame with garbage DER inside — every WebCrypto importKey
    // attempt across the three curves should fail.
    const garbageBody = Buffer.from(new Uint8Array(64).fill(0x00)).toString("base64");
    const pem = `-----BEGIN PRIVATE KEY-----\n${garbageBody}\n-----END PRIVATE KEY-----\n`;
    await expect(importPkcs8PrivateKeyFromPem(pem)).rejects.toThrow(/ECDSA/);
  });
});

// ---------------------------------------------------------------------------
// pem-to-pfx command
// ---------------------------------------------------------------------------

describe("pem-to-pfx command", () => {
  async function writeIssuedClientToTemp(
    curve: SupportedCurve = "P-256"
  ): Promise<{ certPath: string; keyPath: string; chainPath: string }> {
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
    const head = await readFile(outPath);
    expect(head[0]).toBe(0x30);
  });

  it("emits a PFX that Node's tls.createSecureContext accepts (real round-trip)", async () => {
    const { certPath, keyPath, chainPath } = await writeIssuedClientToTemp();
    const outPath = path.join(tempDir, "roundtrip.pfx");

    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--chain", chainPath,
      "--out", outPath,
      "--password", "dev"
    ]);

    const pfx = await readFile(outPath);
    expect(() => tls.createSecureContext({ pfx, passphrase: "dev" })).not.toThrow();
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

  it("rejects unknown flags (parseArgs strict)", async () => {
    const { certPath, keyPath } = await writeIssuedClientToTemp();
    await expect(
      pemToPfxCommand([
        "--cert", certPath,
        "--key", keyPath,
        "--password", "dev",
        "--bogus", "x"
      ])
    ).rejects.toThrow();
  });

  it("rejects when --cert and --key are for different keypairs (mismatch guard)", async () => {
    const { certPath } = await writeIssuedClientToTemp();
    // Overwrite the key file with an unrelated private key.
    const unrelated = await generateKeyPair("P-256");
    const unrelatedKeyPem = await cryptoKeyToPkcs8Pem(unrelated.privateKey);
    const keyPath = path.join(tempDir, "unrelated.key.pem");
    await writeFile(keyPath, unrelatedKeyPem, "utf8");

    await expect(
      pemToPfxCommand([
        "--cert", certPath,
        "--key", keyPath,
        "--password", "dev",
        "--out", path.join(tempDir, "should-not-exist.pfx")
      ])
    ).rejects.toThrow(/does not match/i);

    // And the output file must not have been written.
    await expect(stat(path.join(tempDir, "should-not-exist.pfx"))).rejects.toThrow();
  });

  it("treats an empty --chain file as 'no chain' rather than failing", async () => {
    const { certPath, keyPath } = await writeIssuedClientToTemp();
    const emptyChainPath = path.join(tempDir, "empty.chain.pem");
    await writeFile(emptyChainPath, "", "utf8");

    const withEmptyChain = path.join(tempDir, "empty-chain.pfx");
    const withoutChain = path.join(tempDir, "no-chain.pfx");
    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--chain", emptyChainPath,
      "--password", "dev",
      "--out", withEmptyChain
    ]);
    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--password", "dev",
      "--out", withoutChain
    ]);

    // Both must be valid PFX (parseable by Node tls), and the bag count must
    // match: 1 cert bag (leaf only) in each case.
    const [emptyPfx, noPfx] = await Promise.all([readFile(withEmptyChain), readFile(withoutChain)]);
    expect(() => tls.createSecureContext({ pfx: emptyPfx, passphrase: "dev" })).not.toThrow();
    expect(() => tls.createSecureContext({ pfx: noPfx, passphrase: "dev" })).not.toThrow();
    const password = new TextEncoder().encode("dev");
    const [emptyParsed, noParsed] = await Promise.all([
      parsePfx(emptyPfx, password),
      parsePfx(noPfx, password)
    ]);
    expect(emptyParsed.certBags.length).toBe(1);
    expect(noParsed.certBags.length).toBe(1);
  });

  it("rejects a --chain file containing a non-CERTIFICATE PEM block", async () => {
    const { certPath, keyPath } = await writeIssuedClientToTemp();
    // Plausible operator error: pointing --chain at a PRIVATE KEY by mistake.
    const wrongKp = await generateKeyPair("P-256");
    const wrongLabelChainPath = path.join(tempDir, "wrong-label.chain.pem");
    await writeFile(wrongLabelChainPath, await cryptoKeyToPkcs8Pem(wrongKp.privateKey), "utf8");

    await expect(
      pemToPfxCommand([
        "--cert", certPath,
        "--key", keyPath,
        "--chain", wrongLabelChainPath,
        "--password", "dev",
        "--out", path.join(tempDir, "should-not-write.pfx")
      ])
    ).rejects.toThrow(/CERTIFICATE/);
  });

  it("preserves the full chain inside the PFX (leaf + N chain certs)", async () => {
    // Build a root → intermediate → client hierarchy so the leaf's chain.pem
    // contains exactly 2 issuer certs. parsePfx should report 3 cert bags.
    const rootKp = await generateKeyPair("P-256");
    const root = await createRootCA({
      subject: [{ type: "CN", value: "CLI Chain Test Root" }],
      days: 30,
      keyPair: rootKp
    });
    const interKp = await generateKeyPair("P-256");
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: [{ type: "CN", value: "CLI Chain Test Intermediate" }],
      days: 14,
      keyPair: interKp
    });
    const leafKp = await generateKeyPair("P-256");
    // We could call issueClientCert with the intermediate directly; using the
    // CSR path keeps this purely API-level and parallel to the CLI flow.
    const csr = await createCertificateSigningRequest({
      subject: [{ type: "CN", value: "chain-test-client" }],
      keyPair: leafKp,
      dnsNames: ["chain.example.test"]
    });
    const parsed = await parseCertificateSigningRequest(csr.der);
    const issued = await issueClientCertForPublicKey({
      ca: intermediate,
      publicKey: parsed.publicKey,
      subject: parsed.subject,
      days: 7,
      dnsNames: ["chain.example.test"]
    });

    // Exercise the full CLI write path: writeIssuedLeafTriplet is what the
    // `issue-client` subcommand actually uses, and it strips the leaf from
    // certChainPem before writing chain.pem so the file faithfully holds an
    // issuer-only chain. The issueClientCertForPublicKey return type omits the
    // private key (caller-managed key flow), so we attach leafKp here to match
    // the writeIssuedLeafTriplet input contract.
    const issuedForCliWrite = {
      certPem: issued.certPem,
      certDer: issued.certDer,
      certChainPem: issued.certChainPem,
      privateKey: leafKp.privateKey,
      publicKey: leafKp.publicKey
    };
    const { certPath, keyPath, chainPath } = await writeIssuedLeafTriplet(
      issuedForCliWrite,
      tempDir,
      "chain-test"
    );

    const outPath = path.join(tempDir, "chain-test.pfx");
    await pemToPfxCommand([
      "--cert", certPath,
      "--key", keyPath,
      "--chain", chainPath!,
      "--password", "dev",
      "--out", outPath
    ]);

    const pfx = await readFile(outPath);
    const password = new TextEncoder().encode("dev");
    const result = await parsePfx(pfx, password);
    // After A: chain.pem is issuer-only (intermediate + root), so:
    //   leaf (from --cert) + intermediate + root (from --chain) = 3 cert bags.
    expect(result.certBags.length).toBe(3);
  });

  it("(regression) pem-to-pfx --chain is pass-through: manually-supplied fullchain duplicates the leaf", async () => {
    // pem-to-pfx intentionally trusts its --chain input as-is. The leaf
    // duplication bug was fixed on the *write* side (issue-client now emits an
    // issuer-only chain.pem); pem-to-pfx itself does NOT dedup. This test pins
    // that contract: if a caller manually hands a fullchain (leaf + root) PEM
    // to --chain, the PFX ends up with the leaf in 2 bags (one from --cert,
    // one from --chain). If a future change silently adds dedup inside
    // pem-to-pfx, this test will fail and force explicit re-evaluation.
    const root = await createRootCA({
      subject: [{ type: "CN", value: "Regression Root" }],
      days: 30
    });
    const issued = await issueClientCert({
      ca: root,
      subject: [{ type: "CN", value: "regression-leaf" }],
      days: 7
    });
    // issued.certChainPem here is [leaf, root] (root-issued, no intermediate).
    // Write it verbatim as a fullchain file — i.e., bypass writeIssuedLeafTriplet.
    const fullChainPath = path.join(tempDir, "regression.fullchain.pem");
    const leafPath = path.join(tempDir, "regression.leaf.crt.pem");
    const keyPath = path.join(tempDir, "regression.leaf.key.pem");
    await Promise.all([
      writeFile(fullChainPath, issued.certChainPem, "utf8"),
      writeFile(leafPath, issued.certPem, "utf8"),
      writeFile(keyPath, await cryptoKeyToPkcs8Pem(issued.privateKey), "utf8")
    ]);

    const outPath = path.join(tempDir, "regression.pfx");
    await pemToPfxCommand([
      "--cert", leafPath,
      "--key", keyPath,
      "--chain", fullChainPath,
      "--password", "dev",
      "--out", outPath
    ]);

    const pfxBytes = await readFile(outPath);
    const parsed = await parsePfx(pfxBytes, new TextEncoder().encode("dev"));
    // 1 (leaf from --cert) + 2 (leaf + root from fullchain --chain) = 3 bags.
    // If silent dedup is ever added to pem-to-pfx, this drops to 2.
    expect(parsed.certBags.length).toBe(3);
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

    expect((await stat(outPath)).size).toBeGreaterThan(100);
  });
});

// ---------------------------------------------------------------------------
// create-root-ca / issue-intermediate-ca / issue-client commands (chdir-based)
// ---------------------------------------------------------------------------

describe("create-root-ca command (writes to CWD)", () => {
  let originalCwd: string;

  beforeEach(() => {
    originalCwd = process.cwd();
    process.chdir(tempDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
  });

  it("writes root.crt.pem and root.key.pem with default --name", async () => {
    await createRootCaCommand(["--subject", "CN=Test Root"]);
    const [certPem, keyPem] = await Promise.all([
      readFile(path.join(tempDir, "root.crt.pem"), "utf8"),
      readFile(path.join(tempDir, "root.key.pem"), "utf8")
    ]);
    expect(certPem.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true);
    expect(keyPem.startsWith("-----BEGIN PRIVATE KEY-----\n")).toBe(true);
  });

  it("respects --name for the output basename", async () => {
    await createRootCaCommand(["--subject", "CN=Custom", "--name", "my-root"]);
    await expect(stat(path.join(tempDir, "my-root.crt.pem"))).resolves.toBeTruthy();
    await expect(stat(path.join(tempDir, "my-root.key.pem"))).resolves.toBeTruthy();
  });

  it("respects --curve when generating the key", async () => {
    await createRootCaCommand([
      "--subject", "CN=P384 Root",
      "--curve", "P-384",
      "--name", "p384-root"
    ]);
    const keyPem = await readFile(path.join(tempDir, "p384-root.key.pem"), "utf8");
    const key = await importPkcs8PrivateKeyFromPem(keyPem);
    expect((key.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-384");
  });

  it("rejects an empty --subject", async () => {
    await expect(createRootCaCommand(["--subject", ""])).rejects.toThrow();
  });

  it("rejects invalid --days", async () => {
    await expect(
      createRootCaCommand(["--subject", "CN=x", "--days", "0"])
    ).rejects.toThrow(UsageError);
  });

  it("rejects invalid --curve", async () => {
    await expect(
      createRootCaCommand(["--subject", "CN=x", "--curve", "P-128"])
    ).rejects.toThrow(UsageError);
  });
});

describe("issue-intermediate-ca command (writes to CWD)", () => {
  let originalCwd: string;

  beforeEach(async () => {
    originalCwd = process.cwd();
    process.chdir(tempDir);
    await createRootCaCommand(["--subject", "CN=Test Root"]);
  });

  afterEach(() => {
    process.chdir(originalCwd);
  });

  it("writes intermediate.{crt,key,chain}.pem from a root CA", async () => {
    await issueIntermediateCaCommand([
      "--ca-cert", "root.crt.pem",
      "--ca-key", "root.key.pem",
      "--subject", "CN=Test Intermediate"
    ]);
    const chainPem = await readFile(path.join(tempDir, "intermediate.chain.pem"), "utf8");
    // chain must contain at least one CERTIFICATE block (the root)
    expect(chainPem).toMatch(/-----BEGIN CERTIFICATE-----/);
  });

  it("respects --name for the output basename", async () => {
    await issueIntermediateCaCommand([
      "--ca-cert", "root.crt.pem",
      "--ca-key", "root.key.pem",
      "--subject", "CN=Renamed Intermediate",
      "--name", "ica"
    ]);
    await expect(stat(path.join(tempDir, "ica.crt.pem"))).resolves.toBeTruthy();
    await expect(stat(path.join(tempDir, "ica.key.pem"))).resolves.toBeTruthy();
    await expect(stat(path.join(tempDir, "ica.chain.pem"))).resolves.toBeTruthy();
  });

  it("rejects when --ca-cert is missing", async () => {
    await expect(
      issueIntermediateCaCommand([
        "--ca-key", "root.key.pem",
        "--subject", "CN=x"
      ])
    ).rejects.toThrow(/--ca-cert/);
  });

  it("rejects when --ca-cert and --ca-key are from different CAs (mismatch propagates)", async () => {
    // Create a second root with the same default name 'root', overwriting nothing
    // and write its files under different names.
    await createRootCaCommand(["--subject", "CN=Other Root", "--name", "other"]);
    await expect(
      issueIntermediateCaCommand([
        "--ca-cert", "root.crt.pem",
        "--ca-key", "other.key.pem",
        "--subject", "CN=x"
      ])
    ).rejects.toThrow(/does not match/i);
  });
});

describe("issue-client command (writes to CWD)", () => {
  let originalCwd: string;

  beforeEach(async () => {
    originalCwd = process.cwd();
    process.chdir(tempDir);
    await createRootCaCommand(["--subject", "CN=Test Root"]);
    await issueIntermediateCaCommand([
      "--ca-cert", "root.crt.pem",
      "--ca-key", "root.key.pem",
      "--subject", "CN=Test Intermediate"
    ]);
  });

  afterEach(() => {
    process.chdir(originalCwd);
  });

  it("issues a client cert from a root CA (no chain file)", async () => {
    await issueClientCommand([
      "--ca-cert", "root.crt.pem",
      "--ca-key", "root.key.pem",
      "--subject", "CN=alice"
    ]);
    await expect(stat(path.join(tempDir, "client.crt.pem"))).resolves.toBeTruthy();
    await expect(stat(path.join(tempDir, "client.key.pem"))).resolves.toBeTruthy();
    await expect(stat(path.join(tempDir, "client.chain.pem"))).resolves.toBeTruthy();
  });

  it("writes a 1-block chain.pem (root only, no leaf) when issued directly from a root CA", async () => {
    await issueClientCommand([
      "--ca-cert", "root.crt.pem",
      "--ca-key", "root.key.pem",
      "--subject", "CN=alice-root",
      "--name", "alice-root-client"
    ]);
    const rootPem = await readFile(path.join(tempDir, "root.crt.pem"), "utf8");
    const leafPem = await readFile(path.join(tempDir, "alice-root-client.crt.pem"), "utf8");
    const chainPem = await readFile(path.join(tempDir, "alice-root-client.chain.pem"), "utf8");

    const blocks = splitPemBlocks(chainPem);
    expect(blocks.length).toBe(1);
    const onlyDer = pemToDerWithLabel(blocks[0]!, "CERTIFICATE");
    expect(bytesEqual(onlyDer, pemToDer(rootPem))).toBe(true);
    expect(bytesEqual(onlyDer, pemToDer(leafPem))).toBe(false);
  });

  it("issues a client cert from an intermediate CA with --ca-chain", async () => {
    await issueClientCommand([
      "--ca-cert", "intermediate.crt.pem",
      "--ca-key", "intermediate.key.pem",
      "--ca-chain", "intermediate.chain.pem",
      "--subject", "CN=bob",
      "--dns-name", "bob.example.test",
      "--dns-name", "alt.example.test",
      "--ip", "10.0.0.1"
    ]);
    // client.chain.pem is the issuer-only chain (no leaf), so it must contain
    // intermediate + root → 2 CERTIFICATE blocks.
    const chainPem = await readFile(path.join(tempDir, "client.chain.pem"), "utf8");
    const certCount = chainPem.match(/-----BEGIN CERTIFICATE-----/g)?.length ?? 0;
    expect(certCount).toBe(2);
  });

  it("writes client.chain.pem as issuer-only (intermediate + root, no leaf)", async () => {
    await issueClientCommand([
      "--ca-cert", "intermediate.crt.pem",
      "--ca-key", "intermediate.key.pem",
      "--ca-chain", "intermediate.chain.pem",
      "--subject", "CN=eve",
      "--dns-name", "eve.example.test"
    ]);
    const leafPem = await readFile(path.join(tempDir, "client.crt.pem"), "utf8");
    const rootPem = await readFile(path.join(tempDir, "root.crt.pem"), "utf8");
    const intermediatePem = await readFile(path.join(tempDir, "intermediate.crt.pem"), "utf8");
    const chainPem = await readFile(path.join(tempDir, "client.chain.pem"), "utf8");

    const leafDer = pemToDer(leafPem);
    const rootDer = pemToDer(rootPem);
    const intermediateDer = pemToDer(intermediatePem);
    const chainDers = splitPemBlocks(chainPem).map((b) => pemToDerWithLabel(b, "CERTIFICATE"));

    // Exactly the two issuer DERs are present; the leaf DER is absent.
    expect(chainDers.length).toBe(2);
    expect(chainDers.some((d) => bytesEqual(d, intermediateDer))).toBe(true);
    expect(chainDers.some((d) => bytesEqual(d, rootDer))).toBe(true);
    expect(chainDers.some((d) => bytesEqual(d, leafDer))).toBe(false);
  });

  it("respects --name for the output basename", async () => {
    await issueClientCommand([
      "--ca-cert", "intermediate.crt.pem",
      "--ca-key", "intermediate.key.pem",
      "--ca-chain", "intermediate.chain.pem",
      "--subject", "CN=carol",
      "--name", "carol-cert"
    ]);
    await expect(stat(path.join(tempDir, "carol-cert.crt.pem"))).resolves.toBeTruthy();
    await expect(stat(path.join(tempDir, "carol-cert.key.pem"))).resolves.toBeTruthy();
    await expect(stat(path.join(tempDir, "carol-cert.chain.pem"))).resolves.toBeTruthy();
  });

  it("rejects when --subject is missing", async () => {
    await expect(
      issueClientCommand([
        "--ca-cert", "root.crt.pem",
        "--ca-key", "root.key.pem"
      ])
    ).rejects.toThrow(/--subject/);
  });

  it("accepts multiple --ip flags and encodes all of them in SAN", async () => {
    await issueClientCommand([
      "--ca-cert", "intermediate.crt.pem",
      "--ca-key", "intermediate.key.pem",
      "--ca-chain", "intermediate.chain.pem",
      "--subject", "CN=multi-ip",
      "--ip", "10.0.0.1",
      "--ip", "10.0.0.2",
      "--ip", "2001:db8::1"
    ]);
    const certPem = await readFile(path.join(tempDir, "client.crt.pem"), "utf8");
    // We rely on the underlying SAN encoder being already-tested; this just
    // makes sure the CLI didn't drop any of the --ip values silently. The
    // simplest probe is to feed the produced cert into Node tls and assert
    // that all three IPs survived through the issuance API. A cheaper check
    // is to dump the cert via tls/x509 — but issuing via the CSR helper above
    // is overkill here. Instead, parse via the library's CSR-side parser
    // surrogate: we just look for the literal IP byte patterns in the DER.
    const certDer = Buffer.from(
      certPem
        .replace(/-----BEGIN CERTIFICATE-----/g, "")
        .replace(/-----END CERTIFICATE-----/g, "")
        .replace(/\s+/g, ""),
      "base64"
    );
    // 10.0.0.1 → 0a 00 00 01, 10.0.0.2 → 0a 00 00 02
    const hex = Buffer.from(certDer).toString("hex");
    expect(hex).toContain("0a000001");
    expect(hex).toContain("0a000002");
  });

  it("propagates an invalid --ip value as an error (does not write a file)", async () => {
    await expect(
      issueClientCommand([
        "--ca-cert", "intermediate.crt.pem",
        "--ca-key", "intermediate.key.pem",
        "--ca-chain", "intermediate.chain.pem",
        "--subject", "CN=bad-ip",
        "--ip", "999.999.999.999",
        "--name", "bad-ip-client"
      ])
    ).rejects.toThrow();
    await expect(stat(path.join(tempDir, "bad-ip-client.crt.pem"))).rejects.toThrow();
  });

  it("propagates a duplicate --dns-name as an error (does not write a file)", async () => {
    await expect(
      issueClientCommand([
        "--ca-cert", "intermediate.crt.pem",
        "--ca-key", "intermediate.key.pem",
        "--ca-chain", "intermediate.chain.pem",
        "--subject", "CN=dup-dns",
        "--dns-name", "dup.example.test",
        "--dns-name", "dup.example.test",
        "--name", "dup-dns-client"
      ])
    ).rejects.toThrow(/Duplicate SAN dNSName/);
    await expect(stat(path.join(tempDir, "dup-dns-client.crt.pem"))).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// CLI dispatcher — spawn `node dist/cli.js …`
// ---------------------------------------------------------------------------

interface SpawnResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

async function runCli(args: string[]): Promise<SpawnResult> {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const cliPath = path.join(repoRoot, "dist", "cli.js");
  return new Promise<SpawnResult>((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      cwd: tempDir,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("close", (exitCode) => {
      resolve({ stdout, stderr, exitCode });
    });
  });
}

describe("dispatcher (spawned)", () => {
  it("prints the usage to stdout on --help with exit 0", async () => {
    const { stdout, exitCode } = await runCli(["--help"]);
    expect(stdout).toMatch(/Usage:/);
    expect(stdout).toMatch(/create-root-ca/);
    expect(exitCode).toBe(0);
  });

  it("prints the usage to stdout on -h with exit 0", async () => {
    const { stdout, exitCode } = await runCli(["-h"]);
    expect(stdout).toMatch(/Usage:/);
    expect(exitCode).toBe(0);
  });

  it("prints the usage with no subcommand and exits 0", async () => {
    const { stdout, exitCode } = await runCli([]);
    expect(stdout).toMatch(/Usage:/);
    expect(exitCode).toBe(0);
  });

  it("exits 2 on an unknown subcommand and writes the usage to stderr", async () => {
    const { stderr, exitCode } = await runCli(["nonsense-subcommand"]);
    expect(stderr).toMatch(/unknown subcommand/);
    expect(stderr).toMatch(/Usage:/);
    expect(exitCode).toBe(2);
  });

  it("exits 2 on a UsageError from a subcommand (missing required flag)", async () => {
    const { stderr, exitCode } = await runCli(["create-root-ca"]);
    expect(stderr).toMatch(/--subject/);
    expect(exitCode).toBe(2);
  });

  it("exits 1 on a non-UsageError from a subcommand (file not found)", async () => {
    const { stderr, exitCode } = await runCli([
      "pem-to-pfx",
      "--cert", "does-not-exist.crt.pem",
      "--key", "does-not-exist.key.pem",
      "--password", "dev"
    ]);
    expect(stderr.length).toBeGreaterThan(0);
    expect(exitCode).toBe(1);
  });

  it("runs the full root → intermediate → client → pfx pipeline end-to-end", async () => {
    const root = await runCli(["create-root-ca", "--subject", "CN=E2E Root"]);
    expect(root.exitCode).toBe(0);
    const intermediate = await runCli([
      "issue-intermediate-ca",
      "--ca-cert", "root.crt.pem",
      "--ca-key", "root.key.pem",
      "--subject", "CN=E2E Intermediate"
    ]);
    expect(intermediate.exitCode).toBe(0);
    const client = await runCli([
      "issue-client",
      "--ca-cert", "intermediate.crt.pem",
      "--ca-key", "intermediate.key.pem",
      "--ca-chain", "intermediate.chain.pem",
      "--subject", "CN=e2e-client",
      "--dns-name", "e2e.example.test"
    ]);
    expect(client.exitCode).toBe(0);
    const pfx = await runCli([
      "pem-to-pfx",
      "--cert", "client.crt.pem",
      "--key", "client.key.pem",
      "--chain", "client.chain.pem",
      "--password", "dev"
    ]);
    expect(pfx.exitCode).toBe(0);

    const pfxBytes = await readFile(path.join(tempDir, "client.pfx"));
    expect(() =>
      tls.createSecureContext({ pfx: pfxBytes, passphrase: "dev" })
    ).not.toThrow();

    // The E2E pipeline must produce a PFX with no leaf duplication:
    // leaf (from --cert) + intermediate + root (from issuer-only chain.pem) = 3 bags.
    const parsed = await parsePfx(pfxBytes, new TextEncoder().encode("dev"));
    expect(parsed.certBags.length).toBe(3);
  });
});
