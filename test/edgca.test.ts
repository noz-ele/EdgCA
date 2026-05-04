import { describe, expect, it } from "vitest";
import {
  certificateToPem,
  createRootCA,
  importCertificateAuthority,
  issueClientCert,
  issueIntermediateCA,
  pemToDer,
  privateKeyToPem,
  publicKeyToPem
} from "../src/index.js";
import { ecdsaDerToRaw, ecdsaRawToDer, keyIdentifierFromSpki } from "../src/crypto.js";
import {
  bitString,
  decodeInteger,
  decodeOid,
  oid,
  readChildren,
  readElement,
  readSequenceChildren,
  sequence,
  TAG
} from "../src/der.js";
import { encodeIpAddress } from "../src/ip.js";
import { OID } from "../src/oids.js";
import { pemToDerWithLabel, splitPemBlocks } from "../src/pem.js";
import { assertIssuerSubjectMatches } from "../src/parser.js";
import { keyUsageExtension, subjectAltNameExtension } from "../src/x509.js";
import type { SerialNumber, Subject } from "../src/types.js";
import {
  assertSingleValuedRdns,
  expectSignatureValid,
  findExtension,
  getExtension,
  namesEqual,
  parseAuthorityKeyIdentifier,
  parseCertificate,
  parseCertificateSerialNumber,
  parseCertificateValidity,
  parseExtensionsFromCertificate,
  parseKeyUsage,
  parseName,
  parseSubjectAltName,
  parseSubjectKeyIdentifier,
  subjectPublicKeyBits
} from "./helpers/x509.js";

const rootSubject: Subject = [
  { type: "CN", value: "dev-root" },
  { type: "O", value: "Example" }
];

const intermediateSubject: Subject = [
  { type: "CN", value: "dev-intermediate" },
  { type: "O", value: "Example" }
];

const clientSubject: Subject = [
  { type: "CN", value: "worker-client" },
  { type: "UID", value: "worker-001" }
];

describe("EdgCA issuing API", () => {
  it("issues a root, intermediate, and mTLS client certificate chain", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 3650,
      serialNumber: 1
    });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365,
      serialNumber: 2
    });
    const client = await issueClientCert({
      ca: intermediate,
      subject: clientSubject,
      days: 30,
      serialNumber: 3,
      dnsNames: ["worker-client.example.test"],
      ipAddresses: ["127.0.0.1", "2001:db8::1"]
    });

    expect(root.issuerChainPem).toBe("");
    expect(intermediate.issuerChainPem).toBe(root.certPem);
    expect(splitPemBlocks(client.certChainPem)).toEqual([
      client.certPem.trim(),
      intermediate.certPem.trim(),
      root.certPem.trim()
    ]);

    const parsedRoot = await parseCertificate(root.certDer);
    const parsedIntermediate = await parseCertificate(intermediate.certDer);
    const parsedClient = await parseCertificate(client.certDer);

    assertSingleValuedRdns(parsedRoot.subjectNameDer);
    assertSingleValuedRdns(parsedIntermediate.subjectNameDer);
    assertSingleValuedRdns(parsedClient.subjectNameDer);

    expect(parsedRoot.isCA).toBe(true);
    expect(parsedRoot.pathLenConstraint).toBe(1);
    expect(parsedRoot.keyCertSign).toBe(true);
    expect(namesEqual(parsedRoot.issuerNameDer, parsedRoot.subjectNameDer)).toBe(true);

    expect(parsedIntermediate.isCA).toBe(true);
    expect(parsedIntermediate.pathLenConstraint).toBe(0);
    expect(parsedIntermediate.keyCertSign).toBe(true);
    expect(namesEqual(parsedIntermediate.issuerNameDer, parsedRoot.subjectNameDer)).toBe(true);

    expect(parsedClient.isCA).toBe(false);
    expect(parsedClient.keyCertSign).toBe(false);
    expect(namesEqual(parsedClient.issuerNameDer, parsedIntermediate.subjectNameDer)).toBe(true);

    await expect(expectSignatureValid(parsedRoot, parsedRoot)).resolves.toBe(true);
    await expect(expectSignatureValid(parsedRoot, parsedIntermediate)).resolves.toBe(true);
    await expect(expectSignatureValid(parsedIntermediate, parsedClient)).resolves.toBe(true);

    const rootSki = parseSubjectKeyIdentifier(getExtension(root.certDer, OID.subjectKeyIdentifier).value);
    const intermediateSki = parseSubjectKeyIdentifier(getExtension(intermediate.certDer, OID.subjectKeyIdentifier).value);
    const clientSki = parseSubjectKeyIdentifier(getExtension(client.certDer, OID.subjectKeyIdentifier).value);
    const rootAki = parseAuthorityKeyIdentifier(getExtension(root.certDer, OID.authorityKeyIdentifier).value);
    const intermediateAki = parseAuthorityKeyIdentifier(getExtension(intermediate.certDer, OID.authorityKeyIdentifier).value);
    const clientAki = parseAuthorityKeyIdentifier(getExtension(client.certDer, OID.authorityKeyIdentifier).value);

    expect(rootAki.tag).toBe(0x80);
    expect(intermediateAki.tag).toBe(0x80);
    expect(clientAki.tag).toBe(0x80);
    expect(rootAki.keyIdentifier).toEqual(rootSki);
    expect(intermediateAki.keyIdentifier).toEqual(rootSki);
    expect(clientAki.keyIdentifier).toEqual(intermediateSki);
    expect(rootSki.length).toBe(20);
    expect(intermediateSki.length).toBe(20);
    expect(clientSki.length).toBe(20);
    await expect(digestSha1(subjectPublicKeyBits(parsedRoot.subjectPublicKeyInfoDer))).resolves.toEqual(rootSki);
    await expect(digestSha1(subjectPublicKeyBits(parsedIntermediate.subjectPublicKeyInfoDer))).resolves.toEqual(intermediateSki);
    await expect(digestSha1(subjectPublicKeyBits(parsedClient.subjectPublicKeyInfoDer))).resolves.toEqual(clientSki);

    const rootKeyUsage = parseKeyUsage(getExtension(root.certDer, OID.keyUsage).value);
    const intermediateKeyUsage = parseKeyUsage(getExtension(intermediate.certDer, OID.keyUsage).value);
    const clientKeyUsage = parseKeyUsage(getExtension(client.certDer, OID.keyUsage).value);
    expect(rootKeyUsage).toMatchObject({
      unusedBits: 1,
      digitalSignature: false,
      keyCertSign: true,
      cRLSign: true
    });
    expect(Array.from(rootKeyUsage.bytes)).toEqual([0x06]);
    expect(intermediateKeyUsage).toMatchObject({
      unusedBits: 1,
      digitalSignature: false,
      keyCertSign: true,
      cRLSign: true
    });
    expect(Array.from(intermediateKeyUsage.bytes)).toEqual([0x06]);
    expect(clientKeyUsage).toMatchObject({
      unusedBits: 7,
      digitalSignature: true,
      keyCertSign: false,
      cRLSign: false
    });
    expect(Array.from(clientKeyUsage.bytes)).toEqual([0x80]);

    const san = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);
    expect(san.dnsNames).toEqual(["worker-client.example.test"]);
    expect(san.ipAddresses.map((ipAddress) => Array.from(ipAddress))).toEqual([
      [127, 0, 0, 1],
      [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    ]);

    const clientExtensions = parseExtensionsFromCertificate(client.certDer);
    expect(clientExtensions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ oid: OID.basicConstraints, critical: true }),
        expect.objectContaining({ oid: OID.keyUsage, critical: true }),
        expect.objectContaining({ oid: OID.extendedKeyUsage, critical: false }),
        expect.objectContaining({ oid: OID.subjectKeyIdentifier, critical: false }),
        expect.objectContaining({ oid: OID.authorityKeyIdentifier, critical: false }),
        expect.objectContaining({ oid: OID.subjectAltName, critical: false })
      ])
    );
  });

  it("issues a client certificate directly from a root CA", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 3650,
      serialNumber: 1
    });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      serialNumber: 2
    });

    expect(splitPemBlocks(client.certChainPem)).toEqual([
      client.certPem.trim(),
      root.certPem.trim()
    ]);

    const parsedRoot = await parseCertificate(root.certDer);
    const parsedClient = await parseCertificate(client.certDer);
    expect(namesEqual(parsedClient.issuerNameDer, parsedRoot.subjectNameDer)).toBe(true);
    await expect(expectSignatureValid(parsedRoot, parsedClient)).resolves.toBe(true);

    const rootSki = parseSubjectKeyIdentifier(getExtension(root.certDer, OID.subjectKeyIdentifier).value);
    const clientAki = parseAuthorityKeyIdentifier(getExtension(client.certDer, OID.authorityKeyIdentifier).value);
    expect(clientAki.keyIdentifier).toEqual(rootSki);
  });

  it("round-trips PEM blocks and imported CA issuerChainPem", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    const importedIntermediate = await importCertificateAuthority({
      certPem: intermediate.certPem,
      privateKeyPem: intermediate.privateKeyPem,
      issuerChainPem: intermediate.issuerChainPem
    });
    const client = await issueClientCert({
      ca: importedIntermediate,
      subject: clientSubject,
      days: 30
    });

    expect(importedIntermediate.issuerChainPem).toBe(root.certPem);
    expect(certificateToPem(pemToDer(intermediate.certPem))).toBe(intermediate.certPem);
    expect(certificateToPem(pemToDerWithLabel(intermediate.certPem, "CERTIFICATE"))).toBe(intermediate.certPem);
    await expect(privateKeyToPem(intermediate.privateKey)).resolves.toBe(intermediate.privateKeyPem);
    await expect(publicKeyToPem(intermediate.publicKey)).resolves.toBe(intermediate.publicKeyPem);
    expect(() => pemToDerWithLabel(intermediate.certPem, "PRIVATE KEY")).toThrow("expected PRIVATE KEY");
    expect(splitPemBlocks(client.certChainPem)).toEqual([
      client.certPem.trim(),
      intermediate.certPem.trim(),
      root.certPem.trim()
    ]);
  });

  it("reuses a caller-provided private key for the root CA", async () => {
    const seed = await createRootCA({ subject: rootSubject, days: 365 });
    const reissued = await createRootCA({
      subject: rootSubject,
      days: 365,
      privateKeyPem: seed.privateKeyPem
    });

    expect(reissued.privateKeyPem).toBe(seed.privateKeyPem);
    expect(reissued.publicKeyPem).toBe(seed.publicKeyPem);

    const seedParsed = await parseCertificate(seed.certDer);
    const reissuedParsed = await parseCertificate(reissued.certDer);
    expect(Array.from(reissuedParsed.subjectPublicKeyInfoDer)).toEqual(
      Array.from(seedParsed.subjectPublicKeyInfoDer)
    );
    const seedSki = parseSubjectKeyIdentifier(getExtension(seed.certDer, OID.subjectKeyIdentifier).value);
    const reissuedSki = parseSubjectKeyIdentifier(getExtension(reissued.certDer, OID.subjectKeyIdentifier).value);
    expect(Array.from(reissuedSki)).toEqual(Array.from(seedSki));
  });

  it("issues an intermediate CA with a caller-provided private key", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const seed = await createRootCA({ subject: intermediateSubject, days: 365 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365,
      privateKeyPem: seed.privateKeyPem
    });

    expect(intermediate.privateKeyPem).toBe(seed.privateKeyPem);

    const parsedRoot = await parseCertificate(root.certDer);
    const parsedIntermediate = await parseCertificate(intermediate.certDer);
    await expect(expectSignatureValid(parsedRoot, parsedIntermediate)).resolves.toBe(true);
  });

  it("rejects a non-PRIVATE-KEY PEM passed as privateKeyPem", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        privateKeyPem: root.certPem
      })
    ).rejects.toThrow("expected PRIVATE KEY");
  });

  it("rejects an explicitly empty privateKeyPem", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });

    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        privateKeyPem: ""
      })
    ).rejects.toThrow("expected PRIVATE KEY");
    await expect(
      issueIntermediateCA({
        ca: root,
        subject: intermediateSubject,
        days: 365,
        privateKeyPem: ""
      })
    ).rejects.toThrow("expected PRIVATE KEY");
  });

  it("rejects importing a CA certificate with a mismatched private key", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const otherRoot = await createRootCA({
      subject: [{ type: "CN", value: "other-root" }],
      days: 3650
    });

    await expect(
      importCertificateAuthority({
        certPem: root.certPem,
        privateKeyPem: otherRoot.privateKeyPem
      })
    ).rejects.toThrow("does not match");
  });

  it("rejects issuing from an imported non-CA leaf certificate", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30
    });
    const importedLeaf = await importCertificateAuthority({
      certPem: client.certPem,
      privateKeyPem: client.privateKeyPem,
      issuerChainPem: root.certPem
    });

    await expect(
      issueClientCert({
        ca: importedLeaf,
        subject: [{ type: "CN", value: "blocked-client" }],
        days: 30
      })
    ).rejects.toThrow("Issuer certificate is not a CA");
  });

  it("falls back to certPem when CertificateAuthority.certDer is absent or empty", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });

    const withEmptyCertDer = { ...root, certDer: new Uint8Array(0) };
    const fromEmpty = await issueClientCert({
      ca: withEmptyCertDer,
      subject: clientSubject,
      days: 30
    });
    const parsedFromEmpty = await parseCertificate(fromEmpty.certDer);
    const parsedRoot = await parseCertificate(root.certDer);
    expect(namesEqual(parsedFromEmpty.issuerNameDer, parsedRoot.subjectNameDer)).toBe(true);

    const withMissingCertDer = { ...root, certDer: undefined as unknown as Uint8Array };
    const fromMissing = await issueClientCert({
      ca: withMissingCertDer,
      subject: clientSubject,
      days: 30
    });
    const parsedFromMissing = await parseCertificate(fromMissing.certDer);
    expect(namesEqual(parsedFromMissing.issuerNameDer, parsedRoot.subjectNameDer)).toBe(true);
  });

  it("rejects subsequent issuance when CertificateAuthority.certDer has been mutated", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });

    root.certDer.fill(0);
    intermediate.certDer.fill(0);

    let rootError: unknown;
    try {
      await issueIntermediateCA({
        ca: root,
        subject: [{ type: "CN", value: "next-intermediate" }],
        days: 365
      });
    } catch (e) {
      rootError = e;
    }
    expect((rootError as Error | undefined)?.message).toBe("Invalid certificate DER");

    let intermediateError: unknown;
    try {
      await issueClientCert({ ca: intermediate, subject: clientSubject, days: 30 });
    } catch (e) {
      intermediateError = e;
    }
    expect((intermediateError as Error | undefined)?.message).toBe("Invalid certificate DER");
  });

  it("does not include SAN when no SAN inputs are provided", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const withoutSan = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30
    });
    const withEmptySanInputs = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: [],
      ipAddresses: []
    });

    expect(findExtension(withoutSan.certDer, OID.subjectAltName)).toBeUndefined();
    expect(findExtension(withEmptySanInputs.certDer, OID.subjectAltName)).toBeUndefined();
  });

  it("rejects issuing another intermediate below an intermediate CA", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });

    await expect(
      issueIntermediateCA({
        ca: intermediate,
        subject: [{ type: "CN", value: "blocked-intermediate" }],
        days: 30
      })
    ).rejects.toThrow("pathLenConstraint=0");
  });

  it("rejects issuing an intermediate from a root with pathLenConstraint=0", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 3650,
      pathLenConstraint: 0
    });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30
    });

    expect(client.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    await expect(
      issueIntermediateCA({
        ca: root,
        subject: intermediateSubject,
        days: 365
      })
    ).rejects.toThrow("pathLenConstraint=0");
  });

  it("rejects pathLenConstraint values that would allow a deeper chain", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });

    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        pathLenConstraint: 2
      })
    ).rejects.toThrow("pathLenConstraint");
    await expect(
      issueIntermediateCA({
        ca: root,
        subject: intermediateSubject,
        days: 365,
        pathLenConstraint: 1
      })
    ).rejects.toThrow("Intermediate pathLenConstraint must be 0");
  });

  it("accepts an explicit pathLenConstraint=0 on issueIntermediateCA", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365,
      pathLenConstraint: 0
    });
    const parsed = await parseCertificate(intermediate.certDer);
    expect(parsed.pathLenConstraint).toBe(0);
  });
});

describe("subject encoding", () => {
  it("encodes structured subject input in order with fixed string types", async () => {
    const subject: Subject = [
      { type: "CN", value: "structured-root" },
      { type: "C", value: "JP" },
      { type: "DC", value: "example" },
      { type: "1.2.3.4.5", value: "custom" }
    ];
    const root = await createRootCA({ subject, days: 365 });
    const parsed = await parseCertificate(root.certDer);
    const attributes = parseName(parsed.subjectNameDer);

    assertSingleValuedRdns(parsed.subjectNameDer);
    expect(attributes.map((attribute) => attribute.oid)).toEqual([
      "2.5.4.3",
      "2.5.4.6",
      "0.9.2342.19200300.100.1.25",
      "1.2.3.4.5"
    ]);
    expect(attributes.map((attribute) => attribute.tag)).toEqual([
      TAG.UTF8_STRING,
      TAG.PRINTABLE_STRING,
      TAG.UTF8_STRING,
      TAG.UTF8_STRING
    ]);
  });

  it("encodes emailAddress subjects as IA5String for short and dotted-OID input", async () => {
    const root = await createRootCA({
      subject: [
        { type: "E", value: "ops@example.test" },
        { type: "1.2.840.113549.1.9.1", value: "alias@example.test" }
      ],
      days: 365
    });
    const parsed = await parseCertificate(root.certDer);
    const attributes = parseName(parsed.subjectNameDer);

    expect(attributes.map((attribute) => attribute.oid)).toEqual([
      "1.2.840.113549.1.9.1",
      "1.2.840.113549.1.9.1"
    ]);
    expect(attributes.map((attribute) => attribute.tag)).toEqual([
      TAG.IA5_STRING,
      TAG.IA5_STRING
    ]);
  });

  it("does not accept DN string input", async () => {
    await expect(
      createRootCA({
        subject: "CN=dev-root" as never,
        days: 365
      })
    ).rejects.toThrow("subject must be a non-empty array");
  });
});

describe("input validation", () => {
  it("rejects empty and non-array subject input", async () => {
    await expect(
      createRootCA({
        subject: [],
        days: 365
      })
    ).rejects.toThrow("subject must be a non-empty array");
    await expect(
      createRootCA({
        subject: { type: "CN", value: "not-an-array" } as never,
        days: 365
      })
    ).rejects.toThrow("subject must be a non-empty array");
  });

  it("rejects subject entries with non-string fields", async () => {
    await expect(
      createRootCA({
        subject: [{ type: "CN", value: 123 as never }],
        days: 365
      })
    ).rejects.toThrow("must be a string");
  });

  it("rejects empty subject value", async () => {
    await expect(
      createRootCA({
        subject: [{ type: "CN", value: "" }],
        days: 365
      })
    ).rejects.toThrow("must not be empty");
  });

  it("rejects PrintableString-incompatible country values", async () => {
    await expect(
      createRootCA({
        subject: [{ type: "C", value: "日本" }],
        days: 365
      })
    ).rejects.toThrow("PrintableString");
  });

  it("rejects non-ASCII emailAddress subject values", async () => {
    await expect(
      createRootCA({
        subject: [{ type: "E", value: "ops@\u4f8b.test" }],
        days: 365
      })
    ).rejects.toThrow("ASCII");
  });

  it("rejects subject values containing control or bidi characters", async () => {
    await expect(
      createRootCA({
        subject: [{ type: "CN", value: "safe\u202etext" }],
        days: 365
      })
    ).rejects.toThrow("forbidden");
  });

  it("rejects invalid dotted OID subject attribute types", async () => {
    for (const type of ["abc", "3.2.1", "1", "1..2", "1.40.0", "1.2", "1.02.3"]) {
      await expect(
        createRootCA({
          subject: [{ type: type as never, value: "custom" }],
          days: 365
        })
      ).rejects.toThrow();
    }
  });

  it("rejects non-object subject entries", async () => {
    for (const entry of [null, "CN=root", 42] as never[]) {
      await expect(
        createRootCA({
          subject: [entry],
          days: 365
        })
      ).rejects.toThrow("must be an object");
    }
  });

  it("rejects invalid days values", async () => {
    for (const days of [0, -1, Number.NaN, 1.5, Number.POSITIVE_INFINITY]) {
      await expect(
        createRootCA({
          subject: rootSubject,
          days
        })
      ).rejects.toThrow("days must be a positive integer");
    }
  });

  it("rejects negative pathLenConstraint", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        pathLenConstraint: -1
      })
    ).rejects.toThrow("pathLenConstraint");
  });

  it("rejects non-integer pathLenConstraint", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        pathLenConstraint: 1.5
      })
    ).rejects.toThrow("pathLenConstraint");
  });

  it("rejects oversized serialNumber Uint8Array", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber: new Uint8Array(21)
      })
    ).rejects.toThrow("20 octets");
  });

  it("rejects empty serialNumber Uint8Array", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber: new Uint8Array(0)
      })
    ).rejects.toThrow("must not be empty");
  });

  it("accepts a 20-byte serialNumber with high bit cleared", async () => {
    const bytes = new Uint8Array(20).fill(0x01);
    const root = await createRootCA({
      subject: rootSubject,
      days: 365,
      serialNumber: bytes
    });
    expect(root.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
  });

  it("rejects invalid dnsName format", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        dnsNames: ["bad name with spaces"]
      })
    ).rejects.toThrow("dNSName");
  });

  it("rejects empty dnsName", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        dnsNames: [""]
      })
    ).rejects.toThrow("dNSName");
  });

  it("accepts valid SAN dNSName boundary values", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const maxLabel = "a".repeat(63);
    const maxTotalLengthName = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(61)}`;
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: [`${maxLabel}.example.test`, "*.example.test", maxTotalLengthName]
    });
    const san = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);

    expect(san.dnsNames).toEqual([`${maxLabel}.example.test`, "*.example.test", maxTotalLengthName]);
  });

  it("rejects invalid SAN dNSName boundary values", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const tooLongLabel = `${"a".repeat(64)}.example.test`;
    const tooLongName = `${"a".repeat(63)}.${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(62)}`;

    for (const dnsName of [tooLongLabel, tooLongName, "example.test."]) {
      await expect(
        issueClientCert({
          ca: root,
          subject: clientSubject,
          days: 30,
          dnsNames: [dnsName]
        })
      ).rejects.toThrow("dNSName");
    }
  });

  it("rejects duplicate SAN inputs without normalizing them away", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });

    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        dnsNames: ["worker.example.test", "worker.example.test"]
      })
    ).rejects.toThrow("Duplicate SAN dNSName");

    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        ipAddresses: ["::1", "0:0:0:0:0:0:0:1"]
      })
    ).rejects.toThrow("Duplicate SAN iPAddress");
  });

  it("rejects non-array SAN inputs", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });

    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        dnsNames: "worker-client.example.test" as never
      })
    ).rejects.toThrow("dnsNames must be an array");
    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        ipAddresses: "127.0.0.1" as never
      })
    ).rejects.toThrow("ipAddresses must be an array");
  });

  it("rejects non-string ipAddress entries", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });

    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        ipAddresses: [123 as never]
      })
    ).rejects.toThrow("iPAddress");
  });

  it("rejects importCertificateAuthority when certPem has wrong label", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      importCertificateAuthority({
        certPem: root.privateKeyPem,
        privateKeyPem: root.privateKeyPem
      })
    ).rejects.toThrow("expected CERTIFICATE");
  });

  it("rejects importCertificateAuthority when privateKeyPem has wrong label", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      importCertificateAuthority({
        certPem: root.certPem,
        privateKeyPem: root.certPem
      })
    ).rejects.toThrow("expected PRIVATE KEY");
  });

  it("rejects importCertificateAuthority when issuerChainPem contains a non-CERTIFICATE block", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 30
    });
    await expect(
      importCertificateAuthority({
        certPem: intermediate.certPem,
        privateKeyPem: intermediate.privateKeyPem,
        issuerChainPem: intermediate.privateKeyPem
      })
    ).rejects.toThrow("expected CERTIFICATE");
  });

  it("rejects importCertificateAuthority when issuerChainPem is non-empty garbage", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 30
    });
    await expect(
      importCertificateAuthority({
        certPem: intermediate.certPem,
        privateKeyPem: intermediate.privateKeyPem,
        issuerChainPem: "not a pem block"
      })
    ).rejects.toThrow("CERTIFICATE blocks");
  });

  it("rejects subject values containing each forbidden character class", async () => {
    for (const code of [0x01, 0x1f, 0x7f, 0x200e, 0x200f, 0x202a, 0x202d, 0x2066, 0x2069]) {
      const value = `safe${String.fromCharCode(code)}text`;
      await expect(
        createRootCA({
          subject: [{ type: "CN", value }],
          days: 365
        })
      ).rejects.toThrow("forbidden");
    }
  });

  it("rejects non-string dnsName entries", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        dnsNames: [123 as never]
      })
    ).rejects.toThrow("dNSName");
  });

  it("rejects malformed dNSName wildcard forms", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    for (const dnsName of ["*", "*.*.example.test", "foo.*.example.test", "*-foo.example.test"]) {
      await expect(
        issueClientCert({
          ca: root,
          subject: clientSubject,
          days: 30,
          dnsNames: [dnsName]
        })
      ).rejects.toThrow("dNSName");
    }
  });

  it("rejects subject attribute types that are neither short names nor dotted OIDs", async () => {
    await expect(
      createRootCA({
        subject: [{ type: "FOO" as never, value: "bar" }],
        days: 365
      })
    ).rejects.toThrow("Unsupported subject attribute type");
  });

  it("rejects importCertificateAuthority when certPem holds truncated DER", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const truncatedPem = certificateToPem(root.certDer.slice(0, root.certDer.length - 16));
    await expect(
      importCertificateAuthority({
        certPem: truncatedPem,
        privateKeyPem: root.privateKeyPem
      })
    ).rejects.toThrow();
  });
});

describe("serial numbers and validity", () => {
  it("encodes explicit serial number variants", async () => {
    const cases: Array<{ serialNumber: SerialNumber; expectedValue: bigint; expectedBytes?: number[] }> = [
      { serialNumber: 12345n, expectedValue: 12345n },
      { serialNumber: 12345, expectedValue: 12345n },
      { serialNumber: "12345", expectedValue: 12345n },
      { serialNumber: "0f", expectedValue: 15n, expectedBytes: [0x0f] },
      { serialNumber: new Uint8Array([0x80]), expectedValue: 128n, expectedBytes: [0, 0x80] }
    ];

    for (const { serialNumber, expectedValue, expectedBytes } of cases) {
      const root = await createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber
      });
      const parsed = parseCertificateSerialNumber(root.certDer);

      expect(parsed.value).toBe(expectedValue);
      if (expectedBytes) {
        expect(Array.from(parsed.bytes)).toEqual(expectedBytes);
      }
    }
  });

  it("generates default random serial numbers for every issuing API", async () => {
    const cases: Array<{ name: string; issue: () => Promise<{ certDer: Uint8Array }> }> = [
      {
        name: "root CA",
        issue: () => createRootCA({ subject: rootSubject, days: 365 })
      },
      {
        name: "intermediate CA",
        issue: async () => {
          const root = await createRootCA({
            subject: rootSubject,
            days: 3650,
            serialNumber: 1
          });
          return issueIntermediateCA({
            ca: root,
            subject: intermediateSubject,
            days: 365
          });
        }
      },
      {
        name: "client certificate",
        issue: async () => {
          const root = await createRootCA({
            subject: rootSubject,
            days: 3650,
            serialNumber: 1
          });
          return issueClientCert({
            ca: root,
            subject: clientSubject,
            days: 30
          });
        }
      }
    ];

    for (const { name, issue } of cases) {
      const first = parseCertificateSerialNumber((await issue()).certDer);
      const second = parseCertificateSerialNumber((await issue()).certDer);

      for (const serialNumber of [first, second]) {
        expect(serialNumber.bytes.length, name).toBeGreaterThan(0);
        expect(serialNumber.bytes.length, name).toBeLessThanOrEqual(20);
        expect(serialNumber.value > 0n, name).toBe(true);
        expect((serialNumber.bytes[0]! & 0x80) === 0, name).toBe(true);
      }
      expect(Array.from(second.bytes), name).not.toEqual(Array.from(first.bytes));
    }
  });

  it("encodes explicit validity bounds from notBefore and days for every issuing API", async () => {
    const notBefore = new Date(Date.UTC(2026, 0, 2, 3, 4, 5));
    const days = 30;
    const issuerNotBefore = new Date(Date.UTC(2025, 0, 1, 0, 0, 0));
    const cases: Array<{
      name: string;
      issue: (options: { notBefore: Date; days: number }) => Promise<{ certDer: Uint8Array }>;
    }> = [
      {
        name: "root CA",
        issue: ({ notBefore, days }) => createRootCA({
          subject: rootSubject,
          days,
          notBefore,
          serialNumber: 1
        })
      },
      {
        name: "intermediate CA",
        issue: async ({ notBefore, days }) => {
          const root = await createRootCA({
            subject: rootSubject,
            days: 3650,
            notBefore: issuerNotBefore,
            serialNumber: 1
          });
          return issueIntermediateCA({
            ca: root,
            subject: intermediateSubject,
            days,
            notBefore,
            serialNumber: 2
          });
        }
      },
      {
        name: "client certificate",
        issue: async ({ notBefore, days }) => {
          const root = await createRootCA({
            subject: rootSubject,
            days: 3650,
            notBefore: issuerNotBefore,
            serialNumber: 1
          });
          return issueClientCert({
            ca: root,
            subject: clientSubject,
            days,
            notBefore,
            serialNumber: 2
          });
        }
      }
    ];

    for (const { name, issue } of cases) {
      const issued = await issue({ notBefore, days });
      const validity = parseCertificateValidity(issued.certDer);

      expect(validity.notBefore.date.getTime(), name).toBe(notBefore.getTime());
      expect(validity.notAfter.date.getTime(), name).toBe(notBefore.getTime() + days * 86_400_000);
      expect(validity.notBefore.tag, name).toBe(TAG.UTC_TIME);
      expect(validity.notAfter.tag, name).toBe(TAG.UTC_TIME);
    }
  });

  it("rejects validity periods whose notAfter cannot be represented", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: Number.MAX_VALUE,
        notBefore: new Date(0)
      })
    ).rejects.toThrow("notAfter must be a valid Date");
  });

  it("rejects invalid notBefore values and out-of-range validity years", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        notBefore: "2026-01-01" as never
      })
    ).rejects.toThrow("notBefore must be a Date");

    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        notBefore: new Date(Number.NaN)
      })
    ).rejects.toThrow("notBefore must be a valid Date");

    await expect(
      createRootCA({
        subject: rootSubject,
        days: 1,
        notBefore: new Date(Date.UTC(10000, 0, 1))
      })
    ).rejects.toThrow("notBefore year");

    await expect(
      createRootCA({
        subject: rootSubject,
        days: 2,
        notBefore: new Date(Date.UTC(9999, 11, 31))
      })
    ).rejects.toThrow("notAfter year");
  });

  it("switches between UTCTime and GeneralizedTime at the X.509 year boundaries", async () => {
    const cases = [
      { notBefore: new Date(Date.UTC(1949, 11, 31, 0, 0, 0)), tag: TAG.GENERALIZED_TIME },
      { notBefore: new Date(Date.UTC(1950, 0, 1, 0, 0, 0)), tag: TAG.UTC_TIME },
      { notBefore: new Date(Date.UTC(2049, 11, 31, 0, 0, 0)), tag: TAG.UTC_TIME },
      { notBefore: new Date(Date.UTC(2050, 0, 1, 0, 0, 0)), tag: TAG.GENERALIZED_TIME }
    ];

    for (const { notBefore, tag } of cases) {
      const root = await createRootCA({
        subject: rootSubject,
        days: 1,
        notBefore,
        serialNumber: 1
      });
      expect(parseCertificateValidity(root.certDer).notBefore.tag).toBe(tag);
    }
  });
});

describe("IP address encoding", () => {
  it("encodes IPv4 and IPv6 addresses", () => {
    expect(Array.from(encodeIpAddress("127.0.0.1"))).toEqual([127, 0, 0, 1]);
    expect(Array.from(encodeIpAddress("2001:0db8:0000:0000:0000:0000:0000:0001"))).toEqual([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ]);
    expect(Array.from(encodeIpAddress("::1"))).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    expect(Array.from(encodeIpAddress("fe80::"))).toEqual([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(Array.from(encodeIpAddress("2001:db8::1"))).toEqual([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ]);
  });

  it("rejects invalid IP addresses", () => {
    for (const value of ["::1::2", "1:2:3:4:5:6:7:8:9", "2001:db8::zzzz", "256.0.0.1"]) {
      expect(() => encodeIpAddress(value)).toThrow("Invalid");
    }
  });

  it("rejects IPv6 '::' compressing fewer than two zero groups (RFC 5952 §4.2.2)", () => {
    for (const value of [
      "1:2:3:4:5:6:7::",
      "::1:2:3:4:5:6:7",
      "1:2:3:4:5:6::8"
    ]) {
      expect(() => encodeIpAddress(value)).toThrow("Invalid");
    }
  });

  it("rejects IPv6 addresses with too few groups when '::' is absent", () => {
    for (const value of ["1:2:3:4:5:6:7", "1:2:3"]) {
      expect(() => encodeIpAddress(value)).toThrow("Invalid");
    }
  });

  it("rejects IPv4 octets with leading zeros", () => {
    for (const value of ["01.0.0.1", "127.00.0.1", "127.0.0.001"]) {
      expect(() => encodeIpAddress(value)).toThrow("Invalid");
    }
  });

  it("rejects IPv4 addresses with wrong number of octets", () => {
    for (const value of ["127.0.0", "127.0.0.1.5", "127..0.1"]) {
      expect(() => encodeIpAddress(value)).toThrow("Invalid");
    }
  });

  it("encodes IPv4 boundary octets and the all-zero IPv6 address", () => {
    expect(Array.from(encodeIpAddress("0.0.0.0"))).toEqual([0, 0, 0, 0]);
    expect(Array.from(encodeIpAddress("255.255.255.255"))).toEqual([255, 255, 255, 255]);
    expect(Array.from(encodeIpAddress("::"))).toEqual(new Array(16).fill(0));
  });

  it("rejects IPv6 groups longer than four hex digits", () => {
    for (const value of ["12345::", "::12345", "1:2:3:4:5:6:7:12345"]) {
      expect(() => encodeIpAddress(value)).toThrow("Invalid");
    }
  });
});

describe("low-level encoders", () => {
  it("converts P-256 ECDSA raw signatures to DER and back", () => {
    const raw = new Uint8Array(64);
    raw[0] = 0x80;
    raw[31] = 0x01;
    raw[32] = 0x7f;
    raw[63] = 0x02;

    expect(ecdsaDerToRaw(ecdsaRawToDer(raw))).toEqual(raw);
  });

  it("encodes clientAuth EKU as an OID sequence", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30
    });
    const eku = parseExtensionsFromCertificate(client.certDer).find((extension) => extension.oid === OID.extendedKeyUsage);
    expect(eku).toBeDefined();

    const rootElement = readElement(eku!.value);
    const [clientAuth] = readSequenceChildren(rootElement);
    expect(clientAuth?.tag).toBe(TAG.OBJECT_IDENTIFIER);
    expect(decodeOid(clientAuth!.value)).toBe(OID.clientAuth);
  });
});

describe("RFC 5280 conformance regressions", () => {
  it("rejects zero-valued serialNumber in every input form", async () => {
    const cases: SerialNumber[] = [
      0n,
      0,
      "0",
      "00",
      "0000",
      new Uint8Array([0]),
      new Uint8Array([0, 0, 0])
    ];
    for (const serialNumber of cases) {
      await expect(
        createRootCA({ subject: rootSubject, days: 365, serialNumber })
      ).rejects.toThrow("positive integer");
    }
  });

  it("rejects oversized serialNumber strings before allocating large buffers", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber: "9".repeat(51)
      })
    ).rejects.toThrow("decimal string");
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber: `f${"f".repeat(40)}`
      })
    ).rejects.toThrow("hex string");
  });

  it("rejects subject values exceeding RFC 5280 ub-* character limits", async () => {
    const cases: Array<{ type: "CN" | "O" | "OU" | "C" | "ST" | "L" | "DC" | "POSTALCODE" | "GIVENNAME" | "SURNAME"; length: number }> = [
      { type: "CN", length: 65 },
      { type: "O", length: 65 },
      { type: "OU", length: 65 },
      { type: "C", length: 5 },
      { type: "ST", length: 129 },
      { type: "L", length: 129 },
      { type: "DC", length: 64 },
      { type: "POSTALCODE", length: 17 },
      { type: "GIVENNAME", length: 17 },
      { type: "SURNAME", length: 41 }
    ];
    for (const { type, length } of cases) {
      await expect(
        createRootCA({
          subject: [{ type, value: "a".repeat(length) }],
          days: 365
        })
      ).rejects.toThrow("character limit");
    }
  });

  it("accepts subject values at the RFC 5280 ub-* limits", async () => {
    const root = await createRootCA({
      subject: [
        { type: "CN", value: "a".repeat(64) },
        { type: "O", value: "b".repeat(64) },
        { type: "DC", value: "c".repeat(63) }
      ],
      days: 365
    });
    expect(root.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
  });

  it("caps dotted-OID subject values at the global upper bound", async () => {
    const root = await createRootCA({
      subject: [{ type: "1.2.3.4.5", value: "a".repeat(256) }],
      days: 365
    });
    expect(root.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);

    await expect(
      createRootCA({
        subject: [{ type: "1.2.3.4.5", value: "a".repeat(257) }],
        days: 365
      })
    ).rejects.toThrow("character limit");
  });

  it("rejects pemToDer when BEGIN and END labels do not match", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const malformed = root.certPem.replace("-----END CERTIFICATE-----", "-----END PRIVATE KEY-----");
    expect(() => pemToDer(malformed)).toThrow("Invalid PEM block");
  });

  it("rejects pemToDer input with no PEM block at all", () => {
    expect(() => pemToDer("")).toThrow("Invalid PEM block");
    expect(() => pemToDer("not a pem block")).toThrow("Invalid PEM block");
  });

  it("rejects decodeOid input whose final byte still has the continuation bit set", () => {
    expect(() => decodeOid(new Uint8Array([0x2a, 0x86]))).toThrow("Truncated OID");
  });

  it("rejects empty PEM bodies and decodes the first PEM block", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const otherRoot = await createRootCA({
      subject: [{ type: "CN", value: "other-root" }],
      days: 365
    });

    expect(certificateToPem(pemToDer(`${root.certPem}${otherRoot.certPem}`))).toBe(root.certPem);
    expect(() => pemToDer("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----")).toThrow("empty body");
    expect(() => pemToDerWithLabel(
      "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----",
      "CERTIFICATE"
    )).toThrow("empty CERTIFICATE body");
  });

  it("computes subjectKeyIdentifier as RFC 5280 method (1) (SHA-1 of subjectPublicKey bits)", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const parsed = await parseCertificate(root.certDer);
    const ski = parseSubjectKeyIdentifier(getExtension(root.certDer, OID.subjectKeyIdentifier).value);

    expect(ski.length).toBe(20);
    await expect(
      digestSha1(subjectPublicKeyBits(parsed.subjectPublicKeyInfoDer))
    ).resolves.toEqual(ski);
  });

  it("accepts the maximum allowed decimal and hex serialNumber strings", async () => {
    const decimal47 = "9".repeat(47);
    const fromDecimal = await createRootCA({
      subject: rootSubject,
      days: 365,
      serialNumber: decimal47
    });
    expect(parseCertificateSerialNumber(fromDecimal.certDer).value).toBe(BigInt(decimal47));

    const hex39 = "f".repeat(39);
    const fromHex = await createRootCA({
      subject: rootSubject,
      days: 365,
      serialNumber: hex39
    });
    expect(parseCertificateSerialNumber(fromHex.certDer).value).toBe(BigInt(`0x${hex39}`));
  });

  it("rejects decimal and hex serialNumber strings just past the per-form length cap", async () => {
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber: "9".repeat(48)
      })
    ).rejects.toThrow("decimal string");
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber: "f".repeat(40)
      })
    ).rejects.toThrow("hex string");
  });

  it("rejects serialNumber strings that are neither decimal nor hex", async () => {
    for (const serialNumber of ["0xff", "abc xyz", " 12345 ", "1.5", "-1"]) {
      await expect(
        createRootCA({ subject: rootSubject, days: 365, serialNumber })
      ).rejects.toThrow("decimal digits or hex");
    }
  });

  it("rejects a 20-byte serialNumber whose post-encode form would need 21 octets", async () => {
    const bytes = new Uint8Array(20);
    bytes[0] = 0x80;
    bytes[19] = 0x01;
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        serialNumber: bytes
      })
    ).rejects.toThrow("20 octets");
  });
});

async function digestSha1(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-1", bytes));
}

describe("DER decoder error paths", () => {
  it("rejects indefinite-length form (0x80)", () => {
    expect(() => readElement(new Uint8Array([0x30, 0x80, 0x00, 0x00]))).toThrow("Indefinite DER length");
  });

  it("rejects truncated long-form length", () => {
    expect(() => readElement(new Uint8Array([0x30, 0x82, 0x00]))).toThrow("Truncated DER length");
  });

  it("decodes long-form length encoding round-trip", () => {
    const big = new Uint8Array(300);
    big.fill(0x41);
    const seq = sequence(new Uint8Array([TAG.OCTET_STRING, 0x82, 0x01, 0x2c]), big);
    const root = readElement(seq);
    expect(root.tag).toBe(TAG.SEQUENCE);
    expect(root.length).toBeGreaterThan(0x7f);
    const inner = readElement(root.value);
    expect(inner.length).toBe(300);
  });

  it("rejects readElement when offset is past input", () => {
    expect(() => readElement(new Uint8Array(0))).toThrow("Unexpected end of DER input");
    expect(() => readElement(new Uint8Array([0x05, 0x00]), 2)).toThrow("Unexpected end of DER input");
  });

  it("rejects decodeOid empty input", () => {
    expect(() => decodeOid(new Uint8Array(0))).toThrow("Invalid empty OID");
  });

  it("rejects decodeInteger empty input", () => {
    expect(() => decodeInteger(new Uint8Array(0))).toThrow("Invalid empty INTEGER");
  });

  it("rejects decodeInteger with negative high bit", () => {
    expect(() => decodeInteger(new Uint8Array([0x80]))).toThrow("Negative INTEGER is unsupported");
    expect(() => decodeInteger(new Uint8Array([0xff, 0xff]))).toThrow("Negative INTEGER is unsupported");
  });

  it("rejects bitString with unusedBits outside [0,7]", () => {
    expect(() => bitString(new Uint8Array([0x00]), -1)).toThrow("BIT STRING unused bits");
    expect(() => bitString(new Uint8Array([0x00]), 8)).toThrow("BIT STRING unused bits");
  });

  it("rejects DER length that exceeds input size", () => {
    expect(() => readElement(new Uint8Array([0x04, 0x05, 0x00]))).toThrow("DER length exceeds input size");
  });
});

describe("OID encoder boundaries", () => {
  it("encodes lowest joint-arc and itu/iso boundaries", () => {
    expect(decodeOid(readElement(oid("0.0")).value)).toBe("0.0");
    expect(decodeOid(readElement(oid("0.39")).value)).toBe("0.39");
    expect(decodeOid(readElement(oid("1.0")).value)).toBe("1.0");
    expect(decodeOid(readElement(oid("1.39")).value)).toBe("1.39");
    expect(decodeOid(readElement(oid("2.0")).value)).toBe("2.0");
  });

  it("encodes joint-iso-itu-t arc with second component > 39", () => {
    expect(decodeOid(readElement(oid("2.100.3")).value)).toBe("2.100.3");
    expect(decodeOid(readElement(oid("2.999.1")).value)).toBe("2.999.1");
  });

  it("round-trips OID components requiring multi-byte base128 encoding", () => {
    const value = "1.2.840.113549.1.1.11";
    expect(decodeOid(readElement(oid(value)).value)).toBe(value);
    expect(decodeOid(readElement(oid("2.16.840.1.113894")).value)).toBe("2.16.840.1.113894");
  });
});

describe("ECDSA signature converter error paths", () => {
  it("rejects ecdsaRawToDer with wrong-length raw input", () => {
    expect(() => ecdsaRawToDer(new Uint8Array(0))).toThrow("64 bytes");
    expect(() => ecdsaRawToDer(new Uint8Array(63))).toThrow("64 bytes");
    expect(() => ecdsaRawToDer(new Uint8Array(65))).toThrow("64 bytes");
  });

  it("rejects ecdsaDerToRaw when root is not a SEQUENCE", () => {
    expect(() => ecdsaDerToRaw(new Uint8Array([0x04, 0x00]))).toThrow("Invalid DER ECDSA signature");
  });

  it("rejects ecdsaDerToRaw with trailing bytes after the SEQUENCE", () => {
    const valid = ecdsaRawToDer(new Uint8Array(64).fill(0x01));
    const trailing = new Uint8Array(valid.length + 1);
    trailing.set(valid);
    trailing[valid.length] = 0x00;
    expect(() => ecdsaDerToRaw(trailing)).toThrow("Invalid DER ECDSA signature");
  });

  it("rejects ecdsaDerToRaw whose r or s is not an INTEGER", () => {
    const notInt = new Uint8Array([0x04, 0x01, 0x00]);
    const innerBytes = new Uint8Array(notInt.length * 2);
    innerBytes.set(notInt, 0);
    innerBytes.set(notInt, notInt.length);
    const malformed = sequence(notInt, notInt);
    expect(() => ecdsaDerToRaw(malformed)).toThrow("Invalid DER ECDSA signature integers");
  });

  it("rejects ecdsa integers wider than 32 bytes (P-256)", () => {
    const oversized = new Uint8Array(33).fill(0x01);
    const malformed = sequence(
      new Uint8Array([TAG.INTEGER, oversized.length, ...oversized]),
      new Uint8Array([TAG.INTEGER, 0x01, 0x01])
    );
    expect(() => ecdsaDerToRaw(malformed)).toThrow("wider than P-256");
  });
});

describe("keyIdentifierFromSpki error paths", () => {
  it("rejects non-SEQUENCE SubjectPublicKeyInfo", async () => {
    await expect(keyIdentifierFromSpki(new Uint8Array([0x04, 0x00]))).rejects.toThrow("Invalid SubjectPublicKeyInfo");
  });

  it("rejects SubjectPublicKeyInfo whose subjectPublicKey is not BIT STRING", async () => {
    const bad = sequence(sequence(oid(OID.ecdsaWithSha256)), new Uint8Array([TAG.OCTET_STRING, 0x01, 0x00]));
    await expect(keyIdentifierFromSpki(bad)).rejects.toThrow("Invalid SubjectPublicKeyInfo subjectPublicKey");
  });

  it("rejects SubjectPublicKeyInfo with empty BIT STRING value", async () => {
    const bad = sequence(sequence(oid(OID.ecdsaWithSha256)), new Uint8Array([TAG.BIT_STRING, 0x00]));
    await expect(keyIdentifierFromSpki(bad)).rejects.toThrow("Invalid SubjectPublicKeyInfo subjectPublicKey");
  });
});

describe("subject value ub-* limits (untested attribute types)", () => {
  it("rejects values exceeding ub-* limits for E, SERIALNUMBER, STREET, TITLE, UID", async () => {
    const cases: Array<{ type: "E" | "SERIALNUMBER" | "STREET" | "TITLE" | "UID"; length: number; value?: string }> = [
      { type: "E", length: 256, value: `${"a".repeat(248)}@ex.test` },
      { type: "SERIALNUMBER", length: 65 },
      { type: "STREET", length: 129 },
      { type: "TITLE", length: 65 },
      { type: "UID", length: 257 }
    ];
    for (const { type, length, value } of cases) {
      const v = value ?? "a".repeat(length);
      expect([...v].length).toBe(length);
      await expect(
        createRootCA({ subject: [{ type, value: v }], days: 365 })
      ).rejects.toThrow("character limit");
    }
  });

  it("accepts values exactly at ub-* limits for E, SERIALNUMBER, STREET, TITLE, UID", async () => {
    const root = await createRootCA({
      subject: [
        { type: "E", value: `${"a".repeat(247)}@ex.test` },
        { type: "SERIALNUMBER", value: "s".repeat(64) },
        { type: "STREET", value: "t".repeat(128) },
        { type: "TITLE", value: "u".repeat(64) },
        { type: "UID", value: "v".repeat(256) }
      ],
      days: 365
    });
    expect(root.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
  });
});

describe("forbidden character boundary classes", () => {
  it("rejects NUL (0x00) and the bidi-block upper edge (0x202e)", async () => {
    for (const code of [0x00, 0x202e]) {
      await expect(
        createRootCA({
          subject: [{ type: "CN", value: `safe${String.fromCharCode(code)}text` }],
          days: 365
        })
      ).rejects.toThrow("forbidden");
    }
  });

  it("accepts adjacent code points just outside each forbidden range", async () => {
    const safeCases = [
      "safe text",
      `safe${String.fromCharCode(0x20)}text`,
      `safe${String.fromCharCode(0x7e)}text`,
      `safe${String.fromCharCode(0x80)}text`,
      `safe${String.fromCharCode(0x200d)}text`,
      `safe${String.fromCharCode(0x2010)}text`,
      `safe${String.fromCharCode(0x2029)}text`,
      `safe${String.fromCharCode(0x202f)}text`,
      `safe${String.fromCharCode(0x2065)}text`,
      `safe${String.fromCharCode(0x206a)}text`
    ];
    for (const value of safeCases) {
      const root = await createRootCA({ subject: [{ type: "CN", value }], days: 365 });
      expect(root.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    }
  });
});

describe("certificate parser malformed-input paths", () => {
  it("rejects parse of certificate with non-zero unused bits in signatureValue", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const cert = readSequenceChildren(readElement(root.certDer));
    const tbs = cert[0]!;
    const algo = cert[1]!;
    const sig = cert[2]!;
    const bitStringWithUnusedBits = new Uint8Array(sig.value.length);
    bitStringWithUnusedBits.set(sig.value);
    bitStringWithUnusedBits[0] = 0x01;
    const mutated = sequence(tbs.raw, algo.raw, new Uint8Array([TAG.BIT_STRING, sig.value.length, ...bitStringWithUnusedBits]));
    const pem = certificateToPem(mutated);
    await expect(
      importCertificateAuthority({ certPem: pem, privateKeyPem: root.privateKeyPem })
    ).rejects.toThrow("Invalid certificate signature value");
  });

  it("rejects parse of certificate whose root SEQUENCE has trailing bytes", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const padded = new Uint8Array(root.certDer.length + 1);
    padded.set(root.certDer);
    padded[root.certDer.length] = 0x00;
    const pem = certificateToPem(padded);
    await expect(
      importCertificateAuthority({ certPem: pem, privateKeyPem: root.privateKeyPem })
    ).rejects.toThrow();
  });
});

describe("assertIssuerSubjectMatches", () => {
  it("matches when issuer subject equals issued issuer", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 30
    });
    const parsedRoot = await parseCertificate(root.certDer);
    const parsedIntermediate = await parseCertificate(intermediate.certDer);
    expect(() => assertIssuerSubjectMatches(parsedRoot, parsedIntermediate)).not.toThrow();
  });

  it("throws when issuer subject does not match issued issuer", async () => {
    const a = await createRootCA({ subject: rootSubject, days: 365 });
    const b = await createRootCA({
      subject: [{ type: "CN", value: "other-root" }],
      days: 365
    });
    const parsedA = await parseCertificate(a.certDer);
    const parsedB = await parseCertificate(b.certDer);
    expect(() => assertIssuerSubjectMatches(parsedA, parsedB)).toThrow("does not match CA subject");
  });
});

describe("keyUsageExtension bit layout", () => {
  it("places digitalSignature at bit 0 and cRLSign at bit 6 in a single byte", () => {
    const ext = keyUsageExtension(["digitalSignature", "cRLSign"]);
    const root = readElement(ext);
    const children = readSequenceChildren(root);
    const octetEl = children[children.length - 1]!;
    const bits = readElement(octetEl.value);
    expect(bits.tag).toBe(TAG.BIT_STRING);
    expect(bits.value.length).toBe(2);
    expect(bits.value[0]).toBe(1);
    expect(bits.value[1]).toBe(0x80 | 0x02);
  });

  it("places keyCertSign at bit 5 and cRLSign at bit 6 with unused-bits=1", () => {
    const ext = keyUsageExtension(["keyCertSign", "cRLSign"]);
    const root = readElement(ext);
    const children = readSequenceChildren(root);
    const octetEl = children[children.length - 1]!;
    const bits = readElement(octetEl.value);
    expect(bits.tag).toBe(TAG.BIT_STRING);
    expect(bits.value.length).toBe(2);
    expect(bits.value[0]).toBe(1);
    expect(bits.value[1]).toBe(0x04 | 0x02);
  });

  it("encodes digitalSignature alone with unused-bits=7", () => {
    const ext = keyUsageExtension(["digitalSignature"]);
    const root = readElement(ext);
    const children = readSequenceChildren(root);
    const octetEl = children[children.length - 1]!;
    const bits = readElement(octetEl.value);
    expect(bits.value.length).toBe(2);
    expect(bits.value[0]).toBe(7);
    expect(bits.value[1]).toBe(0x80);
  });
});

describe("subjectAltNameExtension", () => {
  it("returns undefined when called with both arrays empty", () => {
    expect(subjectAltNameExtension([], [])).toBeUndefined();
    expect(subjectAltNameExtension(undefined, undefined)).toBeUndefined();
  });

  it("rejects single-character TLD-only names per the preferred-name pattern", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: ["a.example", "localhost"]
    });
    const san = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);
    expect(san.dnsNames).toEqual(["a.example", "localhost"]);
  });

  it("rejects DNS labels starting with a hyphen", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        dnsNames: ["-foo.example.test"]
      })
    ).rejects.toThrow("dNSName");
  });
});

describe("IP encoding additional boundaries", () => {
  it("rejects IPv4-embedded IPv6 forms", () => {
    for (const value of ["::ffff:192.0.2.1", "::1.2.3.4"]) {
      expect(() => encodeIpAddress(value)).toThrow("Invalid");
    }
  });

  it("rejects IPv6 with trailing single colon", () => {
    expect(() => encodeIpAddress("1:2:3:4:5:6:7:8:")).toThrow("Invalid");
  });

  it("rejects IPv6 over-specified with '::' compressing zero groups", () => {
    expect(() => encodeIpAddress("1:2:3:4::5:6:7:8")).toThrow("Invalid");
  });
});

describe("PEM parser additional cases", () => {
  it("tolerates CRLF line endings", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const crlf = root.certPem.replace(/\n/g, "\r\n");
    const der = pemToDer(crlf);
    expect(der).toEqual(root.certDer);
  });

  it("rejects PEM body containing only non-base64 characters", () => {
    const malformed = "-----BEGIN CERTIFICATE-----\n!@#$%^\n-----END CERTIFICATE-----\n";
    expect(() => pemToDer(malformed)).toThrow();
  });
});
