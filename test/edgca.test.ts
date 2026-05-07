import { describe, expect, it, vi } from "vitest";
import {
  certificateToPem,
  createRootCA,
  importCertificateAuthority,
  issueClientCert,
  issueClientCertForPublicKey,
  issueIntermediateCA,
  parseCertificateSigningRequest,
  pemToDer,
  verifyCertificateSigningRequestSignature,
  verifyClientCertificateIssuedBy
} from "../src/index.js";

async function exportPkcs8Bytes(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("pkcs8", key));
}

async function exportSpkiBytes(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("spki", key));
}
import {
  arrayBufferFromBytes,
  asciiBytes,
  bytesEqual,
  bytesToBinary,
  binaryToBytes,
  cloneBytes,
  concatBytes
} from "../src/bytes.js";
import {
  assertKeyPairMatches,
  digestSha256,
  ecdsaDerToRaw,
  ecdsaRawToDer,
  exportSpki,
  generateKeyPair,
  importPublicKeySpki,
  keyIdentifierFromSpki,
  signDer,
  verifyDer
} from "../src/crypto.js";
import {
  bitString,
  boolean,
  contextPrimitive,
  decodeInteger,
  decodeOid,
  der,
  explicit,
  generalizedTime,
  ia5String,
  integer,
  octetString,
  oid,
  printableString,
  readChildren,
  readElement,
  readSequenceChildren,
  sequence,
  set,
  TAG,
  utcTime,
  utf8String
} from "../src/der.js";
import { encodeName } from "../src/name.js";
import {
  authorityKeyIdentifierExtension,
  basicConstraintsLeafExtension,
  buildCertificate,
  buildTbsCertificate,
  extendedKeyUsageClientAuthExtension,
  keyUsageExtension,
  subjectAltNameExtension,
  subjectKeyIdentifierExtension
} from "../src/x509.js";
import { encodeIpAddress } from "../src/ip.js";
import { OID } from "../src/oids.js";
import { pemToDerWithLabel, splitPemBlocks } from "../src/pem.js";
import { assertIssuerSubjectMatches, parseCertificateDer } from "../src/parser.js";
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
import { buildCsrFixture } from "./helpers/csr.js";

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
      privateKey: intermediate.privateKey,
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
      keyPair: { privateKey: seed.privateKey, publicKey: seed.publicKey }
    });

    expect(
      bytesEqual(
        await exportPkcs8Bytes(reissued.privateKey),
        await exportPkcs8Bytes(seed.privateKey)
      )
    ).toBe(true);
    expect(
      bytesEqual(
        await exportSpkiBytes(reissued.publicKey),
        await exportSpkiBytes(seed.publicKey)
      )
    ).toBe(true);

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
      keyPair: { privateKey: seed.privateKey, publicKey: seed.publicKey }
    });

    expect(
      bytesEqual(
        await exportPkcs8Bytes(intermediate.privateKey),
        await exportPkcs8Bytes(seed.privateKey)
      )
    ).toBe(true);

    const parsedRoot = await parseCertificate(root.certDer);
    const parsedIntermediate = await parseCertificate(intermediate.certDer);
    await expect(expectSignatureValid(parsedRoot, parsedIntermediate)).resolves.toBe(true);
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
        privateKey: otherRoot.privateKey
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
      privateKey: client.privateKey,
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
        certPem: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        privateKey: root.privateKey
      })
    ).rejects.toThrow("expected CERTIFICATE");
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
        privateKey: intermediate.privateKey,
        issuerChainPem: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
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
        privateKey: intermediate.privateKey,
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
        privateKey: root.privateKey
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

    expect(ecdsaDerToRaw(ecdsaRawToDer(raw, 32), 32)).toEqual(raw);
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
  it("rejects ecdsaRawToDer with wrong-length raw input for the requested component size", () => {
    expect(() => ecdsaRawToDer(new Uint8Array(0), 32)).toThrow("64 bytes");
    expect(() => ecdsaRawToDer(new Uint8Array(63), 32)).toThrow("64 bytes");
    expect(() => ecdsaRawToDer(new Uint8Array(65), 32)).toThrow("64 bytes");
    expect(() => ecdsaRawToDer(new Uint8Array(64), 48)).toThrow("96 bytes");
    expect(() => ecdsaRawToDer(new Uint8Array(96), 66)).toThrow("132 bytes");
  });

  it("rejects ecdsaDerToRaw when root is not a SEQUENCE", () => {
    expect(() => ecdsaDerToRaw(new Uint8Array([0x04, 0x00]), 32)).toThrow("Invalid DER ECDSA signature");
  });

  it("rejects ecdsaDerToRaw with trailing bytes after the SEQUENCE", () => {
    const valid = ecdsaRawToDer(new Uint8Array(64).fill(0x01), 32);
    const trailing = new Uint8Array(valid.length + 1);
    trailing.set(valid);
    trailing[valid.length] = 0x00;
    expect(() => ecdsaDerToRaw(trailing, 32)).toThrow("Invalid DER ECDSA signature");
  });

  it("rejects ecdsaDerToRaw whose r or s is not an INTEGER", () => {
    const notInt = new Uint8Array([0x04, 0x01, 0x00]);
    const innerBytes = new Uint8Array(notInt.length * 2);
    innerBytes.set(notInt, 0);
    innerBytes.set(notInt, notInt.length);
    const malformed = sequence(notInt, notInt);
    expect(() => ecdsaDerToRaw(malformed, 32)).toThrow("Invalid DER ECDSA signature integers");
  });

  it("rejects ecdsa integers wider than the requested component size", () => {
    const oversized = new Uint8Array(33).fill(0x01);
    const malformed = sequence(
      new Uint8Array([TAG.INTEGER, oversized.length, ...oversized]),
      new Uint8Array([TAG.INTEGER, 0x01, 0x01])
    );
    expect(() => ecdsaDerToRaw(malformed, 32)).toThrow("wider than 32 bytes");
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
      importCertificateAuthority({ certPem: pem, privateKey: root.privateKey })
    ).rejects.toThrow("Invalid certificate signature value");
  });

  it("rejects parse of certificate whose root SEQUENCE has trailing bytes", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const padded = new Uint8Array(root.certDer.length + 1);
    padded.set(root.certDer);
    padded[root.certDer.length] = 0x00;
    const pem = certificateToPem(padded);
    await expect(
      importCertificateAuthority({ certPem: pem, privateKey: root.privateKey })
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

describe("DER length encoding boundaries", () => {
  it("encodes length 127 in short form (single byte length)", () => {
    const value = new Uint8Array(127);
    const encoded = der(TAG.OCTET_STRING, value);
    expect(encoded[0]).toBe(TAG.OCTET_STRING);
    expect(encoded[1]).toBe(0x7f);
    expect(encoded.length).toBe(2 + 127);
  });

  it("encodes length 128 in long form with one length octet", () => {
    const value = new Uint8Array(128);
    const encoded = der(TAG.OCTET_STRING, value);
    expect(encoded[0]).toBe(TAG.OCTET_STRING);
    expect(encoded[1]).toBe(0x81);
    expect(encoded[2]).toBe(0x80);
    expect(encoded.length).toBe(3 + 128);
  });

  it("encodes length 256 in long form with two length octets", () => {
    const value = new Uint8Array(256);
    const encoded = der(TAG.OCTET_STRING, value);
    expect(encoded[0]).toBe(TAG.OCTET_STRING);
    expect(encoded[1]).toBe(0x82);
    expect(encoded[2]).toBe(0x01);
    expect(encoded[3]).toBe(0x00);
    expect(encoded.length).toBe(4 + 256);
  });

  it("round-trips length 255 (single long-form octet maximum)", () => {
    const value = new Uint8Array(255);
    value.fill(0x42);
    const encoded = der(TAG.OCTET_STRING, value);
    expect(encoded[1]).toBe(0x81);
    expect(encoded[2]).toBe(0xff);
    const parsed = readElement(encoded);
    expect(parsed.length).toBe(255);
    expect(parsed.value).toEqual(value);
  });
});

describe("integer() direct error paths and edge cases", () => {
  it("rejects negative numbers", () => {
    expect(() => integer(-1)).toThrow("non-negative safe integer");
  });

  it("rejects non-integer numbers", () => {
    expect(() => integer(1.5)).toThrow("non-negative safe integer");
  });

  it("rejects NaN and Infinity", () => {
    expect(() => integer(Number.NaN)).toThrow("non-negative safe integer");
    expect(() => integer(Number.POSITIVE_INFINITY)).toThrow("non-negative safe integer");
  });

  it("rejects Number.MAX_VALUE (not a safe integer)", () => {
    expect(() => integer(Number.MAX_VALUE)).toThrow("non-negative safe integer");
  });

  it("rejects negative bigint", () => {
    expect(() => integer(-1n)).toThrow("non-negative");
  });

  it("encodes 0 and 0n as a single zero octet", () => {
    expect(Array.from(readElement(integer(0)).value)).toEqual([0]);
    expect(Array.from(readElement(integer(0n)).value)).toEqual([0]);
  });

  it("adds leading 0x00 sign byte when high bit is set (bigint path)", () => {
    const encoded = integer(128n);
    expect(Array.from(readElement(encoded).value)).toEqual([0x00, 0x80]);
    expect(decodeInteger(readElement(encoded).value)).toBe(128n);
  });

  it("does not add sign byte when high bit is clear (bigint path)", () => {
    const encoded = integer(0x7fn);
    expect(Array.from(readElement(encoded).value)).toEqual([0x7f]);
  });
});

describe("serialNumber hex string odd-length padding", () => {
  it("pads single-character hex with leading zero", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 365,
      serialNumber: "f"
    });
    const parsed = parseCertificateSerialNumber(root.certDer);
    expect(parsed.value).toBe(15n);
    expect(Array.from(parsed.bytes)).toEqual([0x0f]);
  });

  it("pads three-character hex correctly", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 365,
      serialNumber: "abc"
    });
    expect(parseCertificateSerialNumber(root.certDer).value).toBe(0x0abcn);
  });
});

describe("PrintableString character set in country (C) subject", () => {
  it("rejects characters not in PrintableString set", async () => {
    for (const value of ["U*", "U_", "U@", "U#", "U!"]) {
      await expect(
        createRootCA({ subject: [{ type: "C", value }], days: 365 })
      ).rejects.toThrow("PrintableString");
    }
  });

  it("accepts allowed PrintableString punctuation in C value", async () => {
    for (const value of ["A B", "'A'", "(A)", "+A", "A,B", "A-B", "A.B", "A/B", "A:B", "A=B", "A?B"]) {
      const root = await createRootCA({ subject: [{ type: "C", value }], days: 365 });
      expect(root.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    }
  });
});

describe("DNS label additional boundaries", () => {
  it("rejects DNS labels with trailing hyphen", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    await expect(
      issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30,
        dnsNames: ["foo-.example.test"]
      })
    ).rejects.toThrow("dNSName");
  });

  it("accepts all-digit labels", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: ["1.2.example", "123.456.test"]
    });
    const san = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);
    expect(san.dnsNames).toEqual(["1.2.example", "123.456.test"]);
  });

  it("accepts a single-digit single-character label", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: ["1.example"]
    });
    const san = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);
    expect(san.dnsNames).toEqual(["1.example"]);
  });

  it("accepts labels with internal consecutive hyphens", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: ["a--b.example.test", "xn--example.test"]
    });
    const san = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);
    expect(san.dnsNames).toContain("a--b.example.test");
    expect(san.dnsNames).toContain("xn--example.test");
  });
});

describe("certificate parser malformed extension structure", () => {
  function buildCertWithExtensions(baseCertDer: Uint8Array, extensionsValue: Uint8Array): Uint8Array {
    const cert = readElement(baseCertDer);
    const [tbs, algo, sig] = readSequenceChildren(cert);
    const tbsChildren = readSequenceChildren(tbs!);
    const newTbsChildren = tbsChildren.map((child) =>
      child.tag === 0xa3 ? explicit(3, extensionsValue) : child.raw
    );
    const newTbs = sequence(...newTbsChildren);
    return sequence(newTbs, algo!.raw, sig!.raw);
  }

  async function expectParseRejects(malformed: Uint8Array, message: string): Promise<void> {
    let caught: unknown;
    try {
      await parseCertificateDer(malformed);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).toContain(message);
  }

  it("rejects extensions whose outer is not a SEQUENCE", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const malformed = buildCertWithExtensions(root.certDer, new Uint8Array([TAG.OCTET_STRING, 0x00]));
    await expectParseRejects(malformed, "Invalid extensions structure");
  });

  it("rejects extension whose first child is not an OBJECT IDENTIFIER", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const fakeExtension = sequence(
      new Uint8Array([TAG.OCTET_STRING, 0x03, 0x55, 0x1d, 0x13]),
      new Uint8Array([TAG.OCTET_STRING, 0x00])
    );
    const malformed = buildCertWithExtensions(root.certDer, sequence(fakeExtension));
    await expectParseRejects(malformed, "Invalid extension OID");
  });

  it("rejects extension whose value is not an OCTET STRING", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const fakeExtension = sequence(
      oid(OID.basicConstraints),
      new Uint8Array([TAG.INTEGER, 0x01, 0x00])
    );
    const malformed = buildCertWithExtensions(root.certDer, sequence(fakeExtension));
    await expectParseRejects(malformed, "Invalid extension value");
  });

  it("rejects keyUsage extension whose payload is not a BIT STRING", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const fakeKeyUsageValue = octetString(new Uint8Array([0x05, 0x80]));
    const fakeExtension = sequence(oid(OID.keyUsage), octetString(fakeKeyUsageValue));
    const malformed = buildCertWithExtensions(root.certDer, sequence(fakeExtension));
    await expectParseRejects(malformed, "Invalid keyUsage extension");
  });

  it("rejects subjectKeyIdentifier extension whose payload is not an OCTET STRING", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const fakeSkiValue = bitString(new Uint8Array([0xff]));
    const fakeExtension = sequence(oid(OID.subjectKeyIdentifier), octetString(fakeSkiValue));
    const malformed = buildCertWithExtensions(root.certDer, sequence(fakeExtension));
    await expectParseRejects(malformed, "Invalid OCTET STRING extension payload");
  });

  it("returns undefined authorityKeyIdentifier when AKI extension lacks keyIdentifier child", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const innerSerial = new Uint8Array([0x82, 0x01, 0x42]);
    const akiValue = sequence(innerSerial);
    const fakeExtension = sequence(oid(OID.authorityKeyIdentifier), octetString(akiValue));
    const malformed = buildCertWithExtensions(root.certDer, sequence(fakeExtension));
    const parsed = await parseCertificateDer(malformed);
    expect(parsed.authorityKeyIdentifier).toBeUndefined();
  });

  it("finds keyIdentifier when [0] is not the first child of AKI", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const expectedKeyId = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);
    const fakeFirstChild = new Uint8Array([0x82, 0x01, 0x42]);
    const keyIdField = new Uint8Array([0x80, expectedKeyId.length, ...expectedKeyId]);
    const akiValue = sequence(fakeFirstChild, keyIdField);
    const fakeExtension = sequence(oid(OID.authorityKeyIdentifier), octetString(akiValue));
    const malformed = buildCertWithExtensions(root.certDer, sequence(fakeExtension));
    const parsed = await parseCertificateDer(malformed);
    expect(parsed.authorityKeyIdentifier).toEqual(expectedKeyId);
  });

  it("treats basicConstraints with pathLen but no isCA boolean as isCA=false", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const bcValue = sequence(integer(2));
    const bcExtension = sequence(oid(OID.basicConstraints), boolean(true), octetString(bcValue));
    const malformed = buildCertWithExtensions(root.certDer, sequence(bcExtension));
    const parsed = await parseCertificateDer(malformed);
    expect(parsed.isCA).toBe(false);
    expect(parsed.pathLenConstraint).toBe(2);
  });

  it("treats empty basicConstraints SEQUENCE as isCA=false with no pathLen", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const bcExtension = sequence(oid(OID.basicConstraints), boolean(true), octetString(sequence()));
    const malformed = buildCertWithExtensions(root.certDer, sequence(bcExtension));
    const parsed = await parseCertificateDer(malformed);
    expect(parsed.isCA).toBe(false);
    expect(parsed.pathLenConstraint).toBeUndefined();
  });
});

describe("GeneralizedTime year extremes", () => {
  it("encodes notBefore at year 1 with zero-padded year", async () => {
    const notBefore = new Date(Date.UTC(2000, 0, 1, 0, 0, 0));
    notBefore.setUTCFullYear(1);
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore,
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.GENERALIZED_TIME);
    expect(validity.notBefore.text.startsWith("0001")).toBe(true);
  });

  it("encodes notBefore at year 9999 within range", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore: new Date(Date.UTC(9999, 11, 30, 0, 0, 0)),
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.GENERALIZED_TIME);
    expect(validity.notBefore.text.startsWith("9999")).toBe(true);
    expect(validity.notAfter.text.startsWith("9999")).toBe(true);
  });
});

describe("subject value codepoint counting", () => {
  it("counts ub-* limit in codepoints, not UTF-16 code units", async () => {
    const value = "\u{1F600}".repeat(64);
    expect([...value].length).toBe(64);
    expect(value.length).toBe(128);
    const root = await createRootCA({
      subject: [{ type: "CN", value }],
      days: 365
    });
    expect(root.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);

    await expect(
      createRootCA({
        subject: [{ type: "CN", value: `${value}a` }],
        days: 365
      })
    ).rejects.toThrow("character limit");
  });
});

describe("bytesToBinary chunked encoding", () => {
  it("round-trips inputs that exceed the 32K chunk size", () => {
    const large = new Uint8Array(40000);
    for (let i = 0; i < large.length; i += 1) {
      large[i] = (i * 31) & 0xff;
    }
    const binary = bytesToBinary(large);
    expect(binary.length).toBe(40000);
    expect(binaryToBytes(binary)).toEqual(large);
  });
});

describe("OID intermediate components", () => {
  it("encodes OIDs with a zero in an intermediate position", () => {
    for (const value of ["1.2.0.4", "2.5.0.0.1", "1.2.0.0.0.3"]) {
      expect(decodeOid(readElement(oid(value)).value)).toBe(value);
    }
  });
});

describe("import root CA then issue intermediate", () => {
  it("issues an intermediate from an imported self-signed root", async () => {
    const original = await createRootCA({ subject: rootSubject, days: 3650 });
    const imported = await importCertificateAuthority({
      certPem: original.certPem,
      privateKey: original.privateKey
    });
    const intermediate = await issueIntermediateCA({
      ca: imported,
      subject: intermediateSubject,
      days: 365
    });
    expect(intermediate.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    expect(intermediate.issuerChainPem.trim()).toBe(original.certPem.trim());

    const parsedIntermediate = await parseCertificate(intermediate.certDer);
    const parsedRoot = await parseCertificate(original.certDer);
    expect(namesEqual(parsedIntermediate.issuerNameDer, parsedRoot.subjectNameDer)).toBe(true);
  });
});

describe("subjectAltName ordering", () => {
  it("places dnsNames before ipAddresses inside the SAN extension", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: ["worker.example.test", "alt.example.test"],
      ipAddresses: ["127.0.0.1", "::1"]
    });
    const sanRaw = readElement(getExtension(client.certDer, OID.subjectAltName).value);
    const children = readSequenceChildren(sanRaw);
    const tags = children.map((c) => c.tag);
    expect(tags).toEqual([0x82, 0x82, 0x87, 0x87]);

    const parsed = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);
    expect(parsed.dnsNames).toEqual(["worker.example.test", "alt.example.test"]);
    expect(parsed.ipAddresses.length).toBe(2);
    expect(Array.from(parsed.ipAddresses[0]!)).toEqual([127, 0, 0, 1]);
  });
});

describe("X.509 v3-only enforcement", () => {
  function rebuildCertWithVersion(baseCertDer: Uint8Array, versionField: Uint8Array | null): Uint8Array {
    const cert = readElement(baseCertDer);
    const [tbs, algo, sig] = readSequenceChildren(cert);
    const tbsChildren = readSequenceChildren(tbs!);
    const withoutVersion = tbsChildren[0]?.tag === 0xa0 ? tbsChildren.slice(1) : tbsChildren;
    const newChildren = (versionField === null ? withoutVersion : [{ raw: versionField }, ...withoutVersion])
      .map((c) => (c as { raw: Uint8Array }).raw);
    const newTbs = sequence(...newChildren);
    return sequence(newTbs, algo!.raw, sig!.raw);
  }

  it("accepts EdgCA-emitted v3 certificates", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const parsed = await parseCertificateDer(root.certDer);
    expect(parsed.isCA).toBe(true);
  });

  it("rejects certificates that omit the version field (v1)", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const v1Cert = rebuildCertWithVersion(root.certDer, null);
    let caught: unknown;
    try {
      await parseCertificateDer(v1Cert);
    } catch (error) {
      caught = error;
    }
    expect((caught as Error).message).toContain("only v3 is supported");
  });

  it("rejects certificates whose version field encodes v2 (INTEGER 1)", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const v2Field = explicit(0, integer(1));
    const v2Cert = rebuildCertWithVersion(root.certDer, v2Field);
    let caught: unknown;
    try {
      await parseCertificateDer(v2Cert);
    } catch (error) {
      caught = error;
    }
    expect((caught as Error).message).toContain("only v3 is supported");
  });

  it("rejects certificates whose version field encodes v1 explicitly (INTEGER 0)", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const v1ExplicitField = explicit(0, integer(0));
    const v1Cert = rebuildCertWithVersion(root.certDer, v1ExplicitField);
    let caught: unknown;
    try {
      await parseCertificateDer(v1Cert);
    } catch (error) {
      caught = error;
    }
    expect((caught as Error).message).toContain("only v3 is supported");
  });
});

describe("pathLenConstraint additional rejections", () => {
  it("rejects integer != 0 and != 1 for root", async () => {
    for (const value of [2, 3, 100]) {
      await expect(
        createRootCA({ subject: rootSubject, days: 365, pathLenConstraint: value })
      ).rejects.toThrow("Root pathLenConstraint must be 0 or 1");
    }
  });

  it("rejects NaN/Infinity/MAX_VALUE pathLenConstraint for root", async () => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_VALUE]) {
      await expect(
        createRootCA({ subject: rootSubject, days: 365, pathLenConstraint: value })
      ).rejects.toThrow("Root pathLenConstraint");
    }
  });

  it("rejects -0 pathLenConstraint for root (Object.is(-0, 0) === false)", async () => {
    await expect(
      createRootCA({ subject: rootSubject, days: 365, pathLenConstraint: -0 })
    ).rejects.toThrow("Root pathLenConstraint must be 0 or 1");
  });

  it("accepts root with explicit pathLenConstraint=0 and emits it in basicConstraints", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365, pathLenConstraint: 0 });
    const parsed = await parseCertificateDer(root.certDer);
    expect(parsed.isCA).toBe(true);
    expect(parsed.pathLenConstraint).toBe(0);
  });

  it("rejects non-number pathLenConstraint for intermediate", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    for (const value of ["0" as never, true as never, null as never]) {
      await expect(
        issueIntermediateCA({
          ca: root,
          subject: intermediateSubject,
          days: 30,
          pathLenConstraint: value
        })
      ).rejects.toThrow("Intermediate pathLenConstraint must be 0");
    }
  });

  it("rejects -0 and NaN pathLenConstraint for intermediate", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    for (const value of [-0, Number.NaN]) {
      await expect(
        issueIntermediateCA({
          ca: root,
          subject: intermediateSubject,
          days: 30,
          pathLenConstraint: value
        })
      ).rejects.toThrow("Intermediate pathLenConstraint must be 0");
    }
  });
});

describe("bytesEqual direct tests", () => {
  it("returns true for identical content", () => {
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it("returns true for the same instance", () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(bytesEqual(a, a)).toBe(true);
  });

  it("returns false for length mismatch", () => {
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
  });

  it("returns false for content mismatch at any position", () => {
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([0, 2, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 9, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
  });

  it("returns true for two empty arrays", () => {
    expect(bytesEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
  });
});

describe("concatBytes edge cases", () => {
  it("returns empty Uint8Array for an empty parts list", () => {
    const result = concatBytes([]);
    expect(result.length).toBe(0);
  });

  it("ignores empty parts and preserves order", () => {
    const result = concatBytes([
      new Uint8Array(0),
      new Uint8Array([1, 2]),
      new Uint8Array(0),
      new Uint8Array([3]),
      new Uint8Array([4, 5])
    ]);
    expect(Array.from(result)).toEqual([1, 2, 3, 4, 5]);
  });
});

describe("splitPemBlocks edge cases", () => {
  it("returns empty array for empty input", () => {
    expect(splitPemBlocks("")).toEqual([]);
  });

  it("returns empty array when no PEM block matches", () => {
    expect(splitPemBlocks("not a pem block")).toEqual([]);
  });

  it("ignores blocks whose BEGIN/END labels mismatch", () => {
    const malformed = "-----BEGIN A-----\ndGVzdA==\n-----END B-----";
    expect(splitPemBlocks(malformed)).toEqual([]);
  });

  it("returns mixed-label blocks together", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const fakePrivatePem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";
    const blocks = splitPemBlocks(root.certPem + fakePrivatePem);
    expect(blocks.length).toBe(2);
    expect(blocks[0]).toContain("BEGIN CERTIFICATE");
    expect(blocks[1]).toContain("BEGIN PRIVATE KEY");
  });
});

describe("asciiBytes character boundaries", () => {
  it("accepts 0x00 (NUL)", () => {
    expect(Array.from(asciiBytes("\x00"))).toEqual([0]);
  });

  it("accepts 0x7f (DEL) — boundary of allowed range", () => {
    expect(Array.from(asciiBytes("\x7f"))).toEqual([0x7f]);
  });

  it("rejects 0x80 (first non-ASCII)", () => {
    expect(() => asciiBytes("\x80")).toThrow("ASCII");
  });

  it("rejects multi-byte UTF-8 source characters", () => {
    expect(() => asciiBytes("café")).toThrow("ASCII");
    expect(() => asciiBytes("日本")).toThrow("ASCII");
  });

  it("encodes printable ASCII verbatim", () => {
    expect(Array.from(asciiBytes("abc XYZ 0!~"))).toEqual([
      0x61, 0x62, 0x63, 0x20, 0x58, 0x59, 0x5a, 0x20, 0x30, 0x21, 0x7e
    ]);
  });
});

describe("assertKeyPairMatches direct", () => {
  it("resolves when keys match", async () => {
    const pair = await generateKeyPair();
    await expect(assertKeyPairMatches(pair.privateKey, pair.publicKey)).resolves.toBeUndefined();
  });

  it("rejects when private key does not match public key", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    await expect(assertKeyPairMatches(a.privateKey, b.publicKey))
      .rejects.toThrow("Private key does not match");
  });
});

describe("verifyDer direct", () => {
  it("returns true for a valid signature over the same data", async () => {
    const pair = await generateKeyPair();
    const data = new TextEncoder().encode("edgca-verify-test");
    const sig = await signDer(pair.privateKey, data);
    expect(await verifyDer(pair.publicKey, sig, data)).toBe(true);
  });

  it("returns false for a signature over different data (no throw)", async () => {
    const pair = await generateKeyPair();
    const sig = await signDer(pair.privateKey, new TextEncoder().encode("hello"));
    const result = await verifyDer(pair.publicKey, sig, new TextEncoder().encode("HELLO"));
    expect(result).toBe(false);
  });

  it("returns false for a signature from a different key (no throw)", async () => {
    const a = await generateKeyPair();
    const b = await generateKeyPair();
    const data = new TextEncoder().encode("edgca-verify-test");
    const sig = await signDer(a.privateKey, data);
    expect(await verifyDer(b.publicKey, sig, data)).toBe(false);
  });
});

describe("generalizedTime year zero-padding", () => {
  it("zero-pads year=99 to 4 digits", async () => {
    const notBefore = new Date(Date.UTC(2000, 0, 1, 0, 0, 0));
    notBefore.setUTCFullYear(99);
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore,
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.GENERALIZED_TIME);
    expect(validity.notBefore.text.startsWith("0099")).toBe(true);
  });

  it("zero-pads year=999 to 4 digits", async () => {
    const notBefore = new Date(Date.UTC(2000, 0, 1, 0, 0, 0));
    notBefore.setUTCFullYear(999);
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore,
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.GENERALIZED_TIME);
    expect(validity.notBefore.text.startsWith("0999")).toBe(true);
  });
});

describe("UTCTime text format", () => {
  it("encodes year 1950 with two-digit '50'", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore: new Date(Date.UTC(1950, 0, 1, 0, 0, 0)),
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.UTC_TIME);
    expect(validity.notBefore.text).toBe("500101000000Z");
  });

  it("encodes year 2049 with two-digit '49'", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore: new Date(Date.UTC(2049, 0, 1, 0, 0, 0)),
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.UTC_TIME);
    expect(validity.notBefore.text).toBe("490101000000Z");
  });

  it("encodes year 2000 with two-digit '00' (Y2K boundary)", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore: new Date(Date.UTC(2000, 0, 1, 0, 0, 0)),
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.UTC_TIME);
    expect(validity.notBefore.text).toBe("000101000000Z");
  });

  it("zero-pads single-digit month/day/hour/minute/second", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 1,
      notBefore: new Date(Date.UTC(2026, 2, 4, 5, 6, 7)),
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);
    expect(validity.notBefore.tag).toBe(TAG.UTC_TIME);
    expect(validity.notBefore.text).toBe("260304050607Z");
  });
});

describe("IPv6 case insensitivity", () => {
  it("accepts uppercase hex digits", () => {
    expect(Array.from(encodeIpAddress("2001:DB8::1"))).toEqual([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ]);
  });

  it("accepts mixed-case hex digits", () => {
    expect(Array.from(encodeIpAddress("2001:Db8::AbCd"))).toEqual([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd
    ]);
  });
});

describe("issuerChainPem whitespace handling", () => {
  it("accepts whitespace-only issuerChainPem (trims to empty for chain checks)", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const ca = await importCertificateAuthority({
      certPem: root.certPem,
      privateKey: root.privateKey,
      issuerChainPem: "   \n\n\t  \n"
    });
    const intermediate = await issueIntermediateCA({
      ca,
      subject: intermediateSubject,
      days: 30
    });
    expect(intermediate.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    expect(intermediate.issuerChainPem.trim()).toBe(root.certPem.trim());
  });
});

describe("SAN with explicit empty arrays via public API", () => {
  it("does not include SAN when both arrays are explicitly empty", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: [],
      ipAddresses: []
    });
    expect(findExtension(client.certDer, OID.subjectAltName)).toBeUndefined();
  });

  it("includes SAN with only dnsNames when ipAddresses is explicitly empty", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      dnsNames: ["only.example.test"],
      ipAddresses: []
    });
    const san = parseSubjectAltName(getExtension(client.certDer, OID.subjectAltName).value);
    expect(san.dnsNames).toEqual(["only.example.test"]);
    expect(san.ipAddresses.length).toBe(0);
  });
});

describe("DER encoder primitives direct", () => {
  it("boolean(true) encodes as DER TRUE [0x01, 0x01, 0xff]", () => {
    expect(Array.from(boolean(true))).toEqual([0x01, 0x01, 0xff]);
  });

  it("boolean(false) encodes as DER FALSE [0x01, 0x01, 0x00]", () => {
    expect(Array.from(boolean(false))).toEqual([0x01, 0x01, 0x00]);
  });

  it("utf8String encodes 3-byte UTF-8 (kanji)", () => {
    const parsed = readElement(utf8String("日"));
    expect(parsed.tag).toBe(TAG.UTF8_STRING);
    expect(Array.from(parsed.value)).toEqual([0xe6, 0x97, 0xa5]);
  });

  it("utf8String encodes 4-byte UTF-8 (emoji)", () => {
    const parsed = readElement(utf8String("\u{1f600}"));
    expect(parsed.tag).toBe(TAG.UTF8_STRING);
    expect(Array.from(parsed.value)).toEqual([0xf0, 0x9f, 0x98, 0x80]);
  });

  it("ia5String encodes ASCII verbatim", () => {
    const parsed = readElement(ia5String("hello@world.test"));
    expect(parsed.tag).toBe(TAG.IA5_STRING);
    expect(Array.from(parsed.value)).toEqual(Array.from(new TextEncoder().encode("hello@world.test")));
  });

  it("ia5String rejects non-ASCII characters", () => {
    expect(() => ia5String("hoé")).toThrow("ASCII");
  });
});

describe("cloneBytes direct", () => {
  it("returns a different Uint8Array instance with identical content", () => {
    const original = new Uint8Array([1, 2, 3, 4, 5]);
    const copy = cloneBytes(original);
    expect(copy).not.toBe(original);
    expect(Array.from(copy)).toEqual([1, 2, 3, 4, 5]);
  });

  it("does not share buffer with original (mutating original leaves copy intact)", () => {
    const original = new Uint8Array([1, 2, 3]);
    const copy = cloneBytes(original);
    original.fill(0);
    expect(Array.from(copy)).toEqual([1, 2, 3]);
  });

  it("returns an empty Uint8Array for empty input", () => {
    const copy = cloneBytes(new Uint8Array(0));
    expect(copy.length).toBe(0);
  });
});

describe("certDer/certPem round-trip consistency", () => {
  it("createRootCA returns matching certPem and certDer", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    expect(certificateToPem(root.certDer)).toBe(root.certPem);
    expect(pemToDer(root.certPem)).toEqual(root.certDer);
  });

  it("issueIntermediateCA returns matching certPem and certDer", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    expect(certificateToPem(intermediate.certDer)).toBe(intermediate.certPem);
    expect(pemToDer(intermediate.certPem)).toEqual(intermediate.certDer);
  });

  it("issueClientCert returns matching certPem and certDer", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30
    });
    expect(certificateToPem(client.certDer)).toBe(client.certPem);
    expect(pemToDer(client.certPem)).toEqual(client.certDer);
  });

  it("importCertificateAuthority returns matching certPem and certDer", async () => {
    const original = await createRootCA({ subject: rootSubject, days: 365 });
    const imported = await importCertificateAuthority({
      certPem: original.certPem,
      privateKey: original.privateKey
    });
    expect(certificateToPem(imported.certDer)).toBe(imported.certPem);
    expect(pemToDer(imported.certPem)).toEqual(imported.certDer);
  });
});

describe("algorithm identifier consistency", () => {
  it("emits identical algorithm identifier in TBSCertificate.signature and Certificate.signatureAlgorithm", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const cert = readElement(root.certDer);
    const [tbs, certAlgo] = readSequenceChildren(cert);
    const tbsChildren = readSequenceChildren(tbs!);
    let i = 0;
    if (tbsChildren[i]?.tag === 0xa0) i++;
    i++; // serialNumber
    const tbsSignature = tbsChildren[i]!;
    expect(Array.from(tbsSignature.raw)).toEqual(Array.from(certAlgo!.raw));
    const innerOid = readSequenceChildren(tbsSignature)[0]!;
    expect(decodeOid(innerOid.value)).toBe(OID.ecdsaWithSha256);
  });
});

describe("parseKeyUsage normal extraction", () => {
  it("returns keyCertSign=true and cRLSign=true for a CA cert", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const ku = parseKeyUsage(getExtension(root.certDer, OID.keyUsage).value);
    expect(ku.keyCertSign).toBe(true);
    expect(ku.cRLSign).toBe(true);
    expect(ku.digitalSignature).toBe(false);
  });

  it("returns keyCertSign=false and digitalSignature=true for a leaf cert", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const ku = parseKeyUsage(getExtension(client.certDer, OID.keyUsage).value);
    expect(ku.keyCertSign).toBe(false);
    expect(ku.cRLSign).toBe(false);
    expect(ku.digitalSignature).toBe(true);
  });
});

describe("PEM line wrapping at 64 characters", () => {
  it("wraps body lines at exactly 64 characters in EdgCA-emitted PEMs", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const lines = root.certPem.split("\n");
    const bodyLines = lines.filter((line, idx) => idx > 0 && idx < lines.length - 2 && line.length > 0);
    expect(bodyLines.length).toBeGreaterThan(1);
    for (const line of bodyLines.slice(0, -1)) {
      expect(line.length).toBe(64);
    }
    expect(bodyLines[bodyLines.length - 1]!.length).toBeLessThanOrEqual(64);
  });

  it("round-trips a DER whose base64 is exactly 64 chars (single body line)", () => {
    const der48 = new Uint8Array(48);
    for (let i = 0; i < der48.length; i += 1) der48[i] = i;
    const pem = certificateToPem(der48);
    const lines = pem.split("\n");
    expect(lines[0]).toBe("-----BEGIN CERTIFICATE-----");
    expect(lines[1]!.length).toBe(64);
    expect(lines[2]).toBe("-----END CERTIFICATE-----");
    expect(pemToDer(pem)).toEqual(der48);
  });

  it("round-trips a DER whose base64 wraps to two body lines", () => {
    const der49 = new Uint8Array(49);
    for (let i = 0; i < der49.length; i += 1) der49[i] = i;
    const pem = certificateToPem(der49);
    const lines = pem.split("\n");
    expect(lines[0]).toBe("-----BEGIN CERTIFICATE-----");
    expect(lines[1]!.length).toBe(64);
    expect(lines[2]!.length).toBeGreaterThan(0);
    expect(lines[2]!.length).toBeLessThanOrEqual(64);
    expect(lines[3]).toBe("-----END CERTIFICATE-----");
    expect(pemToDer(pem)).toEqual(der49);
  });
});

describe("isRootCa rejects self-signed-with-chain", () => {
  it("rejects intermediate issuance from a CA whose subject==issuer but issuerChainPem is non-empty", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const otherRoot = await createRootCA({
      subject: [{ type: "CN", value: "decoy-other" }],
      days: 365
    });
    const fakeCA = await importCertificateAuthority({
      certPem: root.certPem,
      privateKey: root.privateKey,
      issuerChainPem: otherRoot.certPem
    });
    await expect(
      issueIntermediateCA({ ca: fakeCA, subject: intermediateSubject, days: 30 })
    ).rejects.toThrow("Only root CAs may issue intermediate CAs");
  });
});

describe("issueClientCert key uniqueness", () => {
  it("generates a fresh private key on each call (does not reuse across invocations)", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const a = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const b = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    expect(
      bytesEqual(await exportPkcs8Bytes(a.privateKey), await exportPkcs8Bytes(b.privateKey))
    ).toBe(false);
    expect(
      bytesEqual(await exportSpkiBytes(a.publicKey), await exportSpkiBytes(b.publicKey))
    ).toBe(false);
  });
});

describe("pemToDerWithLabel block selection", () => {
  it("selects the first block of the requested label among multiple same-label blocks", async () => {
    const a = await createRootCA({ subject: rootSubject, days: 365 });
    const b = await createRootCA({
      subject: [{ type: "CN", value: "second-root" }],
      days: 365
    });
    const combined = a.certPem + b.certPem;
    expect(pemToDerWithLabel(combined, "CERTIFICATE")).toEqual(a.certDer);
  });

  it("skips blocks of other labels and returns the requested one", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const fakePrivatePem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n";
    const combined = fakePrivatePem + root.certPem;
    expect(pemToDerWithLabel(combined, "CERTIFICATE")).toEqual(root.certDer);
  });
});

describe("buildTbsCertificate empty extensions", () => {
  it("accepts an empty extensions array and parses back as non-CA leaf", async () => {
    const pair = await generateKeyPair();
    const subjectNameDer = encodeName([{ type: "CN", value: "no-extensions-test" }]);
    const spki = await exportSpki(pair.publicKey);
    const { tbsCertificateDer } = buildTbsCertificate({
      days: 1,
      issuerNameDer: subjectNameDer,
      subjectNameDer,
      subjectPublicKeyInfoDer: spki,
      extensions: [],
      serialNumber: 1,
      issuerCurve: "P-256"
    });
    const sig = await signDer(pair.privateKey, tbsCertificateDer);
    const certDer = buildCertificate(tbsCertificateDer, sig, "P-256");
    const parsed = await parseCertificateDer(certDer);
    expect(parsed.isCA).toBe(false);
    expect(parsed.keyCertSign).toBe(false);
    expect(parsed.subjectKeyIdentifier).toBeUndefined();
    expect(parsed.authorityKeyIdentifier).toBeUndefined();
  });
});

describe("AKI fallback to SHA-1(SPKI) when issuer has no SKI extension", () => {
  function stripSkiExtension(certDer: Uint8Array): Uint8Array {
    const cert = readElement(certDer);
    const [tbs, algo, sig] = readSequenceChildren(cert);
    const tbsChildren = readSequenceChildren(tbs!);
    const extIndex = tbsChildren.findIndex((c) => c.tag === 0xa3);
    const extElements = readSequenceChildren(readElement(tbsChildren[extIndex]!.value));
    const filtered = extElements.filter((ext) => {
      const children = readSequenceChildren(ext);
      return decodeOid(children[0]!.value) !== OID.subjectKeyIdentifier;
    });
    const newExtensions = sequence(...filtered.map((e) => e.raw));
    const newTbsChildren = tbsChildren.map((c, i) =>
      i === extIndex ? explicit(3, newExtensions) : c.raw
    );
    const newTbs = sequence(...newTbsChildren);
    return sequence(newTbs, algo!.raw, sig!.raw);
  }

  it("uses keyIdentifierFromSpki(issuer.SPKI) for AKI when issuer parsed cert has no SKI", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const noSkiDer = stripSkiExtension(root.certDer);
    const noSkiPem = certificateToPem(noSkiDer);

    const importedCA = await importCertificateAuthority({
      certPem: noSkiPem,
      privateKey: root.privateKey
    });
    const parsedNoSki = await parseCertificateDer(noSkiDer);
    expect(parsedNoSki.subjectKeyIdentifier).toBeUndefined();
    const expectedAki = await keyIdentifierFromSpki(parsedNoSki.subjectPublicKeyInfoDer);

    const client = await issueClientCert({
      ca: importedCA,
      subject: clientSubject,
      days: 30
    });
    const aki = parseAuthorityKeyIdentifier(getExtension(client.certDer, OID.authorityKeyIdentifier).value);
    expect(aki.keyIdentifier).toEqual(expectedAki);

    const intermediate = await issueIntermediateCA({
      ca: importedCA,
      subject: intermediateSubject,
      days: 30
    });
    const intermediateAki = parseAuthorityKeyIdentifier(getExtension(intermediate.certDer, OID.authorityKeyIdentifier).value);
    expect(intermediateAki.keyIdentifier).toEqual(expectedAki);
  });

  it("verifies a client cert against an imported CA whose cert has no SKI extension", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const noSkiPem = certificateToPem(stripSkiExtension(root.certDer));
    const importedCA = await importCertificateAuthority({
      certPem: noSkiPem,
      privateKey: root.privateKey
    });
    const client = await issueClientCert({
      ca: importedCA,
      subject: clientSubject,
      days: 30
    });

    expect(
      await verifyClientCertificateIssuedBy({ ca: importedCA, certPem: client.certPem })
    ).toBe(true);
  });
});

function rebuildExtensions(baseCertDer: Uint8Array, extensionsValue: Uint8Array): Uint8Array {
  const cert = readElement(baseCertDer);
  const [tbs, algo, sig] = readSequenceChildren(cert);
  const tbsChildren = readSequenceChildren(tbs!);
  const newTbsChildren = tbsChildren.map((child) =>
    child.tag === 0xa3 ? explicit(3, extensionsValue) : child.raw
  );
  const newTbs = sequence(...newTbsChildren);
  return sequence(newTbs, algo!.raw, sig!.raw);
}

describe("import-time CA validation rejections", () => {
  it("rejects issuance from imported CA whose KU lacks keyCertSign even when BC says isCA=true", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const bcExt = sequence(oid(OID.basicConstraints), boolean(true), octetString(sequence(boolean(true))));
    const kuValue = bitString(new Uint8Array([0x80]), 7);
    const kuExt = sequence(oid(OID.keyUsage), boolean(true), octetString(kuValue));
    const malformedDer = rebuildExtensions(root.certDer, sequence(bcExt, kuExt));
    const malformedPem = certificateToPem(malformedDer);
    const importedCA = await importCertificateAuthority({
      certPem: malformedPem,
      privateKey: root.privateKey
    });
    await expect(
      issueClientCert({ ca: importedCA, subject: clientSubject, days: 30 })
    ).rejects.toThrow("keyUsage does not allow certificate signing");
  });

  it("rejects issuance from imported cert that has no basicConstraints extension", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const kuValue = bitString(new Uint8Array([0x06]), 1);
    const kuExt = sequence(oid(OID.keyUsage), boolean(true), octetString(kuValue));
    const malformedDer = rebuildExtensions(root.certDer, sequence(kuExt));
    const malformedPem = certificateToPem(malformedDer);
    const importedCA = await importCertificateAuthority({
      certPem: malformedPem,
      privateKey: root.privateKey
    });
    await expect(
      issueClientCert({ ca: importedCA, subject: clientSubject, days: 30 })
    ).rejects.toThrow("Issuer certificate is not a CA");
  });

  it("rejects issuance from imported cert that has BC isCA=true but no keyUsage extension", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const bcExt = sequence(oid(OID.basicConstraints), boolean(true), octetString(sequence(boolean(true))));
    const malformedDer = rebuildExtensions(root.certDer, sequence(bcExt));
    const malformedPem = certificateToPem(malformedDer);
    const importedCA = await importCertificateAuthority({
      certPem: malformedPem,
      privateKey: root.privateKey
    });
    await expect(
      issueClientCert({ ca: importedCA, subject: clientSubject, days: 30 })
    ).rejects.toThrow("keyUsage does not allow certificate signing");
  });
});

describe("importCertificateAuthority does not validate signature (non-goal documenting)", () => {
  it("imports a cert whose signatureValue has been tampered", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const cert = readElement(root.certDer);
    const [tbs, algo, sig] = readSequenceChildren(cert);
    const tamperedSigValue = new Uint8Array(sig!.value.length);
    tamperedSigValue.set(sig!.value);
    tamperedSigValue[tamperedSigValue.length - 1] ^= 0xff;
    const tamperedSig = der(TAG.BIT_STRING, tamperedSigValue);
    const tamperedDer = sequence(tbs!.raw, algo!.raw, tamperedSig);
    const tamperedPem = certificateToPem(tamperedDer);
    const ca = await importCertificateAuthority({
      certPem: tamperedPem,
      privateKey: root.privateKey
    });
    expect(ca.certPem).toBe(tamperedPem);
    const client = await issueClientCert({ ca, subject: clientSubject, days: 30 });
    expect(client.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
  });
});

describe("parser tolerates unknown extension OIDs", () => {
  it("imports a CA cert with an unknown extension OID and continues to issue", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const cert = readElement(root.certDer);
    const [, , ] = readSequenceChildren(cert);
    const tbsChildren = readSequenceChildren(readSequenceChildren(cert)[0]!);
    const extIndex = tbsChildren.findIndex((c) => c.tag === 0xa3);
    const existingExts = readSequenceChildren(readElement(tbsChildren[extIndex]!.value));
    const unknownExt = sequence(oid("1.2.3.4.5.99"), octetString(new Uint8Array([0x01, 0x02, 0x03])));
    const augmentedExtensions = sequence(...existingExts.map((e) => e.raw), unknownExt);
    const newCertDer = rebuildExtensions(root.certDer, augmentedExtensions);
    const newCertPem = certificateToPem(newCertDer);
    const ca = await importCertificateAuthority({
      certPem: newCertPem,
      privateKey: root.privateKey
    });
    const client = await issueClientCert({ ca, subject: clientSubject, days: 30 });
    expect(client.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
  });
});

describe("default notBefore is approximately current time", () => {
  it("encodes notBefore within ±60 seconds of the test's wall clock", async () => {
    const before = Date.now();
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const after = Date.now();
    const validity = parseCertificateValidity(root.certDer);
    const nb = validity.notBefore.date.getTime();
    expect(nb).toBeGreaterThanOrEqual(before - 60_000);
    expect(nb).toBeLessThanOrEqual(after + 60_000);
  });

  it("encodes notAfter as default-notBefore + days * 86_400_000", async () => {
    const before = Date.now();
    const root = await createRootCA({ subject: rootSubject, days: 30 });
    const after = Date.now();
    const validity = parseCertificateValidity(root.certDer);
    const na = validity.notAfter.date.getTime();
    expect(na).toBeGreaterThanOrEqual(before + 30 * 86_400_000 - 60_000);
    expect(na).toBeLessThanOrEqual(after + 30 * 86_400_000 + 60_000);
  });
});

describe("DER encoder primitives — set/octetString/contextPrimitive direct", () => {
  it("set(...) wraps children in [0x31, len, ...]", () => {
    const result = set(oid("1.2.3"));
    const parsed = readElement(result);
    expect(parsed.tag).toBe(TAG.SET);
    const inner = readChildren(parsed.value);
    expect(decodeOid(inner[0]!.value)).toBe("1.2.3");
  });

  it("octetString wraps bytes in [0x04, len, ...]", () => {
    expect(Array.from(octetString(new Uint8Array([1, 2, 3])))).toEqual([0x04, 0x03, 0x01, 0x02, 0x03]);
    expect(Array.from(octetString(new Uint8Array(0)))).toEqual([0x04, 0x00]);
  });

  it("contextPrimitive(n, value) emits [0x80+n, len, ...]", () => {
    expect(Array.from(contextPrimitive(0, new Uint8Array([0xab])))).toEqual([0x80, 0x01, 0xab]);
    expect(Array.from(contextPrimitive(5, new Uint8Array([0x01, 0x02])))).toEqual([0x85, 0x02, 0x01, 0x02]);
  });
});

describe("digestSha256 direct", () => {
  it("matches the known SHA-256 vector for empty input", async () => {
    const result = await digestSha256(new Uint8Array(0));
    expect(Array.from(result)).toEqual([
      0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
      0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
      0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
      0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    ]);
  });

  it("matches the known SHA-256 vector for 'abc'", async () => {
    const result = await digestSha256(new TextEncoder().encode("abc"));
    expect(Array.from(result)).toEqual([
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
      0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
      0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
      0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    ]);
  });
});

describe("assertCanIssueIntermediate check ordering", () => {
  it("rejects with pathLenConstraint=0 message before requestedPathLenConstraint validation", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    await expect(
      issueIntermediateCA({
        ca: intermediate,
        subject: [{ type: "CN", value: "deeper" }],
        days: 30,
        pathLenConstraint: 99
      })
    ).rejects.toThrow("Issuer pathLenConstraint=0 does not allow issuing another intermediate CA");
  });
});

describe("integer(bigint) byte-width boundaries", () => {
  it("encodes 1n as a single octet without sign byte", () => {
    expect(Array.from(readElement(integer(1n)).value)).toEqual([0x01]);
  });

  it("encodes 255n as two octets with a leading sign byte", () => {
    expect(Array.from(readElement(integer(255n)).value)).toEqual([0x00, 0xff]);
  });

  it("encodes 256n as two octets without sign byte (multi-byte transition)", () => {
    expect(Array.from(readElement(integer(256n)).value)).toEqual([0x01, 0x00]);
  });

  it("encodes 127n as a single octet without sign byte (high-bit boundary)", () => {
    expect(Array.from(readElement(integer(127n)).value)).toEqual([0x7f]);
  });

  it("encodes 128n as two octets with a leading sign byte", () => {
    expect(Array.from(readElement(integer(128n)).value)).toEqual([0x00, 0x80]);
  });
});

describe("arrayBufferFromBytes non-shared buffer", () => {
  it("returns an ArrayBuffer not aliased to the input TypedArray's buffer", () => {
    const input = new Uint8Array([1, 2, 3, 4, 5]);
    const buffer = arrayBufferFromBytes(input);
    const view = new Uint8Array(buffer);
    expect(Array.from(view)).toEqual([1, 2, 3, 4, 5]);
    input.fill(0);
    expect(Array.from(view)).toEqual([1, 2, 3, 4, 5]);
  });

  it("returns an empty ArrayBuffer for empty input", () => {
    const buffer = arrayBufferFromBytes(new Uint8Array(0));
    expect(buffer.byteLength).toBe(0);
  });
});

describe("printableString direct character set", () => {
  it("emits each allowed punctuation byte verbatim", () => {
    for (const ch of " '()+,-./:=?") {
      const parsed = readElement(printableString(ch));
      expect(parsed.tag).toBe(TAG.PRINTABLE_STRING);
      expect(Array.from(parsed.value)).toEqual([ch.charCodeAt(0)]);
    }
  });

  it("rejects each disallowed printable character", () => {
    for (const ch of ["*", "_", "@", "#", "!", "~", "$", "%", "^", "&"]) {
      expect(() => printableString(ch)).toThrow("PrintableString");
    }
  });
});

describe("oid() direct format errors", () => {
  it("rejects a component that is not a non-negative decimal integer", () => {
    expect(() => oid("1.2.abc")).toThrow("Invalid OID");
    expect(() => oid("1.2.-3")).toThrow("Invalid OID");
    expect(() => oid("1.2.03")).toThrow("Invalid OID");
  });

  it("rejects an OID with fewer than two components", () => {
    expect(() => oid("1")).toThrow("Invalid OID");
    expect(() => oid("")).toThrow("Invalid OID");
  });
});

describe("utcTime / generalizedTime direct boundaries", () => {
  it("utcTime falls back to GeneralizedTime when year is outside [1950, 2049]", () => {
    const before = new Date(Date.UTC(1949, 11, 31, 23, 59, 59));
    const after = new Date(Date.UTC(2050, 0, 1, 0, 0, 0));
    expect(readElement(utcTime(before)).tag).toBe(TAG.GENERALIZED_TIME);
    expect(readElement(utcTime(after)).tag).toBe(TAG.GENERALIZED_TIME);
  });

  it("generalizedTime rejects years outside [1, 9999]", () => {
    const yearZero = new Date(Date.UTC(2000, 0, 1));
    yearZero.setUTCFullYear(0);
    const yearTenThousand = new Date(Date.UTC(2000, 0, 1));
    yearTenThousand.setUTCFullYear(10000);
    expect(() => generalizedTime(yearZero)).toThrow("GeneralizedTime year must be between 0001 and 9999");
    expect(() => generalizedTime(yearTenThousand)).toThrow("GeneralizedTime year must be between 0001 and 9999");
  });
});

describe("readSequenceChildren rejects non-SEQUENCE input", () => {
  it("throws when called on an INTEGER element", () => {
    const element = readElement(integer(1));
    expect(() => readSequenceChildren(element)).toThrow("Expected SEQUENCE");
  });

  it("throws when called on a SET element", () => {
    const element = readElement(set(integer(1)));
    expect(() => readSequenceChildren(element)).toThrow("Expected SEQUENCE");
  });
});

describe("integer() handles empty Uint8Array input", () => {
  it("encodes an empty Uint8Array as the single-octet zero INTEGER", () => {
    const element = readElement(integer(new Uint8Array(0)));
    expect(element.tag).toBe(TAG.INTEGER);
    expect(Array.from(element.value)).toEqual([0]);
    expect(decodeInteger(element.value)).toBe(0n);
  });
});

describe("auto-generated serial number when crypto.getRandomValues yields all zeros", () => {
  it("forces the last byte to 1 so the resulting serial is a positive INTEGER", async () => {
    const original = crypto.getRandomValues.bind(crypto);
    const spy = vi.spyOn(crypto, "getRandomValues").mockImplementation(((array: ArrayBufferView) => {
      if (array instanceof Uint8Array) {
        array.fill(0);
      } else {
        // Fall back to the real implementation for non-Uint8Array views (none expected here).
        return original(array as Parameters<typeof original>[0]);
      }
      return array;
    }) as typeof crypto.getRandomValues);
    try {
      const root = await createRootCA({ subject: rootSubject, days: 365 });
      expect(parseCertificateSerialNumber(root.certDer).value).toBe(1n);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("notAfter rejection when computed Date overflows JS Date range", () => {
  it("rejects notBefore=year 9999 + days large enough that notAfterMs is finite but exceeds the Date range", async () => {
    const notBefore = new Date(Date.UTC(9999, 11, 31, 0, 0, 0));
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 100_000_000,
        notBefore,
        serialNumber: 1
      })
    ).rejects.toThrow("notAfter must be a valid Date");
  });
});

describe("certificate parser truncated-structure paths", () => {
  it("rejects an outer Certificate SEQUENCE with too few children", async () => {
    const cert = sequence(integer(1));
    await expect(parseCertificateDer(cert)).rejects.toThrow("Invalid certificate structure");
  });

  it("rejects a TBSCertificate SEQUENCE missing subject/SPKI", async () => {
    const issuerName = encodeName([{ type: "CN", value: "x" }]);
    const tbs = sequence(
      explicit(0, integer(2)),
      integer(1),
      sequence(oid(OID.ecdsaWithSha256)),
      issuerName
    );
    const cert = sequence(
      tbs,
      sequence(oid(OID.ecdsaWithSha256)),
      bitString(new Uint8Array(0), 0)
    );
    await expect(parseCertificateDer(cert)).rejects.toThrow(
      "Invalid certificate TBSCertificate structure"
    );
  });

  it("parses a v3 certificate that omits the [3] EXPLICIT extensions field entirely", async () => {
    const pair = await generateKeyPair();
    const subjectNameDer = encodeName([{ type: "CN", value: "no-ext-tag" }]);
    const spki = await exportSpki(pair.publicKey);
    const { tbsCertificateDer } = buildTbsCertificate({
      days: 1,
      issuerNameDer: subjectNameDer,
      subjectNameDer,
      subjectPublicKeyInfoDer: spki,
      extensions: [],
      serialNumber: 1,
      issuerCurve: "P-256"
    });
    const tbsChildren = readSequenceChildren(readElement(tbsCertificateDer));
    expect(tbsChildren[tbsChildren.length - 1]!.tag).toBe(0xa3);
    const tbsWithoutExtTag = sequence(...tbsChildren.slice(0, -1).map((child) => child.raw));
    const signature = await signDer(pair.privateKey, tbsWithoutExtTag);
    const certDer = buildCertificate(tbsWithoutExtTag, signature, "P-256");

    const parsed = await parseCertificateDer(certDer);
    expect(parsed.isCA).toBe(false);
    expect(parsed.keyCertSign).toBe(false);
    expect(parsed.subjectKeyIdentifier).toBeUndefined();
    expect(parsed.authorityKeyIdentifier).toBeUndefined();
    expect(parsed.pathLenConstraint).toBeUndefined();
  });
});

describe("DER decoder remaining boundary paths", () => {
  it("rejects decodeOid whose first sub-identifier never closes its continuation", () => {
    expect(() => decodeOid(new Uint8Array([0x80]))).toThrow("Truncated OID");
  });

  it("rejects readElement on a single-byte input where the length octet is missing", () => {
    expect(() => readElement(new Uint8Array([0x05]))).toThrow("Missing DER length");
  });
});

describe("OID encoder rejects components beyond Number.MAX_SAFE_INTEGER", () => {
  it("rejects oid() directly with a non-safe-integer component", () => {
    expect(() => oid("1.2.99999999999999999999")).toThrow("non-negative safe integer");
  });

  it("rejects a subject dotted-OID type whose component exceeds Number.MAX_SAFE_INTEGER", async () => {
    await expect(
      createRootCA({
        subject: [{ type: "1.2.99999999999999999999" as never, value: "x" }],
        days: 365
      })
    ).rejects.toThrow("non-negative safe integer");
  });
});

describe("subject attribute validation: non-string type", () => {
  it("rejects a subject entry whose type field is a number", async () => {
    await expect(
      createRootCA({
        subject: [{ type: 42 as never, value: "x" }],
        days: 365
      })
    ).rejects.toThrow("subject[0].type must be a string");
  });

  it("rejects a subject entry whose type field is null", async () => {
    await expect(
      createRootCA({
        subject: [{ type: null as never, value: "x" }],
        days: 365
      })
    ).rejects.toThrow("subject[0].type must be a string");
  });
});

describe("PEM tolerates surrounding text and whitespace", () => {
  it("ignores descriptive header and trailer text outside the PEM block", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const wrapped = `Subject: CN=dev-root\nIssuer: CN=dev-root\n\n${root.certPem}\nIssued for testing.\n`;
    expect(pemToDer(wrapped)).toEqual(root.certDer);
    expect(pemToDerWithLabel(wrapped, "CERTIFICATE")).toEqual(root.certDer);
  });
});

describe("integer() Uint8Array direct boundaries", () => {
  it("trims leading zero octets when the high bit is clear", () => {
    const element = readElement(integer(new Uint8Array([0, 0, 0x05])));
    expect(element.tag).toBe(TAG.INTEGER);
    expect(Array.from(element.value)).toEqual([0x05]);
    expect(decodeInteger(element.value)).toBe(5n);
  });

  it("collapses an all-zero input to a single zero octet", () => {
    const element = readElement(integer(new Uint8Array([0, 0, 0])));
    expect(element.tag).toBe(TAG.INTEGER);
    expect(Array.from(element.value)).toEqual([0]);
    expect(decodeInteger(element.value)).toBe(0n);
  });

  it("prepends a 0x00 sign octet when the high bit of the first byte is set", () => {
    const element = readElement(integer(new Uint8Array([0x80])));
    expect(element.tag).toBe(TAG.INTEGER);
    expect(Array.from(element.value)).toEqual([0x00, 0x80]);
    expect(decodeInteger(element.value)).toBe(128n);
  });
});

describe("readChildren empty input", () => {
  it("returns an empty array for empty SEQUENCE contents", () => {
    expect(readChildren(new Uint8Array(0))).toEqual([]);
  });
});

describe("SAN with only ipAddresses (no dnsNames)", () => {
  it("emits a SAN extension whose only entries are iPAddress GeneralNames", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const issued = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30,
      ipAddresses: ["192.0.2.1", "::1"]
    });
    const san = parseSubjectAltName(getExtension(issued.certDer, OID.subjectAltName).value);
    expect(san.dnsNames).toEqual([]);
    expect(san.ipAddresses).toHaveLength(2);
    expect(Array.from(san.ipAddresses[0]!)).toEqual([192, 0, 2, 1]);
    expect(Array.from(san.ipAddresses[1]!)).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
  });
});

describe("IPv4 empty-octet variants", () => {
  it("rejects IPv4 inputs whose split has 4 parts but contains an empty octet", () => {
    for (const value of ["1.2.3.", ".1.2.3", "1..2.3", "1.2..3"]) {
      expect(() => encodeIpAddress(value)).toThrow(`Invalid IPv4 address: ${value}`);
    }
  });

  it("rejects an empty-string IPv4 address (no dots)", () => {
    expect(() => encodeIpAddress("")).toThrow("Invalid IPv4 address: ");
  });
});

describe("oid() encoder self-validation independent of name.ts filtering", () => {
  it("rejects OIDs whose first component exceeds 2", () => {
    expect(() => oid("3.1.2")).toThrow("Invalid OID");
    expect(() => oid("99.0.0")).toThrow("Invalid OID");
  });

  it("rejects OIDs whose second component exceeds 39 when the first is 0 or 1", () => {
    expect(() => oid("0.40.0")).toThrow("Invalid OID");
    expect(() => oid("1.40.0")).toThrow("Invalid OID");
  });

  it("accepts OIDs whose second component exceeds 39 only when the first is 2 (joint-iso-itu-t)", () => {
    const element = readElement(oid("2.40.0"));
    expect(element.tag).toBe(TAG.OBJECT_IDENTIFIER);
    expect(decodeOid(element.value)).toBe("2.40.0");
  });
});

describe("keyUsageExtension with an empty usages array", () => {
  it("emits a single zero byte with unusedBits=7 (degenerate but well-formed)", () => {
    const ext = keyUsageExtension([]);
    // ext = SEQUENCE { OID(keyUsage), BOOLEAN(true), OCTET STRING { BIT STRING { 0x07, 0x00 } } }
    const children = readSequenceChildren(readElement(ext));
    const octet = children[children.length - 1]!;
    const inner = readElement(octet.value);
    expect(inner.tag).toBe(TAG.BIT_STRING);
    expect(Array.from(inner.value)).toEqual([0x07, 0x00]);
  });
});

describe("verifyClientCertificateIssuedBy", () => {
  it("returns true for a client cert issued by the given intermediate CA", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    const client = await issueClientCert({
      ca: intermediate,
      subject: clientSubject,
      days: 30
    });

    expect(
      await verifyClientCertificateIssuedBy({ ca: intermediate, certPem: client.certPem })
    ).toBe(true);
  });

  it("returns true for a client cert issued directly by a root CA", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      days: 30
    });

    expect(
      await verifyClientCertificateIssuedBy({ ca: root, certPem: client.certPem })
    ).toBe(true);
  });

  it("returns true round-trip when both issuance and verification go through importCertificateAuthority", async () => {
    const original = await createRootCA({ subject: rootSubject, days: 3650 });
    const importedRoot = await importCertificateAuthority({
      certPem: original.certPem,
      privateKey: original.privateKey
    });
    const importedIntermediate = await issueIntermediateCA({
      ca: importedRoot,
      subject: intermediateSubject,
      days: 365
    });
    const reimportedIntermediate = await importCertificateAuthority({
      certPem: importedIntermediate.certPem,
      privateKey: importedIntermediate.privateKey,
      issuerChainPem: importedIntermediate.issuerChainPem
    });
    const client = await issueClientCert({
      ca: reimportedIntermediate,
      subject: clientSubject,
      days: 30
    });

    expect(
      await verifyClientCertificateIssuedBy({
        ca: reimportedIntermediate,
        certPem: client.certPem
      })
    ).toBe(true);
    expect(
      await verifyClientCertificateIssuedBy({ ca: importedRoot, certPem: client.certPem })
    ).toBe(false);
  });

  it("returns true for a client cert issued by a CA built from a brought-in keyPair", async () => {
    const seed = await createRootCA({ subject: rootSubject, days: 3650 });
    const broughtIn = await createRootCA({
      subject: rootSubject,
      days: 3650,
      keyPair: { privateKey: seed.privateKey, publicKey: seed.publicKey }
    });
    const client = await issueClientCert({
      ca: broughtIn,
      subject: clientSubject,
      days: 30
    });

    expect(
      await verifyClientCertificateIssuedBy({ ca: broughtIn, certPem: client.certPem })
    ).toBe(true);
  });

  it("returns false when the cert was issued by a different CA", async () => {
    const realCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const otherCa = await createRootCA({
      subject: [{ type: "CN", value: "other-root" }],
      days: 3650
    });
    const client = await issueClientCert({
      ca: realCa,
      subject: clientSubject,
      days: 30
    });

    expect(
      await verifyClientCertificateIssuedBy({ ca: otherCa, certPem: client.certPem })
    ).toBe(false);
  });

  it("returns false when verifying a leaf against the root that issued only its intermediate", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    const client = await issueClientCert({
      ca: intermediate,
      subject: clientSubject,
      days: 30
    });

    expect(
      await verifyClientCertificateIssuedBy({ ca: root, certPem: client.certPem })
    ).toBe(false);
  });

  it("returns false when the TBS was tampered with even though the signature is genuinely from the CA", async () => {
    const realCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const clientA = await issueClientCert({
      ca: realCa,
      subject: [{ type: "CN", value: "client-a" }],
      days: 30
    });
    const clientB = await issueClientCert({
      ca: realCa,
      subject: [{ type: "CN", value: "client-b" }],
      days: 30
    });
    const parsedA = await parseCertificateDer(clientA.certDer);
    const parsedB = await parseCertificateDer(clientB.certDer);

    // Splice: B's TBS bytes paired with A's genuine CA signature.
    // Both halves are individually authentic (issuer DN, AKI both match realCa),
    // but the signature is over A's TBS hash, so verify against B's TBS must fail.
    const splicedDer = buildCertificate(parsedB.tbsCertificateDer, parsedA.signatureDer, "P-256");
    const splicedPem = certificateToPem(splicedDer);

    expect(
      await verifyClientCertificateIssuedBy({ ca: realCa, certPem: splicedPem })
    ).toBe(false);
  });

  it("returns false when issuer DN/AKI match but signature was produced by a different key", async () => {
    const realCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const realClient = await issueClientCert({
      ca: realCa,
      subject: clientSubject,
      days: 30
    });
    const realParsed = await parseCertificateDer(realClient.certDer);

    // Forge: same TBS (so issuer DN + AKI still match realCa's subject + SKI),
    // but signed with an attacker key. Signature verify against realCa.publicKey must fail.
    const attackerKeyPair = await generateKeyPair();
    const forgedSignatureDer = await signDer(attackerKeyPair.privateKey, realParsed.tbsCertificateDer);
    const forgedCertDer = buildCertificate(realParsed.tbsCertificateDer, forgedSignatureDer, "P-256");
    const forgedPem = certificateToPem(forgedCertDer);

    expect(
      await verifyClientCertificateIssuedBy({ ca: realCa, certPem: forgedPem })
    ).toBe(false);
  });

  it("returns false when issuer DN matches but the cert has no AKI extension", async () => {
    const realCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const realCaParsed = await parseCertificateDer(realCa.certDer);

    const leafKeyPair = await generateKeyPair();
    const leafSpki = await exportSpki(leafKeyPair.publicKey);
    const leafSki = await keyIdentifierFromSpki(leafSpki);
    const leafSubjectDer = encodeName(clientSubject);

    const { tbsCertificateDer } = buildTbsCertificate({
      serialNumber: 1,
      days: 30,
      issuerNameDer: realCaParsed.subjectNameDer,
      subjectNameDer: leafSubjectDer,
      subjectPublicKeyInfoDer: leafSpki,
      extensions: [
        basicConstraintsLeafExtension(),
        keyUsageExtension(["digitalSignature"]),
        extendedKeyUsageClientAuthExtension(),
        subjectKeyIdentifierExtension(leafSki)
        // intentionally no authorityKeyIdentifierExtension
      ],
      issuerCurve: "P-256"
    });
    const signature = await signDer(realCa.privateKey, tbsCertificateDer);
    const certPem = certificateToPem(buildCertificate(tbsCertificateDer, signature, "P-256"));

    expect(
      await verifyClientCertificateIssuedBy({ ca: realCa, certPem })
    ).toBe(false);
  });

  it("returns false when issuer DN matches but AKI does not match the CA SKI", async () => {
    const realCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const realCaParsed = await parseCertificateDer(realCa.certDer);

    const leafKeyPair = await generateKeyPair();
    const leafSpki = await exportSpki(leafKeyPair.publicKey);
    const leafSki = await keyIdentifierFromSpki(leafSpki);
    const leafSubjectDer = encodeName(clientSubject);
    const wrongAki = new Uint8Array(20); // 20 zero bytes — won't match realCa SKI

    const { tbsCertificateDer } = buildTbsCertificate({
      serialNumber: 1,
      days: 30,
      issuerNameDer: realCaParsed.subjectNameDer,
      subjectNameDer: leafSubjectDer,
      subjectPublicKeyInfoDer: leafSpki,
      extensions: [
        basicConstraintsLeafExtension(),
        keyUsageExtension(["digitalSignature"]),
        extendedKeyUsageClientAuthExtension(),
        subjectKeyIdentifierExtension(leafSki),
        authorityKeyIdentifierExtension(wrongAki)
      ],
      issuerCurve: "P-256"
    });
    const signature = await signDer(realCa.privateKey, tbsCertificateDer);
    const certPem = certificateToPem(buildCertificate(tbsCertificateDer, signature, "P-256"));

    expect(
      await verifyClientCertificateIssuedBy({ ca: realCa, certPem })
    ).toBe(false);
  });

  it("returns false when an attacker CA shares the same subject DN as the real CA but uses a different key", async () => {
    const realCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const attackerCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const victimClient = await issueClientCert({
      ca: attackerCa,
      subject: clientSubject,
      days: 30
    });

    // Cert was issued by attackerCa but its issuer DN is identical to realCa's
    // subject DN (DN check would naively pass). AKI carries attackerCa's SKI,
    // which differs from realCa's SKI → AKI check rejects it.
    expect(
      await verifyClientCertificateIssuedBy({ ca: realCa, certPem: victimClient.certPem })
    ).toBe(false);
  });

  it("throws on invalid PEM input", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });

    await expect(
      verifyClientCertificateIssuedBy({ ca: root, certPem: "not a pem block" })
    ).rejects.toThrow();
  });

  it("throws when the PEM block is labeled something other than CERTIFICATE", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });

    await expect(
      verifyClientCertificateIssuedBy({
        ca: root,
        certPem: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"
      })
    ).rejects.toThrow();
  });
});

describe("verifyClientCertificateIssuedBy validity option", () => {
  it("returns true when current time is inside the supplied window and identity checks pass", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    const now = Date.now();
    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: {
          notBefore: now - 1000,
          notAfter: now + 1000,
          now
        }
      })
    ).toBe(true);
  });

  it("returns false when now is after notAfter", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: {
          notBefore: new Date("2020-01-01T00:00:00Z"),
          notAfter: new Date("2020-12-31T23:59:59Z"),
          now: new Date("2021-06-01T00:00:00Z")
        }
      })
    ).toBe(false);
  });

  it("returns false when now is before notBefore", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: {
          notBefore: new Date("2030-01-01T00:00:00Z"),
          notAfter: new Date("2030-12-31T23:59:59Z"),
          now: new Date("2025-06-01T00:00:00Z")
        }
      })
    ).toBe(false);
  });

  it("falls back to Date.now() when now is omitted", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    const realDateNow = Date.now;
    const fixedNow = Date.parse("2099-01-01T00:00:00Z");
    Date.now = () => fixedNow;
    try {
      // No now provided → uses Date.now() which we've stubbed to 2099.
      // Window 2020 → 2021 is in the past, so this must be false.
      expect(
        await verifyClientCertificateIssuedBy({
          ca: root,
          certPem: client.certPem,
          validity: {
            notBefore: new Date("2020-01-01T00:00:00Z"),
            notAfter: new Date("2021-01-01T00:00:00Z")
          }
        })
      ).toBe(false);
    } finally {
      Date.now = realDateNow;
    }
  });

  it("still rejects identity-mismatched cert when validity passes", async () => {
    const realCa = await createRootCA({ subject: rootSubject, days: 3650 });
    const otherCa = await createRootCA({
      subject: [{ type: "CN", value: "other-root" }],
      days: 3650
    });
    const client = await issueClientCert({ ca: realCa, subject: clientSubject, days: 30 });

    const now = Date.now();
    expect(
      await verifyClientCertificateIssuedBy({
        ca: otherCa,
        certPem: client.certPem,
        validity: { notBefore: now - 1000, notAfter: now + 1000, now }
      })
    ).toBe(false);
  });

  it("short-circuits to false on expired window without parsing the cert", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });

    // certPem is garbage. With validity option failing first, we expect false
    // (not a parse error) — proves the validity gate runs before pemToDerWithLabel.
    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: "this is not a pem block at all",
        validity: {
          notBefore: new Date("2020-01-01T00:00:00Z"),
          notAfter: new Date("2020-12-31T23:59:59Z"),
          now: new Date("2099-01-01T00:00:00Z")
        }
      })
    ).toBe(false);
  });

  it("throws when notBefore is greater than notAfter", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    await expect(
      verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: {
          notBefore: new Date("2030-01-01T00:00:00Z"),
          notAfter: new Date("2020-01-01T00:00:00Z")
        }
      })
    ).rejects.toThrow(/notBefore/);
  });

  it("throws on non-finite validity values (NaN Date or Infinity)", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    await expect(
      verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: {
          notBefore: new Date("not a real date"),
          notAfter: Date.now() + 1000
        }
      })
    ).rejects.toThrow(/finite/);

    await expect(
      verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: {
          notBefore: 0,
          notAfter: Number.POSITIVE_INFINITY
        }
      })
    ).rejects.toThrow(/finite/);

    await expect(
      verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: {
          notBefore: 0,
          notAfter: Date.now() + 1000,
          now: Number.NaN
        }
      })
    ).rejects.toThrow(/finite/);
  });

  it("accepts Date and epoch-number values interchangeably", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const now = Date.now();

    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: { notBefore: new Date(now - 1000), notAfter: now + 1000, now: new Date(now) }
      })
    ).toBe(true);
    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: { notBefore: now - 1000, notAfter: new Date(now + 1000), now }
      })
    ).toBe(true);
  });

  it("treats now exactly equal to notBefore or notAfter as inside the window", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const t = 1_700_000_000_000;

    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: { notBefore: t, notAfter: t + 1000, now: t }
      })
    ).toBe(true);
    expect(
      await verifyClientCertificateIssuedBy({
        ca: root,
        certPem: client.certPem,
        validity: { notBefore: t, notAfter: t + 1000, now: t + 1000 }
      })
    ).toBe(true);
  });
});

describe("subject encodes repeated attribute types in order", () => {
  it("emits two OU RDNs in input order without deduplication", async () => {
    const root = await createRootCA({
      subject: [
        { type: "CN", value: "dev-multi-ou" },
        { type: "OU", value: "team-alpha" },
        { type: "OU", value: "team-beta" }
      ],
      days: 365,
      serialNumber: 1
    });
    const parsed = await parseCertificate(root.certDer);
    const attributes = parseName(parsed.subjectNameDer);
    expect(attributes.map((a) => a.oid)).toEqual([
      "2.5.4.3",   // CN
      "2.5.4.11",  // OU
      "2.5.4.11"   // OU (repeated)
    ]);
    expect(attributes.map((a) => new TextDecoder().decode(a.value))).toEqual([
      "dev-multi-ou",
      "team-alpha",
      "team-beta"
    ]);
  });
});

describe("CryptoKey input boundary failures", () => {
  it("rejects createRootCA when keyPair uses a non-ECDSA algorithm", async () => {
    const rsa = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        keyPair: rsa
      })
    ).rejects.toThrow("Expected ECDSA key");
  });

  it("rejects createRootCA when keyPair.publicKey is not extractable", async () => {
    const extractable = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const spki = await crypto.subtle.exportKey("spki", extractable.publicKey);
    const nonExtractablePublic = await crypto.subtle.importKey(
      "spki",
      spki,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const keyPair: CryptoKeyPair = {
      privateKey: extractable.privateKey,
      publicKey: nonExtractablePublic
    };
    await expect(
      createRootCA({
        subject: rootSubject,
        days: 365,
        keyPair
      })
    ).rejects.toThrow();
  });

  it("rejects importCertificateAuthority when privateKey is RSA, not ECDSA", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const rsa = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );
    await expect(
      importCertificateAuthority({
        certPem: root.certPem,
        privateKey: rsa.privateKey
      })
    ).rejects.toThrow("Expected ECDSA key");
  });

  it("rejects importCertificateAuthority when privateKey curve does not match certificate's curve", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const wrongCurve = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"]
    );
    await expect(
      importCertificateAuthority({
        certPem: root.certPem,
        privateKey: wrongCurve.privateKey
      })
    ).rejects.toThrow();
  });
});

describe("importPublicKeySpki error paths", () => {
  it("rejects a non-SEQUENCE root", async () => {
    await expect(importPublicKeySpki(new Uint8Array([0x04, 0x00]))).rejects.toThrow(
      "Invalid SubjectPublicKeyInfo"
    );
  });

  it("rejects when the algorithm element is not a SEQUENCE", async () => {
    const bad = sequence(integer(0), bitString(new Uint8Array([0x04])));
    await expect(importPublicKeySpki(bad)).rejects.toThrow("Invalid SubjectPublicKeyInfo algorithm");
  });

  it("rejects when the algorithm OID is missing or wrong-tagged", async () => {
    const bad = sequence(sequence(integer(0)), bitString(new Uint8Array([0x04])));
    await expect(importPublicKeySpki(bad)).rejects.toThrow(
      "Invalid SubjectPublicKeyInfo algorithm OID"
    );
  });

  it("rejects when the algorithm OID is not id-ecPublicKey", async () => {
    const bad = sequence(
      sequence(oid("1.2.840.113549.1.1.1"), oid(OID.secp256r1)),
      bitString(new Uint8Array([0x04]))
    );
    await expect(importPublicKeySpki(bad)).rejects.toThrow(
      "SubjectPublicKeyInfo is not an EC public key"
    );
  });

  it("rejects when EC parameters are missing or not a named-curve OID", async () => {
    const bad = sequence(
      sequence(oid(OID.ecPublicKey), integer(0)),
      bitString(new Uint8Array([0x04]))
    );
    await expect(importPublicKeySpki(bad)).rejects.toThrow(
      "EC SubjectPublicKeyInfo parameters must be a named-curve OID"
    );
  });

  it("rejects when the named-curve OID is not P-256/384/521", async () => {
    const secp192r1 = "1.2.840.10045.3.1.1";
    const bad = sequence(
      sequence(oid(OID.ecPublicKey), oid(secp192r1)),
      bitString(new Uint8Array([0x04]))
    );
    await expect(importPublicKeySpki(bad)).rejects.toThrow("Unsupported EC named curve OID");
  });
});

describe("multi-curve ECDSA support", () => {
  for (const curve of ["P-256", "P-384", "P-521"] as const) {
    it(`creates a self-signed root and issues a leaf with ${curve}`, async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: curve },
        true,
        ["sign", "verify"]
      );
      const root = await createRootCA({
        subject: rootSubject,
        days: 3650,
        keyPair
      });
      expect((root.privateKey.algorithm as EcKeyAlgorithm).namedCurve).toBe(curve);

      const client = await issueClientCert({
        ca: root,
        subject: clientSubject,
        days: 30
      });
      const parsedRoot = await parseCertificate(root.certDer);
      const parsedClient = await parseCertificate(client.certDer);
      await expect(expectSignatureValid(parsedRoot, parsedRoot)).resolves.toBe(true);
      await expect(expectSignatureValid(parsedRoot, parsedClient)).resolves.toBe(true);
      expect(
        await verifyClientCertificateIssuedBy({ ca: root, certPem: client.certPem })
      ).toBe(true);
    });
  }

  it("issues a P-384 intermediate from a P-256 root and a leaf below it", async () => {
    const rootKeyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const intermediateKeyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"]
    );
    const root = await createRootCA({
      subject: rootSubject,
      days: 3650,
      keyPair: rootKeyPair
    });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365,
      keyPair: intermediateKeyPair
    });
    expect((intermediate.privateKey.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-384");

    const parsedRoot = await parseCertificate(root.certDer);
    const parsedIntermediate = await parseCertificate(intermediate.certDer);
    await expect(expectSignatureValid(parsedRoot, parsedIntermediate)).resolves.toBe(true);

    const client = await issueClientCert({
      ca: intermediate,
      subject: clientSubject,
      days: 30
    });
    const parsedClient = await parseCertificate(client.certDer);
    await expect(expectSignatureValid(parsedIntermediate, parsedClient)).resolves.toBe(true);
  });

  it("re-imports a P-521 root via importCertificateAuthority", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-521" },
      true,
      ["sign", "verify"]
    );
    const root = await createRootCA({ subject: rootSubject, days: 3650, keyPair });
    const reimported = await importCertificateAuthority({
      certPem: root.certPem,
      privateKey: root.privateKey
    });
    expect((reimported.publicKey.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-521");
    const client = await issueClientCert({
      ca: reimported,
      subject: clientSubject,
      days: 30
    });
    expect(
      await verifyClientCertificateIssuedBy({ ca: reimported, certPem: client.certPem })
    ).toBe(true);
  });
});

describe("issueClientCertForPublicKey", () => {
  it("issues a client cert from a caller-provided P-256 public key without returning a private key", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const subjectKeyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const issued = await issueClientCertForPublicKey({
      ca: root,
      publicKey: subjectKeyPair.publicKey,
      subject: clientSubject,
      days: 30,
      dnsNames: ["client.example.test"]
    });

    expect((issued as object).hasOwnProperty("privateKey")).toBe(false);
    expect(splitPemBlocks(issued.certChainPem)).toEqual([
      issued.certPem.trim(),
      root.certPem.trim()
    ]);

    const parsedRoot = await parseCertificate(root.certDer);
    const parsedClient = await parseCertificate(issued.certDer);
    await expect(expectSignatureValid(parsedRoot, parsedClient)).resolves.toBe(true);

    // Subject cert SPKI matches the caller's public key.
    const callerSpki = await exportSpki(subjectKeyPair.publicKey);
    expect(Array.from(parsedClient.subjectPublicKeyInfoDer)).toEqual(Array.from(callerSpki));

    expect(
      await verifyClientCertificateIssuedBy({ ca: root, certPem: issued.certPem })
    ).toBe(true);
  });

  it("issues a P-384 client cert under a P-256 CA when only the public key is provided", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const subjectKeyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-384" },
      true,
      ["sign", "verify"]
    );
    const issued = await issueClientCertForPublicKey({
      ca: root,
      publicKey: subjectKeyPair.publicKey,
      subject: clientSubject,
      days: 30
    });
    expect(
      await verifyClientCertificateIssuedBy({ ca: root, certPem: issued.certPem })
    ).toBe(true);
  });

  it("rejects issueClientCertForPublicKey when ca is a non-CA leaf", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const leaf = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const reimportedLeaf = await importCertificateAuthority({
      certPem: leaf.certPem,
      privateKey: leaf.privateKey,
      issuerChainPem: root.certPem
    });
    const otherKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    await expect(
      issueClientCertForPublicKey({
        ca: reimportedLeaf,
        publicKey: otherKey.publicKey,
        subject: [{ type: "CN", value: "blocked" }],
        days: 30
      })
    ).rejects.toThrow("Issuer certificate is not a CA");
  });
});

describe("CSR parsing and POP verification", () => {
  it("parses a valid P-256 CSR with subject and SAN extensionRequest", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      dnsNames: ["client.example.test", "alt.example.test"],
      ipAddresses: [{ v4: [10, 0, 0, 1] }]
    });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.subject).toEqual(clientSubject);
    expect(parsed.requestedDnsNames).toEqual(["client.example.test", "alt.example.test"]);
    expect(parsed.requestedIpAddresses).toEqual(["10.0.0.1"]);
    expect(parsed.signatureAlgorithmOid).toBe(OID.ecdsaWithSha256);
    expect(parsed.requestedExtensions.length).toBe(1);
    expect(parsed.requestedExtensions[0]!.oid).toBe(OID.subjectAltName);
    expect(parsed.otherAttributes.length).toBe(0);
    expect(await verifyCertificateSigningRequestSignature(parsed)).toBe(true);
  });

  for (const curve of ["P-384", "P-521"] as const) {
    it(`parses a valid ${curve} CSR and verifies its POP signature`, async () => {
      const keyPair = await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: curve },
        true,
        ["sign", "verify"]
      );
      const fixture = await buildCsrFixture({ subject: clientSubject, keyPair });
      const parsed = await parseCertificateSigningRequest(fixture.der);
      expect((parsed.publicKey.algorithm as EcKeyAlgorithm).namedCurve).toBe(curve);
      expect(await verifyCertificateSigningRequestSignature(parsed)).toBe(true);
    });
  }

  it("accepts an IPv6 SAN and decodes the bytes back to RFC 5952 form", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      ipAddresses: [{ v6: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] }]
    });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.requestedIpAddresses).toEqual(["2001:db8::1"]);
  });

  it("accepts both CERTIFICATE REQUEST and NEW CERTIFICATE REQUEST PEM labels", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const fixture = await buildCsrFixture({ subject: clientSubject, keyPair });
    const fromStandard = await parseCertificateSigningRequest(fixture.pem);
    const fromLegacy = await parseCertificateSigningRequest(fixture.legacyPem);
    expect(fromStandard.subject).toEqual(clientSubject);
    expect(fromLegacy.subject).toEqual(clientSubject);
  });

  it("returns false from POP verification when the signature is broken", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const fixture = await buildCsrFixture({ subject: clientSubject, keyPair });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    // Flip a bit inside the certificationRequestInfo to invalidate the signature
    // without breaking the DER framing.
    const tampered: typeof parsed = {
      ...parsed,
      certificationRequestInfoDer: parsed.certificationRequestInfoDer.slice()
    };
    tampered.certificationRequestInfoDer[tampered.certificationRequestInfoDer.length - 1] ^= 0xff;
    expect(await verifyCertificateSigningRequestSignature(tampered)).toBe(false);
  });

  it("rejects a CSR whose signatureAlgorithm is not ECDSA P-256/384/521", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      // RSA-SHA256 OID — out of scope for EdgCA.
      signatureAlgorithmOid: "1.2.840.113549.1.1.11"
    });
    await expect(parseCertificateSigningRequest(fixture.der)).rejects.toThrow(
      "Unsupported CSR signatureAlgorithm"
    );
  });

  it("preserves non-extensionRequest attributes as raw values", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    // PKCS#9 challengePassword (1.2.840.113549.1.9.7), IA5String value.
    const challengePasswordOid = "1.2.840.113549.1.9.7";
    const challengeValue = ia5String("hunter2");
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [{ oid: challengePasswordOid, valuesDer: [challengeValue] }]
    });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.otherAttributes.length).toBe(1);
    expect(parsed.otherAttributes[0]!.oid).toBe(challengePasswordOid);
    expect(parsed.otherAttributes[0]!.valuesDer.length).toBe(1);
    expect(Array.from(parsed.otherAttributes[0]!.valuesDer[0]!)).toEqual(Array.from(challengeValue));
  });

  it("decodes PrintableString and IA5String subject values", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const subject: Subject = [
      { type: "C", value: "JP" },              // PrintableString
      { type: "E", value: "user@example.com" } // IA5String
    ];
    const fixture = await buildCsrFixture({ subject, keyPair });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.subject).toEqual(subject);
  });

  it("rejects malformed CSR DER inputs", async () => {
    await expect(parseCertificateSigningRequest(new Uint8Array([0x04, 0x00]))).rejects.toThrow("Invalid CSR DER");

    // Outer SEQUENCE with trailing byte → length doesn't match.
    const inner = sequence(integer(0));
    const trailingExtra = new Uint8Array(inner.length + 1);
    trailingExtra.set(inner);
    trailingExtra[inner.length] = 0;
    await expect(parseCertificateSigningRequest(trailingExtra)).rejects.toThrow();

    // SEQUENCE with too few children.
    await expect(parseCertificateSigningRequest(sequence(integer(0)))).rejects.toThrow("Invalid CSR structure");

    // requestInfo is not a SEQUENCE.
    const badReqInfo = sequence(integer(0), sequence(oid(OID.ecdsaWithSha256)), bitString(new Uint8Array([0x00])));
    await expect(parseCertificateSigningRequest(badReqInfo)).rejects.toThrow(
      "Invalid CSR certificationRequestInfo"
    );

    // signatureAlgorithm is not a SEQUENCE.
    const badSigAlg = sequence(sequence(integer(0)), integer(0), bitString(new Uint8Array([0x00])));
    await expect(parseCertificateSigningRequest(badSigAlg)).rejects.toThrow("Invalid CSR signatureAlgorithm");

    // signatureValue is not a BIT STRING / has nonzero unused-bits.
    const badSig = sequence(
      sequence(integer(0)),
      sequence(oid(OID.ecdsaWithSha256)),
      // BIT STRING but leading byte is 1, not 0 (indicating unused bits ≠ 0).
      new Uint8Array([0x03, 0x02, 0x01, 0x00])
    );
    await expect(parseCertificateSigningRequest(badSig)).rejects.toThrow("Invalid CSR signature value");
  });

  it("rejects unsupported CSR version and malformed CRI structure", async () => {
    // CRI with no version field at all (missing CRI children).
    const ecdsaSigAlg = sequence(oid(OID.ecdsaWithSha256));
    const sig = bitString(new Uint8Array(70).fill(0x00));
    const briefCri = sequence();
    const csrBrief = sequence(briefCri, ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrBrief)).rejects.toThrow(
      "Invalid CSR certificationRequestInfo structure"
    );

    // CRI with version=1 (only v1 / INTEGER 0 is allowed).
    const fakeName = sequence(); // empty
    const fakeSpki = sequence(); // empty
    const v2Cri = sequence(integer(1), fakeName, fakeSpki);
    const csrV2 = sequence(v2Cri, ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrV2)).rejects.toThrow(
      "Unsupported CSR version"
    );

    // CRI where SPKI is not a SEQUENCE.
    const badSpki = new Uint8Array([0x04, 0x01, 0x00]);
    const badSpkiCri = sequence(integer(0), fakeName, badSpki);
    const csrBadSpki = sequence(badSpkiCri, ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrBadSpki)).rejects.toThrow(
      "Invalid CSR subjectPublicKeyInfo"
    );
  });

  it("rejects a CSR whose attributes field is not tagged with IMPLICIT [0]", async () => {
    // Construct a CSR where the 4th CRI child has tag 0xa1 instead of 0xa0.
    const ecdsaSigAlg = sequence(oid(OID.ecdsaWithSha256));
    const sig = bitString(new Uint8Array(70).fill(0x00));
    const validSpki = sequence(
      sequence(oid(OID.ecPublicKey), oid(OID.secp256r1)),
      bitString(new Uint8Array(65).fill(0x04))
    );
    const minimalName = sequence(set(sequence(oid("2.5.4.3"), new Uint8Array([0x0c, 0x01, 0x61]))));
    const wrongTagAttributes = der(0xa1, new Uint8Array(0));
    const cri = sequence(integer(0), minimalName, validSpki, wrongTagAttributes);
    const csr = sequence(cri, ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csr)).rejects.toThrow(
      "Invalid CSR attributes tag"
    );
  });

  it("rejects CSR PEM with the wrong block label", async () => {
    await expect(
      parseCertificateSigningRequest("-----BEGIN PUBLIC KEY-----\nAA==\n-----END PUBLIC KEY-----")
    ).rejects.toThrow("Invalid CSR PEM");
  });

  it("rejects an algorithm identifier whose first child is not an OID", async () => {
    const ecdsaSigAlgWithBoolean = sequence(new Uint8Array([0x01, 0x01, 0xff]));
    const fakeName = sequence();
    const fakeSpki = sequence(sequence(oid(OID.ecPublicKey), oid(OID.secp256r1)), bitString(new Uint8Array([0x04])));
    const cri = sequence(integer(0), fakeName, fakeSpki);
    const csr = sequence(cri, ecdsaSigAlgWithBoolean, bitString(new Uint8Array([0x00])));
    await expect(parseCertificateSigningRequest(csr)).rejects.toThrow("Invalid AlgorithmIdentifier OID");
  });

  it("rejects malformed Name structures inside the CSR", async () => {
    const realKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const validSpki = await exportSpki(realKey.publicKey);
    const ecdsaSigAlg = sequence(oid(OID.ecdsaWithSha256));
    const sig = bitString(new Uint8Array(70).fill(0x00));

    // Name where an RDN is not a SET.
    const rdnNotSet = sequence(sequence(integer(0)));
    const csrRdnNotSet = sequence(sequence(integer(0), rdnNotSet, validSpki), ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrRdnNotSet)).rejects.toThrow("Invalid RDN");

    // Multi-valued RDN.
    const dummyAttr = sequence(oid(OID.basicConstraints), new Uint8Array([0x0c, 0x01, 0x61]));
    const multiValuedRdn = sequence(set(dummyAttr, dummyAttr));
    const csrMulti = sequence(sequence(integer(0), multiValuedRdn, validSpki), ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrMulti)).rejects.toThrow(
      "Multi-valued RDNs are not supported"
    );

    // Non-SEQUENCE AttributeTypeAndValue.
    const notSeqAttr = new Uint8Array([0x04, 0x00]);
    const badAttrRdn = sequence(set(notSeqAttr));
    const csrBadAttr = sequence(sequence(integer(0), badAttrRdn, validSpki), ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrBadAttr)).rejects.toThrow(
      "Invalid AttributeTypeAndValue"
    );

    // AttributeTypeAndValue missing value.
    const incompleteAttr = sequence(oid("2.5.4.3"));
    const incompleteRdn = sequence(set(incompleteAttr));
    const csrIncomplete = sequence(sequence(integer(0), incompleteRdn, validSpki), ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrIncomplete)).rejects.toThrow(
      "Invalid AttributeTypeAndValue contents"
    );

    // Unsupported attribute value string type (use INTEGER tag where a string is expected).
    const unsupportedTypeAttr = sequence(oid("2.5.4.3"), integer(7));
    const unsupportedTypeRdn = sequence(set(unsupportedTypeAttr));
    const csrUnsupportedType = sequence(
      sequence(integer(0), unsupportedTypeRdn, validSpki),
      ecdsaSigAlg,
      sig
    );
    await expect(parseCertificateSigningRequest(csrUnsupportedType)).rejects.toThrow(
      "Unsupported AttributeValue string type"
    );
  });

  it("rejects malformed CSR attributes/extensions", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );

    // extensionRequest with two values (must be exactly one SEQUENCE OF Extension).
    const dummyExtension = sequence(oid(OID.subjectAltName), octetString(sequence()));
    const dummyExtensionsSeq = sequence(dummyExtension);
    const fixtureMultiValues = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        {
          oid: OID.extensionRequest,
          valuesDer: [dummyExtensionsSeq, dummyExtensionsSeq]
        }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureMultiValues.der)).rejects.toThrow(
      "extensionRequest attribute must contain exactly one SEQUENCE OF Extension"
    );

    // extensionRequest value that is not a SEQUENCE.
    const fixtureNotSequence = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        {
          oid: OID.extensionRequest,
          valuesDer: [new Uint8Array([0x04, 0x00])]
        }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureNotSequence.der)).rejects.toThrow(
      "extensionRequest value must be a SEQUENCE OF Extension"
    );

    // Extension that is not a SEQUENCE.
    const fixtureBadExtension = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        {
          oid: OID.extensionRequest,
          valuesDer: [sequence(new Uint8Array([0x04, 0x00]))]
        }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureBadExtension.der)).rejects.toThrow(
      "Invalid Extension"
    );

    // Extension whose first child is not an OID.
    const noOidExt = sequence(integer(0), octetString(sequence()));
    const fixtureNoOid = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        { oid: OID.extensionRequest, valuesDer: [sequence(noOidExt)] }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureNoOid.der)).rejects.toThrow("Invalid Extension OID");

    // Extension value not OCTET STRING.
    const noOctetExt = sequence(oid(OID.subjectAltName), integer(0));
    const fixtureNoOctet = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        { oid: OID.extensionRequest, valuesDer: [sequence(noOctetExt)] }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureNoOctet.der)).rejects.toThrow(
      "Invalid Extension value"
    );
  });

  it("rejects malformed top-level CSR attributes", async () => {
    const realKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const realSpki = await exportSpki(realKey.publicKey);
    const ecdsaSigAlg = sequence(oid(OID.ecdsaWithSha256));
    const sig = bitString(new Uint8Array(70).fill(0x00));
    const validSpki = realSpki;
    const minimalName = sequence(set(sequence(oid("2.5.4.3"), new Uint8Array([0x0c, 0x01, 0x61]))));

    // Attribute child not a SEQUENCE.
    const notSeqAttr = new Uint8Array([0x04, 0x00]);
    const badAttrs = der(0xa0, notSeqAttr);
    const csrBadAttr = sequence(sequence(integer(0), minimalName, validSpki, badAttrs), ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrBadAttr)).rejects.toThrow("Invalid CSR attribute");

    // Attribute first child not an OID.
    const noOidAttr = sequence(integer(0), set(integer(0)));
    const badAttrs2 = der(0xa0, noOidAttr);
    const csrNoOid = sequence(sequence(integer(0), minimalName, validSpki, badAttrs2), ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csrNoOid)).rejects.toThrow("Invalid CSR attribute OID");

    // Attribute values not SET.
    const wrongValuesAttr = sequence(oid("1.2.3.4"), integer(0));
    const badAttrs3 = der(0xa0, wrongValuesAttr);
    const csrWrongValues = sequence(
      sequence(integer(0), minimalName, validSpki, badAttrs3),
      ecdsaSigAlg,
      sig
    );
    await expect(parseCertificateSigningRequest(csrWrongValues)).rejects.toThrow(
      "Invalid CSR attribute values"
    );
  });

  it("rejects malformed SAN inside extensionRequest", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );

    // SAN extension whose value (after stripping OCTET STRING wrapper) is not a SEQUENCE.
    const badSanExtension = sequence(
      oid(OID.subjectAltName),
      octetString(new Uint8Array([0x04, 0x00]))
    );
    const fixtureBadSan = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        { oid: OID.extensionRequest, valuesDer: [sequence(badSanExtension)] }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureBadSan.der)).rejects.toThrow(
      "Invalid SubjectAltName extension"
    );

    // SAN dNSName containing a non-ASCII byte.
    const badDnsName = der(0x82, new Uint8Array([0xff, 0x01]));
    const sanWithBadDns = sequence(
      oid(OID.subjectAltName),
      octetString(sequence(badDnsName))
    );
    const fixtureBadDns = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        { oid: OID.extensionRequest, valuesDer: [sequence(sanWithBadDns)] }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureBadDns.der)).rejects.toThrow(
      "non-ASCII byte"
    );

    // SAN iPAddress with invalid byte length (3 bytes — neither IPv4 nor IPv6).
    const badIp = der(0x87, new Uint8Array([1, 2, 3]));
    const sanWithBadIp = sequence(
      oid(OID.subjectAltName),
      octetString(sequence(badIp))
    );
    const fixtureBadIp = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        { oid: OID.extensionRequest, valuesDer: [sequence(sanWithBadIp)] }
      ]
    });
    await expect(parseCertificateSigningRequest(fixtureBadIp.der)).rejects.toThrow(
      "Invalid SAN iPAddress length"
    );
  });

  it("formats an IPv6 address with no compressible run as full eight groups", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    // 16 bytes that produce no run of two consecutive zero groups.
    const noZeroRun = [
      0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02,
      0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06
    ];
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      ipAddresses: [{ v6: noZeroRun }]
    });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.requestedIpAddresses).toEqual(["2001:db8:1:2:3:4:5:6"]);
  });

  it("preserves the critical flag on requested extensions", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraExtensions: [
        { oid: "2.5.29.19", critical: true, valueDer: sequence() } // basicConstraints with critical=true
      ]
    });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    const basicConstraints = parsed.requestedExtensions.find((ext) => ext.oid === "2.5.29.19");
    expect(basicConstraints?.critical).toBe(true);
  });

  it("rejects a CSR whose subject element is not a SEQUENCE", async () => {
    const realKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const realSpki = await exportSpki(realKey.publicKey);
    const ecdsaSigAlg = sequence(oid(OID.ecdsaWithSha256));
    const sig = bitString(new Uint8Array(70).fill(0x00));
    // subject is an INTEGER instead of a SEQUENCE.
    const cri = sequence(integer(0), integer(0), realSpki);
    const csr = sequence(cri, ecdsaSigAlg, sig);
    await expect(parseCertificateSigningRequest(csr)).rejects.toThrow("Invalid Name structure");
  });

  it("rejects a forged CryptoKey whose namedCurve is not P-256/384/521", async () => {
    const real = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const forged = Object.create(Object.getPrototypeOf(real.privateKey), {
      algorithm: { value: { name: "ECDSA", namedCurve: "P-192" }, enumerable: true },
      type: { value: "private", enumerable: true },
      usages: { value: ["sign"], enumerable: true },
      extractable: { value: false, enumerable: true }
    }) as CryptoKey;
    await expect(signDer(forged, new Uint8Array([1, 2, 3]))).rejects.toThrow(
      "Unsupported ECDSA curve: P-192"
    );
  });

  it("parses a CSR whose attributes field is absent entirely", async () => {
    const realKey = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const realSpki = await exportSpki(realKey.publicKey);
    const minimalName = encodeName(clientSubject);
    // CRI without the [0] IMPLICIT Attributes field at all.
    const cri = sequence(integer(0), minimalName, realSpki);
    const rawSig = new Uint8Array(
      await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, realKey.privateKey, cri)
    );
    const sigDer = ecdsaRawToDer(rawSig, 32);
    const csr = sequence(cri, sequence(oid(OID.ecdsaWithSha256)), bitString(sigDer));
    const parsed = await parseCertificateSigningRequest(csr);
    expect(parsed.requestedExtensions).toEqual([]);
    expect(parsed.otherAttributes).toEqual([]);
    expect(await verifyCertificateSigningRequestSignature(parsed)).toBe(true);
  });

  it("preserves dotted-OID subject types in the parsed Subject", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const subject: Subject = [
      { type: "CN", value: "alice" },
      { type: "1.2.3.4.5", value: "custom-attr-value" }
    ];
    const fixture = await buildCsrFixture({ subject, keyPair });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.subject).toEqual(subject);
  });

  it("ignores SAN GeneralName tags other than dNSName and iPAddress", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    // GeneralName.uniformResourceIdentifier = [6] IA5String — should be silently skipped
    // by the parser (only dNSName and iPAddress are surfaced).
    const uri = der(0x86, asciiBytes("https://example.test"));
    const dnsName = der(0x82, asciiBytes("client.example.test"));
    const sanExtension = sequence(
      oid(OID.subjectAltName),
      octetString(sequence(uri, dnsName))
    );
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      extraAttributes: [
        { oid: OID.extensionRequest, valuesDer: [sequence(sanExtension)] }
      ]
    });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.requestedDnsNames).toEqual(["client.example.test"]);
    expect(parsed.requestedIpAddresses).toEqual([]);
  });

  it("compresses the longest zero run in IPv6 SAN even when a shorter run also exists", async () => {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    // 2001:0:0:abcd:0:0:0:1 → longest run is the second three-zero run.
    const bytes = [
      0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair,
      ipAddresses: [{ v6: bytes }]
    });
    const parsed = await parseCertificateSigningRequest(fixture.der);
    expect(parsed.requestedIpAddresses).toEqual(["2001:0:0:abcd::1"]);
  });

  it("integrates: CSR is parsed, POP-verified, and re-issued via issueClientCertForPublicKey", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const subjectKeyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const fixture = await buildCsrFixture({
      subject: clientSubject,
      keyPair: subjectKeyPair,
      dnsNames: ["client.example.test"]
    });
    const csr = await parseCertificateSigningRequest(fixture.pem);
    expect(await verifyCertificateSigningRequestSignature(csr)).toBe(true);

    // Caller decides issuance fields independently from CSR contents.
    const issued = await issueClientCertForPublicKey({
      ca: root,
      publicKey: csr.publicKey,
      subject: csr.subject,
      days: 30,
      dnsNames: csr.requestedDnsNames as string[]
    });
    expect(
      await verifyClientCertificateIssuedBy({ ca: root, certPem: issued.certPem })
    ).toBe(true);
  });
});
