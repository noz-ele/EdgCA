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
import { ecdsaDerToRaw, ecdsaRawToDer } from "../src/crypto.js";
import { decodeOid, readElement, readSequenceChildren, TAG } from "../src/der.js";
import { encodeIpAddress } from "../src/ip.js";
import { OID } from "../src/oids.js";
import { pemToDerWithLabel, splitPemBlocks } from "../src/pem.js";
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
  parseSubjectKeyIdentifier
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
    await expect(digestSha256(parsedRoot.subjectPublicKeyInfoDer)).resolves.toEqual(rootSki);
    await expect(digestSha256(parsedIntermediate.subjectPublicKeyInfoDer)).resolves.toEqual(intermediateSki);
    await expect(digestSha256(parsedClient.subjectPublicKeyInfoDer)).resolves.toEqual(clientSki);

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

  it("keeps CA metadata usable if returned certDer bytes are mutated", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });

    root.certDer.fill(0);
    intermediate.certDer.fill(0);

    const nextIntermediate = await issueIntermediateCA({
      ca: root,
      subject: [{ type: "CN", value: "next-intermediate" }],
      days: 365
    });
    const client = await issueClientCert({
      ca: intermediate,
      subject: clientSubject,
      days: 30
    });

    expect(nextIntermediate.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
    expect(client.certPem.startsWith("-----BEGIN CERTIFICATE-----")).toBe(true);
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

  it("rejects invalid dotted OID subject attribute types", async () => {
    for (const type of ["abc", "3.2.1", "1", "1..2", "1.40.0"]) {
      await expect(
        createRootCA({
          subject: [{ type: type as never, value: "custom" }],
          days: 365
        })
      ).rejects.toThrow();
    }
  });

  it("rejects invalid days values", async () => {
    for (const days of [0, -1, Number.NaN]) {
      await expect(
        createRootCA({
          subject: rootSubject,
          days
        })
      ).rejects.toThrow("days must be a positive number");
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
});

describe("serial numbers and validity", () => {
  it("encodes explicit serial number variants", async () => {
    const cases: Array<{ serialNumber: SerialNumber; expectedValue: bigint; expectedBytes?: number[] }> = [
      { serialNumber: 12345n, expectedValue: 12345n },
      { serialNumber: 12345, expectedValue: 12345n },
      { serialNumber: "12345", expectedValue: 12345n },
      { serialNumber: "0f", expectedValue: 15n, expectedBytes: [0x0f] },
      { serialNumber: 0n, expectedValue: 0n, expectedBytes: [0] },
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

  it("generates a non-zero random serial number within the 20-octet limit", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 365 });
    const serialNumber = parseCertificateSerialNumber(root.certDer);

    expect(serialNumber.bytes.length).toBeGreaterThan(0);
    expect(serialNumber.bytes.length).toBeLessThanOrEqual(20);
    expect(serialNumber.value > 0n).toBe(true);
    expect((serialNumber.bytes[0]! & 0x80) === 0).toBe(true);
  });

  it("encodes explicit validity bounds from notBefore and days", async () => {
    const notBefore = new Date(Date.UTC(2026, 0, 2, 3, 4, 5));
    const root = await createRootCA({
      subject: rootSubject,
      days: 30,
      notBefore,
      serialNumber: 1
    });
    const validity = parseCertificateValidity(root.certDer);

    expect(validity.notBefore.date.getTime()).toBe(notBefore.getTime());
    expect(validity.notAfter.date.getTime()).toBe(notBefore.getTime() + 30 * 86_400_000);
    expect(validity.notBefore.tag).toBe(TAG.UTC_TIME);
    expect(validity.notAfter.tag).toBe(TAG.UTC_TIME);
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

async function digestSha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
