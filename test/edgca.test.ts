import { describe, expect, it } from "vitest";
import {
  certificateToPem,
  createRootCA,
  importCertificateAuthority,
  issueClientCert,
  issueIntermediateCA,
  pemToDer
} from "../src/index.js";
import { ecdsaDerToRaw, ecdsaRawToDer } from "../src/crypto.js";
import { decodeOid, readElement, readSequenceChildren, TAG } from "../src/der.js";
import { OID } from "../src/oids.js";
import { splitPemBlocks } from "../src/pem.js";
import type { Subject } from "../src/types.js";
import {
  expectSignatureValid,
  namesEqual,
  parseCertificate,
  parseExtensionsFromCertificate,
  parseName
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

    expect(parsedRoot.isCA).toBe(true);
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

    const clientExtensions = parseExtensionsFromCertificate(client.certDer);
    expect(clientExtensions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ oid: OID.basicConstraints, critical: true }),
        expect.objectContaining({ oid: OID.keyUsage, critical: true }),
        expect.objectContaining({ oid: OID.extendedKeyUsage, critical: false }),
        expect.objectContaining({ oid: OID.subjectAltName, critical: false })
      ])
    );
  });

  it("round-trips certificate PEM and imported CA issuerChainPem", async () => {
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
    expect(splitPemBlocks(client.certChainPem)).toEqual([
      client.certPem.trim(),
      intermediate.certPem.trim(),
      root.certPem.trim()
    ]);
  });

  it("rejects issuing another intermediate below a pathLenConstraint=0 intermediate", async () => {
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
