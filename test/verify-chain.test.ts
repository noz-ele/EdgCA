import { describe, expect, it } from "vitest";
import {
  certificateToPem,
  createRootCA,
  issueClientCert,
  issueClientCertForPublicKey,
  issueDocumentSigningCert,
  issueIntermediateCA,
  verifyCertificateChain,
  verifyCertificateIssuedBy
} from "../src/index.js";
import { asciiBytes } from "../src/bytes.js";
import {
  boolean,
  der,
  octetString,
  oid,
  readElement,
  readSequenceChildren,
  sequence
} from "../src/der.js";
import {
  curveOf,
  exportSpki,
  generateKeyPair,
  keyIdentifierFromSpki,
  signDer,
  type SupportedCurve
} from "../src/crypto.js";
import { encodeName } from "../src/name.js";
import { parseCertificateDer } from "../src/parser.js";
import type { CertificateAuthority, Subject } from "../src/types.js";
import {
  authorityKeyIdentifierExtension,
  basicConstraintsCaExtension,
  basicConstraintsLeafExtension,
  buildCertificate,
  buildTbsCertificate,
  extendedKeyUsageClientAuthExtension,
  keyUsageExtension,
  subjectKeyIdentifierExtension
} from "../src/x509.js";

const rootSubject: Subject = [{ type: "CN", value: "verify-root" }];
const intermediateSubject: Subject = [{ type: "CN", value: "verify-intermediate" }];
const clientSubject: Subject = [{ type: "CN", value: "verify-client" }];

describe("bounded certificate verification", () => {
  it("verifies a direct issuer using public certificates only", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const unrelated = await createRootCA({
      subject: [{ type: "CN", value: "unrelated-root" }],
      days: 3650
    });

    await expect(verifyCertificateIssuedBy({
      certificatePem: client.certPem,
      issuerCertificatePem: root.certPem
    })).resolves.toBe(true);
    await expect(verifyCertificateIssuedBy({
      certificatePem: client.certPem,
      issuerCertificatePem: unrelated.certPem
    })).resolves.toBe(false);
  });

  it("verifies root-direct and root-intermediate-client chains", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const directClient = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    const chainedClient = await issueClientCert({
      ca: intermediate,
      subject: clientSubject,
      days: 30
    });

    await expect(verifyCertificateChain({
      certificatePem: directClient.certPem,
      trustedRootCertificatesPem: [root.certPem],
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });

    await expect(verifyCertificateChain({
      certificatePem: chainedClient.certPem,
      intermediateCertificatesPem: [intermediate.certPem],
      trustedRootCertificatesPem: [root.certPem],
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });
  });

  it("selects the matching explicitly trusted root", async () => {
    const unrelated = await createRootCA({
      subject: [{ type: "CN", value: "first-unrelated-root" }],
      days: 3650
    });
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      trustedRootCertificatesPem: [unrelated.certPem, root.certPem],
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 1 });
  });

  it("supports mixed P-256, P-384, and P-521 curves across the chain", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365,
      keyPair: await generateKeyPair("P-384")
    });
    const leafKeyPair = await generateKeyPair("P-521");
    const client = await issueClientCertForPublicKey({
      ca: intermediate,
      publicKey: leafKeyPair.publicKey,
      subject: clientSubject,
      days: 30
    });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      intermediateCertificatesPem: [intermediate.certPem],
      trustedRootCertificatesPem: [root.certPem],
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });
  });

  it("checks clientAuth, documentSigning, and CA target profiles", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    const client = await issueClientCert({ ca: intermediate, subject: clientSubject, days: 30 });
    const signer = await issueDocumentSigningCert({
      ca: intermediate,
      subject: [{ type: "CN", value: "document-signer" }],
      days: 30
    });

    await expect(verifyCertificateChain({
      certificatePem: intermediate.certPem,
      trustedRootCertificatesPem: [root.certPem],
      purpose: "ca"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });

    await expect(verifyCertificateChain({
      certificatePem: signer.certPem,
      intermediateCertificatesPem: [intermediate.certPem],
      trustedRootCertificatesPem: [root.certPem],
      purpose: "documentSigning"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      intermediateCertificatesPem: [intermediate.certPem],
      trustedRootCertificatesPem: [root.certPem],
      purpose: "documentSigning"
    })).resolves.toEqual({
      valid: false,
      reason: "target-profile-invalid",
      certificateIndex: 0
    });
  });

  it("reads validity from DER and reports the target certificate index", async () => {
    const notBefore = new Date("2020-01-01T00:00:00Z");
    const root = await createRootCA({ subject: rootSubject, notBefore, days: 1000 });
    const client = await issueClientCert({
      ca: root,
      subject: clientSubject,
      notBefore,
      days: 10
    });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      trustedRootCertificatesPem: [root.certPem],
      at: notBefore,
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      trustedRootCertificatesPem: [root.certPem],
      at: new Date("2020-02-01T00:00:00Z"),
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: false, reason: "expired", certificateIndex: 0 });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      trustedRootCertificatesPem: [root.certPem],
      at: new Date("2019-12-31T23:59:59Z"),
      purpose: "clientAuth"
    })).resolves.toEqual({ valid: false, reason: "not-yet-valid", certificateIndex: 0 });
  });

  it("parses UTCTime and GeneralizedTime validity encodings", async () => {
    for (const notBefore of [
      new Date("2049-01-01T00:00:00Z"),
      new Date("2050-01-01T00:00:00Z")
    ]) {
      const root = await createRootCA({ subject: rootSubject, notBefore, days: 3650 });
      const client = await issueClientCert({
        ca: root,
        subject: clientSubject,
        notBefore,
        days: 30
      });
      await expect(verifyCertificateChain({
        certificatePem: client.certPem,
        trustedRootCertificatesPem: [root.certPem],
        at: notBefore,
        purpose: "clientAuth"
      })).resolves.toEqual({ valid: true, trustedRootIndex: 0 });
    }
  });

  it("throws for a malformed DER certificate time", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const malformed = replaceNotBefore(client.certDer, "991332000000Z");

    await expect(verifyCertificateChain({
      certificatePem: certificateToPem(malformed),
      trustedRootCertificatesPem: [root.certPem]
    })).rejects.toThrow("time");
  });

  it("rejects an untrusted root and an incorrectly ordered chain", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const intermediate = await issueIntermediateCA({
      ca: root,
      subject: intermediateSubject,
      days: 365
    });
    const client = await issueClientCert({ ca: intermediate, subject: clientSubject, days: 30 });
    const unrelated = await createRootCA({
      subject: [{ type: "CN", value: "untrusted" }],
      days: 3650
    });
    const wrongIntermediate = await issueIntermediateCA({
      ca: unrelated,
      subject: [{ type: "CN", value: "wrong-intermediate" }],
      days: 365
    });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      intermediateCertificatesPem: [intermediate.certPem],
      trustedRootCertificatesPem: [unrelated.certPem]
    })).resolves.toEqual({ valid: false, reason: "untrusted-root", certificateIndex: 2 });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      intermediateCertificatesPem: [wrongIntermediate.certPem],
      trustedRootCertificatesPem: [root.certPem]
    })).resolves.toEqual({ valid: false, reason: "issuer-name-mismatch", certificateIndex: 0 });
  });

  it("rejects a trusted root supplied redundantly as an intermediate", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      intermediateCertificatesPem: [root.certPem],
      trustedRootCertificatesPem: [root.certPem]
    })).resolves.toEqual({ valid: false, reason: "invalid-chain-order", certificateIndex: 1 });
  });

  it("enforces pathLenConstraint against a supplied intermediate", async () => {
    const root = await createRootCA({
      subject: rootSubject,
      days: 3650,
      pathLenConstraint: 0
    });
    const customIntermediate = await buildCustomCertificate({
      issuer: root,
      subject: intermediateSubject,
      isCA: true
    });
    const intermediate: CertificateAuthority = {
      certPem: customIntermediate.certPem,
      certDer: customIntermediate.certDer,
      privateKey: customIntermediate.keyPair.privateKey,
      publicKey: customIntermediate.keyPair.publicKey,
      issuerChainPem: root.certPem
    };
    const client = await issueClientCert({ ca: intermediate, subject: clientSubject, days: 30 });

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      intermediateCertificatesPem: [intermediate.certPem],
      trustedRootCertificatesPem: [root.certPem],
      purpose: "clientAuth"
    })).resolves.toEqual({
      valid: false,
      reason: "path-length-exceeded",
      certificateIndex: 2
    });
  });

  it("reports duplicate and unsupported critical extensions", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const duplicate = await buildCustomCertificate({
      issuer: root,
      subject: clientSubject,
      duplicateBasicConstraints: true
    });
    const unknownCritical = await buildCustomCertificate({
      issuer: root,
      subject: clientSubject,
      unknownCriticalExtension: true
    });
    const criticalSan = await buildCustomCertificate({
      issuer: root,
      subject: clientSubject,
      criticalSubjectAltName: true
    });

    await expect(verifyCertificateChain({
      certificatePem: duplicate.certPem,
      trustedRootCertificatesPem: [root.certPem]
    })).resolves.toEqual({ valid: false, reason: "duplicate-extension", certificateIndex: 0 });

    await expect(verifyCertificateChain({
      certificatePem: unknownCritical.certPem,
      trustedRootCertificatesPem: [root.certPem]
    })).resolves.toEqual({
      valid: false,
      reason: "unsupported-critical-extension",
      certificateIndex: 0
    });

    await expect(verifyCertificateChain({
      certificatePem: criticalSan.certPem,
      trustedRootCertificatesPem: [root.certPem]
    })).resolves.toEqual({
      valid: false,
      reason: "unsupported-critical-extension",
      certificateIndex: 0
    });
  });

  it("reports a mismatch between inner and outer signature algorithms", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const mislabeled = await buildCustomCertificate({
      issuer: root,
      subject: clientSubject,
      outerSignatureCurve: "P-384"
    });

    await expect(verifyCertificateChain({
      certificatePem: mislabeled.certPem,
      trustedRootCertificatesPem: [root.certPem]
    })).resolves.toEqual({
      valid: false,
      reason: "signature-algorithm-mismatch",
      certificateIndex: 0
    });
  });

  it("checks the trusted root self-signature for integrity", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    const client = await issueClientCert({ ca: root, subject: clientSubject, days: 30 });
    const tamperedRootDer = new Uint8Array(root.certDer);
    tamperedRootDer[tamperedRootDer.length - 1] ^= 0x01;

    await expect(verifyCertificateChain({
      certificatePem: client.certPem,
      trustedRootCertificatesPem: [certificateToPem(tamperedRootDer)]
    })).resolves.toEqual({ valid: false, reason: "invalid-signature", certificateIndex: 1 });
  });

  it("throws for malformed inputs and more than one intermediate", async () => {
    const root = await createRootCA({ subject: rootSubject, days: 3650 });
    await expect(verifyCertificateChain({
      certificatePem: "not a certificate",
      trustedRootCertificatesPem: [root.certPem]
    })).rejects.toThrow();

    await expect(verifyCertificateChain({
      certificatePem: root.certPem,
      intermediateCertificatesPem: [root.certPem, root.certPem],
      trustedRootCertificatesPem: [root.certPem]
    })).rejects.toThrow("at most one");
  });
});

interface CustomCertificateOptions {
  issuer: CertificateAuthority;
  subject: Subject;
  isCA?: boolean;
  duplicateBasicConstraints?: boolean;
  unknownCriticalExtension?: boolean;
  criticalSubjectAltName?: boolean;
  outerSignatureCurve?: SupportedCurve;
}

async function buildCustomCertificate(options: CustomCertificateOptions): Promise<{
  certPem: string;
  certDer: Uint8Array;
  keyPair: CryptoKeyPair;
}> {
  const issuer = await parseCertificateDer(options.issuer.certDer);
  const issuerCurve = curveOf(options.issuer.privateKey);
  const keyPair = await generateKeyPair();
  const spki = await exportSpki(keyPair.publicKey);
  const ski = await keyIdentifierFromSpki(spki);
  const issuerSki = issuer.subjectKeyIdentifier ?? await keyIdentifierFromSpki(issuer.subjectPublicKeyInfoDer);
  const basicConstraints = options.isCA
    ? basicConstraintsCaExtension(0)
    : basicConstraintsLeafExtension();
  const extensions = [
    basicConstraints,
    keyUsageExtension(options.isCA ? ["keyCertSign", "cRLSign"] : ["digitalSignature"]),
    ...(!options.isCA ? [extendedKeyUsageClientAuthExtension()] : []),
    subjectKeyIdentifierExtension(ski),
    authorityKeyIdentifierExtension(issuerSki)
  ];
  if (options.duplicateBasicConstraints) {
    extensions.push(basicConstraintsLeafExtension());
  }
  if (options.unknownCriticalExtension) {
    extensions.push(sequence(
      oid("1.2.3.4.5.6"),
      boolean(true),
      octetString(sequence())
    ));
  }
  if (options.criticalSubjectAltName) {
    extensions.push(sequence(
      oid("2.5.29.17"),
      boolean(true),
      octetString(sequence())
    ));
  }

  const { tbsCertificateDer } = buildTbsCertificate({
    serialNumber: 1,
    days: 30,
    issuerNameDer: issuer.subjectNameDer,
    subjectNameDer: encodeName(options.subject),
    subjectPublicKeyInfoDer: spki,
    extensions,
    issuerCurve
  });
  const signature = await signDer(options.issuer.privateKey, tbsCertificateDer);
  const certDer = buildCertificate(
    tbsCertificateDer,
    signature,
    options.outerSignatureCurve ?? issuerCurve
  );
  return { certPem: certificateToPem(certDer), certDer, keyPair };
}

function replaceNotBefore(certDer: Uint8Array, encodedTime: string): Uint8Array {
  const certificateChildren = readSequenceChildren(readElement(certDer));
  const tbs = certificateChildren[0]!;
  const tbsChildren = readSequenceChildren(tbs);
  const validity = tbsChildren[4]!;
  const validityChildren = readSequenceChildren(validity);
  const replacementValidity = sequence(
    der(validityChildren[0]!.tag, asciiBytes(encodedTime)),
    validityChildren[1]!.raw
  );
  const replacementTbs = sequence(...tbsChildren.map((child, index) =>
    index === 4 ? replacementValidity : child.raw
  ));
  return sequence(
    replacementTbs,
    certificateChildren[1]!.raw,
    certificateChildren[2]!.raw
  );
}
