import { describe, expect, it } from "vitest";
import {
  certificateToPem,
  createRootCA,
  generateKeyPair,
  issueClientCertForPublicKey,
  pemToDerWithLabel,
  verifyCertificateSignature
} from "../src/index.js";
import { arrayBufferFromBytes } from "../src/bytes.js";
import {
  ecdsaRawToDer,
  type SupportedCurve
} from "../src/crypto.js";
import {
  bitString,
  der,
  oid,
  readElement,
  readSequenceChildren,
  sequence,
  TAG
} from "../src/der.js";

const CURVE_HASH: Record<SupportedCurve, "SHA-256" | "SHA-384" | "SHA-512"> = {
  "P-256": "SHA-256",
  "P-384": "SHA-384",
  "P-521": "SHA-512"
};

const CURVE_COMPONENT_SIZE: Record<SupportedCurve, number> = {
  "P-256": 32,
  "P-384": 48,
  "P-521": 66
};

describe("certificate public-key signature verification", () => {
  for (const curve of ["P-256", "P-384", "P-521"] as const) {
    it(`verifies DER and IEEE P1363 signatures for ${curve}`, async () => {
      const { certificatePem, privateKey } = await issueClientForCurve(curve);
      const data = new TextEncoder().encode(`edgca-signature-test:${curve}`);
      const signatureP1363 = await signP1363(privateKey, curve, data);
      const signatureDer = ecdsaRawToDer(signatureP1363, CURVE_COMPONENT_SIZE[curve]);

      await expect(verifyCertificateSignature({
        certificatePem,
        data,
        signature: signatureP1363,
        signatureFormat: "ieee-p1363"
      })).resolves.toBe(true);

      await expect(verifyCertificateSignature({
        certificatePem,
        data,
        signature: signatureDer,
        signatureFormat: "der"
      })).resolves.toBe(true);
    });
  }

  it("returns false for changed data, a changed signature, or another certificate", async () => {
    const signer = await issueClientForCurve("P-256");
    const other = await issueClientForCurve("P-256");
    const data = new TextEncoder().encode("request-bound-signature-base");
    const signature = await signP1363(signer.privateKey, "P-256", data);
    const changedSignature = new Uint8Array(signature);
    changedSignature[0] ^= 0x01;

    await expect(verifyCertificateSignature({
      certificatePem: signer.certificatePem,
      data: new TextEncoder().encode("different-signature-base"),
      signature,
      signatureFormat: "ieee-p1363"
    })).resolves.toBe(false);

    await expect(verifyCertificateSignature({
      certificatePem: signer.certificatePem,
      data,
      signature: changedSignature,
      signatureFormat: "ieee-p1363"
    })).resolves.toBe(false);

    await expect(verifyCertificateSignature({
      certificatePem: other.certificatePem,
      data,
      signature,
      signatureFormat: "ieee-p1363"
    })).resolves.toBe(false);
  });

  it("does not apply chain, validity, or target-profile policy", async () => {
    const notBefore = new Date("2020-01-01T00:00:00Z");
    const root = await createRootCA({
      subject: [{ type: "CN", value: "expired-signature-root" }],
      notBefore,
      days: 10
    });
    const data = new TextEncoder().encode("signature-primitive-only");
    const signature = await signP1363(root.privateKey, "P-256", data);

    await expect(verifyCertificateSignature({
      certificatePem: root.certPem,
      data,
      signature,
      signatureFormat: "ieee-p1363"
    })).resolves.toBe(true);
  });

  it("rejects malformed encodings and P1363 lengths", async () => {
    const { certificatePem } = await issueClientForCurve("P-256");
    const data = new Uint8Array([1, 2, 3]);

    await expect(verifyCertificateSignature({
      certificatePem,
      data,
      signature: new Uint8Array([0x04, 0x00]),
      signatureFormat: "der"
    })).rejects.toThrow("Invalid DER ECDSA signature");

    await expect(verifyCertificateSignature({
      certificatePem,
      data,
      signature: new Uint8Array(63),
      signatureFormat: "ieee-p1363"
    })).rejects.toThrow("64 bytes for P-256");

    await expect(verifyCertificateSignature({
      certificatePem,
      data,
      signature: new Uint8Array(65),
      signatureFormat: "ieee-p1363"
    })).rejects.toThrow("64 bytes for P-256");

    const integerOne = der(TAG.INTEGER, new Uint8Array([1]));
    const malformedDerCases: Array<{ signature: Uint8Array; message: string }> = [
      {
        signature: sequence(integerOne, integerOne, integerOne),
        message: "Invalid DER ECDSA signature integers"
      },
      {
        signature: sequence(der(TAG.INTEGER, new Uint8Array([0x80])), integerOne),
        message: "Negative DER ECDSA integer"
      },
      {
        signature: sequence(der(TAG.INTEGER, new Uint8Array([0, 1])), integerOne),
        message: "Non-minimal DER ECDSA integer"
      },
      {
        signature: sequence(der(TAG.INTEGER, new Uint8Array()), integerOne),
        message: "Invalid empty DER ECDSA integer"
      }
    ];
    for (const malformed of malformedDerCases) {
      await expect(verifyCertificateSignature({
        certificatePem,
        data,
        signature: malformed.signature,
        signatureFormat: "der"
      })).rejects.toThrow(malformed.message);
    }
  });

  it("rejects malformed certificates and invalid runtime options", async () => {
    const { certificatePem } = await issueClientForCurve("P-256");
    const data = new Uint8Array();
    const signature = new Uint8Array(64);

    await expect(verifyCertificateSignature({
      certificatePem: "not a certificate",
      data,
      signature,
      signatureFormat: "ieee-p1363"
    })).rejects.toThrow();

    await expect(verifyCertificateSignature(null as unknown as Parameters<typeof verifyCertificateSignature>[0]))
      .rejects.toThrow("options must be an object");

    await expect(verifyCertificateSignature({
      certificatePem,
      data: "not bytes" as unknown as Uint8Array,
      signature,
      signatureFormat: "ieee-p1363"
    })).rejects.toThrow("data must be a Uint8Array");

    await expect(verifyCertificateSignature({
      certificatePem,
      data,
      signature: [] as unknown as Uint8Array,
      signatureFormat: "ieee-p1363"
    })).rejects.toThrow("signature must be a Uint8Array");

    await expect(verifyCertificateSignature({
      certificatePem,
      data,
      signature,
      signatureFormat: "auto" as "der"
    })).rejects.toThrow("signatureFormat must be der or ieee-p1363");
  });

  it("rejects certificates carrying RSA or Ed25519 public keys", async () => {
    const { certificatePem } = await issueClientForCurve("P-256");
    const rsaKeyPair = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["sign", "verify"]
    );
    const rsaSpki = new Uint8Array(await crypto.subtle.exportKey("spki", rsaKeyPair.publicKey));
    const ed25519Spki = sequence(
      sequence(oid("1.3.101.112")),
      bitString(new Uint8Array(32))
    );

    for (const unsupportedSpki of [rsaSpki, ed25519Spki]) {
      const unsupportedCertificatePem = replaceCertificateSpki(certificatePem, unsupportedSpki);
      await expect(verifyCertificateSignature({
        certificatePem: unsupportedCertificatePem,
        data: new Uint8Array(),
        signature: new Uint8Array(64),
        signatureFormat: "ieee-p1363"
      })).rejects.toThrow("SubjectPublicKeyInfo is not an EC public key");
    }
  });

  it("does not mutate caller-owned data or signature buffers", async () => {
    const { certificatePem, privateKey } = await issueClientForCurve("P-256");
    const backingData = new Uint8Array([0xaa, 10, 20, 30, 0xbb]);
    const data = backingData.subarray(1, 4);
    const signature = await signP1363(privateKey, "P-256", data);
    const dataBefore = new Uint8Array(backingData);
    const signatureBefore = new Uint8Array(signature);

    await expect(verifyCertificateSignature({
      certificatePem,
      data,
      signature,
      signatureFormat: "ieee-p1363"
    })).resolves.toBe(true);

    expect(backingData).toEqual(dataBefore);
    expect(signature).toEqual(signatureBefore);
  });
});

async function issueClientForCurve(curve: SupportedCurve): Promise<{
  certificatePem: string;
  privateKey: CryptoKey;
}> {
  const root = await createRootCA({
    subject: [{ type: "CN", value: `signature-root-${curve}` }],
    days: 3650
  });
  const keyPair = await generateKeyPair(curve);
  const client = await issueClientCertForPublicKey({
    ca: root,
    publicKey: keyPair.publicKey,
    subject: [{ type: "CN", value: `signature-client-${curve}` }],
    days: 30
  });
  return { certificatePem: client.certPem, privateKey: keyPair.privateKey };
}

async function signP1363(
  privateKey: CryptoKey,
  curve: SupportedCurve,
  data: Uint8Array
): Promise<Uint8Array> {
  const dataBuffer = arrayBufferFromBytes(data);
  try {
    return new Uint8Array(await crypto.subtle.sign(
      { name: "ECDSA", hash: CURVE_HASH[curve] },
      privateKey,
      dataBuffer
    ));
  } finally {
    new Uint8Array(dataBuffer).fill(0);
  }
}

function replaceCertificateSpki(certificatePem: string, spkiDer: Uint8Array): string {
  const certificate = readSequenceChildren(
    readElement(pemToDerWithLabel(certificatePem, "CERTIFICATE"))
  );
  const tbsChildren = readSequenceChildren(certificate[0]!);
  const replacedTbs = sequence(...tbsChildren.map((element, index) =>
    index === 6 ? spkiDer : element.raw
  ));
  return certificateToPem(sequence(
    replacedTbs,
    certificate[1]!.raw,
    certificate[2]!.raw
  ));
}
