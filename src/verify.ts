import { bytesEqual } from "./bytes.js";
import { keyIdentifierFromSpki, verifyDer } from "./crypto.js";
import { pemToDerWithLabel } from "./pem.js";
import { parseCertificateDer } from "./parser.js";
import type { CertificateAuthority } from "./types.js";

export interface VerifyClientCertificateValidity {
  notBefore: Date | number;
  notAfter: Date | number;
  now?: Date | number;
}

export interface VerifyClientCertificateIssuedByOptions {
  ca: CertificateAuthority;
  certPem: string;
  validity?: VerifyClientCertificateValidity;
}

export async function verifyClientCertificateIssuedBy(
  options: VerifyClientCertificateIssuedByOptions
): Promise<boolean> {
  if (options.validity && !isWithinValidity(options.validity)) {
    return false;
  }

  const certDer = pemToDerWithLabel(options.certPem, "CERTIFICATE");
  const cert = await parseCertificateDer(certDer);
  const issuer = await parseCertificateDer(options.ca.certDer);

  if (!bytesEqual(cert.issuerNameDer, issuer.subjectNameDer)) {
    return false;
  }

  if (!cert.authorityKeyIdentifier) {
    return false;
  }
  const issuerSki =
    issuer.subjectKeyIdentifier ??
    (await keyIdentifierFromSpki(issuer.subjectPublicKeyInfoDer));
  if (!bytesEqual(cert.authorityKeyIdentifier, issuerSki)) {
    return false;
  }

  return verifyDer(options.ca.publicKey, cert.signatureDer, cert.tbsCertificateDer);
}

function isWithinValidity(validity: VerifyClientCertificateValidity): boolean {
  const notBefore = toEpochMs(validity.notBefore, "validity.notBefore");
  const notAfter = toEpochMs(validity.notAfter, "validity.notAfter");
  const now = validity.now !== undefined ? toEpochMs(validity.now, "validity.now") : Date.now();
  if (notBefore > notAfter) {
    throw new Error("validity.notBefore must be less than or equal to validity.notAfter");
  }
  return notBefore <= now && now <= notAfter;
}

function toEpochMs(value: Date | number, name: string): number {
  const ms = value instanceof Date ? value.getTime() : value;
  if (typeof ms !== "number" || !Number.isFinite(ms)) {
    throw new Error(`${name} must be a finite Date or epoch milliseconds number`);
  }
  return ms;
}
