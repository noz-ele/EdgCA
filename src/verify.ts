import { bytesEqual } from "./bytes.js";
import { keyIdentifierFromSpki, verifyDer } from "./crypto.js";
import { pemToDerWithLabel } from "./pem.js";
import { parseCertificateDer } from "./parser.js";
import type { CertificateAuthority } from "./types.js";

export interface VerifyClientCertificateIssuedByOptions {
  ca: CertificateAuthority;
  certPem: string;
}

export async function verifyClientCertificateIssuedBy(
  options: VerifyClientCertificateIssuedByOptions
): Promise<boolean> {
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
