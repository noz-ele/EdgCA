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

/**
 * Confirms that `options.certPem` was issued by `options.ca`.
 *
 * This is **not** mTLS verification, and does not even attempt to be.
 * At most it is *issuance verification*: "the presented certificate was
 * issued by the specified CA" — which is **not** the same as authenticating
 * that the presenter is the certificate's legitimate owner.
 *
 * A client certificate is, by design, presentable to anyone, and its
 * contents are trivially copyable. You must assume that anyone could be
 * holding a valid copy. Therefore possession of valid certificate data
 * **never** proves legitimate ownership.
 *
 * Proving legitimate ownership additionally requires verifying possession
 * of the corresponding private key (a signature made by it, verified
 * against the certificate's public key). The TLS handshake's
 * `CertificateVerify` message normally provides this, but the Cloudflare
 * Workers runtime does not expose that signature to the application. On
 * non-Enterprise plans, Cloudflare's TLS layer also does not know about
 * your self-managed CA, so `request.cf.tlsClientAuth.certVerified` will
 * not be `"SUCCESS"` for certificates EdgCA issued. Application code on
 * Workers (Enterprise excluded) has no way to verify proof-of-possession.
 *
 * Implication: anyone who has obtained a copy of a valid certificate
 * (logs, leaked storage, network capture, etc.) can present it and pass
 * this check. Use this as a minimum identity-check layer, not as
 * authentication. For real authentication, use Cloudflare Enterprise mTLS
 * at the TLS layer, or add an application-layer challenge-response that
 * has the client sign a server-issued nonce with its private key.
 *
 * Also out of scope (not checked here): `BasicConstraints CA=false`,
 * `EKU clientAuth`, revocation, and chain walking.
 */
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
