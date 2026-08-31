import { bytesEqual } from "./bytes.js";
import {
  curveOf,
  keyIdentifierFromSpki,
  signatureAlgorithmOidForCurve,
  verifyDer,
  verifyP1363
} from "./crypto.js";
import { OID } from "./oids.js";
import { pemToDerWithLabel } from "./pem.js";
import {
  parseCertificateDer,
  parseCertificateDerForVerification,
  type ParsedCertificateForVerification
} from "./parser.js";
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

export interface VerifyCertificateIssuedByOptions {
  certificatePem: string;
  issuerCertificatePem: string;
  at?: Date | number;
}

export type CertificateVerificationPurpose = "ca" | "clientAuth" | "documentSigning";

export interface VerifyCertificateChainOptions {
  certificatePem: string;
  intermediateCertificatesPem?: readonly string[];
  trustedRootCertificatesPem: readonly string[];
  at?: Date | number;
  purpose?: CertificateVerificationPurpose;
}

export type EcdsaSignatureFormat = "der" | "ieee-p1363";

export interface VerifyCertificateSignatureOptions {
  certificatePem: string;
  data: Uint8Array;
  signature: Uint8Array;
  signatureFormat: EcdsaSignatureFormat;
}

export type CertificateVerificationFailureReason =
  | "not-yet-valid"
  | "expired"
  | "issuer-name-mismatch"
  | "key-identifier-mismatch"
  | "invalid-signature"
  | "issuer-not-ca"
  | "issuer-key-usage-invalid"
  | "path-length-exceeded"
  | "target-profile-invalid"
  | "invalid-chain-order"
  | "duplicate-extension"
  | "signature-algorithm-mismatch"
  | "unsupported-critical-extension"
  | "untrusted-root";

export type CertificateChainVerificationResult =
  | { valid: true; trustedRootIndex: number }
  | {
      valid: false;
      reason: CertificateVerificationFailureReason;
      certificateIndex: number;
    };

type VerificationFailure = Extract<CertificateChainVerificationResult, { valid: false }>;

/**
 * Verifies one certificate/issuer link using public certificate material only.
 * This is not proof that a presenter possesses the certificate's private key.
 */
export async function verifyCertificateIssuedBy(
  options: VerifyCertificateIssuedByOptions
): Promise<boolean> {
  assertObject(options, "options");
  const at = toEpochMs(options.at ?? Date.now(), "at");
  const certificate = await parseVerificationCertificate(options.certificatePem, "certificatePem");
  const issuer = await parseVerificationCertificate(options.issuerCertificatePem, "issuerCertificatePem");

  if (certificatePolicyFailure(certificate, at, 0)) return false;
  if (certificatePolicyFailure(issuer, at, 1)) return false;
  if (issuerConstraintFailure(issuer, 1)) return false;
  return (await linkFailure(certificate, issuer, 0)) === undefined;
}

/**
 * Verifies a caller-ordered chain ending at one explicitly supplied trust
 * anchor. It intentionally does not perform PKI path building or revocation.
 */
export async function verifyCertificateChain(
  options: VerifyCertificateChainOptions
): Promise<CertificateChainVerificationResult> {
  assertObject(options, "options");
  const at = toEpochMs(options.at ?? Date.now(), "at");
  const intermediatePems = options.intermediateCertificatesPem ?? [];
  if (!Array.isArray(intermediatePems)) {
    throw new Error("intermediateCertificatesPem must be an array");
  }
  if (intermediatePems.length > 1) {
    throw new Error("intermediateCertificatesPem supports at most one certificate");
  }
  if (!Array.isArray(options.trustedRootCertificatesPem) || options.trustedRootCertificatesPem.length === 0) {
    throw new Error("trustedRootCertificatesPem must be a non-empty array");
  }
  if (
    options.purpose !== undefined &&
    options.purpose !== "ca" &&
    options.purpose !== "clientAuth" &&
    options.purpose !== "documentSigning"
  ) {
    throw new Error("purpose must be ca, clientAuth, or documentSigning");
  }

  const target = await parseVerificationCertificate(options.certificatePem, "certificatePem");
  const intermediates = await Promise.all(
    intermediatePems.map((pem, index) =>
      parseVerificationCertificate(pem, `intermediateCertificatesPem[${index}]`)
    )
  );
  const roots = await Promise.all(
    options.trustedRootCertificatesPem.map((pem, index) =>
      parseVerificationCertificate(pem, `trustedRootCertificatesPem[${index}]`)
    )
  );
  const path = [target, ...intermediates];

  for (let index = 0; index < intermediates.length; index += 1) {
    const intermediate = intermediates[index]!;
    if (bytesEqual(intermediate.subjectNameDer, intermediate.issuerNameDer)) {
      return failure("invalid-chain-order", index + 1);
    }
  }

  for (let index = 0; index < path.length; index += 1) {
    const policyFailure = certificatePolicyFailure(path[index]!, at, index);
    if (policyFailure) return policyFailure;
  }

  const profileFailure = targetProfileFailure(target, options.purpose);
  if (profileFailure) return failure(profileFailure, 0);

  for (let childIndex = 0; childIndex < path.length - 1; childIndex += 1) {
    const issuerIndex = childIndex + 1;
    const issuer = path[issuerIndex]!;
    const issuerFailure = issuerConstraintFailure(issuer, issuerIndex);
    if (issuerFailure) return issuerFailure;
    const pathFailure = pathLengthFailure(issuer, path.slice(0, issuerIndex), issuerIndex);
    if (pathFailure) return pathFailure;
    const relationshipFailure = await linkFailure(path[childIndex]!, issuer, childIndex);
    if (relationshipFailure) return relationshipFailure;
  }

  const terminalChild = path[path.length - 1]!;
  const rootIndexInPath = path.length;
  const candidateRootIndexes: number[] = [];
  for (let index = 0; index < roots.length; index += 1) {
    if (await issuerIdentityMatches(terminalChild, roots[index]!)) {
      candidateRootIndexes.push(index);
    }
  }
  if (candidateRootIndexes.length === 0) {
    return failure("untrusted-root", rootIndexInPath);
  }

  let firstCandidateFailure: VerificationFailure | undefined;
  for (const trustedRootIndex of candidateRootIndexes) {
    const root = roots[trustedRootIndex]!;
    const checks = [
      certificatePolicyFailure(root, at, rootIndexInPath),
      issuerConstraintFailure(root, rootIndexInPath),
      pathLengthFailure(root, path, rootIndexInPath),
      await linkFailure(terminalChild, root, path.length - 1),
      await rootIntegrityFailure(root, rootIndexInPath)
    ];
    const candidateFailure = checks.find((check): check is VerificationFailure => check !== undefined);
    if (!candidateFailure) {
      return { valid: true, trustedRootIndex };
    }
    firstCandidateFailure ??= candidateFailure;
  }

  return firstCandidateFailure ?? failure("untrusted-root", rootIndexInPath);
}

/**
 * Verifies an arbitrary byte sequence with the public key embedded in a
 * certificate. This is a cryptographic primitive only: it does not validate
 * the certificate chain, certificate policy, challenge freshness, or replay
 * state, and it never handles private-key material.
 */
export async function verifyCertificateSignature(
  options: VerifyCertificateSignatureOptions
): Promise<boolean> {
  assertObject(options, "options");
  if (!(options.data instanceof Uint8Array)) {
    throw new Error("data must be a Uint8Array");
  }
  if (!(options.signature instanceof Uint8Array)) {
    throw new Error("signature must be a Uint8Array");
  }
  if (options.signatureFormat !== "der" && options.signatureFormat !== "ieee-p1363") {
    throw new Error("signatureFormat must be der or ieee-p1363");
  }

  const certificate = await parseVerificationCertificate(options.certificatePem, "certificatePem");
  if (options.signatureFormat === "der") {
    return await verifyDer(certificate.publicKey, options.signature, options.data);
  }
  return await verifyP1363(certificate.publicKey, options.signature, options.data);
}

/**
 * Legacy compatibility API. Its external validity option and direct-issuer
 * semantics intentionally remain unchanged.
 *
 * This is not mTLS verification and does not authenticate the presenter.
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

async function parseVerificationCertificate(
  pem: string,
  name: string
): Promise<ParsedCertificateForVerification> {
  if (typeof pem !== "string" || pem.length === 0) {
    throw new Error(`${name} must be a non-empty certificate PEM string`);
  }
  return parseCertificateDerForVerification(pemToDerWithLabel(pem, "CERTIFICATE"));
}

function certificatePolicyFailure(
  certificate: ParsedCertificateForVerification,
  at: number,
  certificateIndex: number
): VerificationFailure | undefined {
  if (certificate.duplicateExtensionOids.length > 0) {
    return failure("duplicate-extension", certificateIndex);
  }
  if (!certificate.signatureAlgorithmMatches) {
    return failure("signature-algorithm-mismatch", certificateIndex);
  }
  if (certificate.unsupportedCriticalExtensionOids.length > 0) {
    return failure("unsupported-critical-extension", certificateIndex);
  }
  if (at < certificate.notBeforeMs) {
    return failure("not-yet-valid", certificateIndex);
  }
  if (at > certificate.notAfterMs) {
    return failure("expired", certificateIndex);
  }
  return undefined;
}

function issuerConstraintFailure(
  issuer: ParsedCertificateForVerification,
  certificateIndex: number
): VerificationFailure | undefined {
  if (!issuer.basicConstraintsPresent || !issuer.isCA) {
    return failure("issuer-not-ca", certificateIndex);
  }
  if (!issuer.keyUsagePresent || !issuer.keyUsage.keyCertSign) {
    return failure("issuer-key-usage-invalid", certificateIndex);
  }
  return undefined;
}

function pathLengthFailure(
  issuer: ParsedCertificateForVerification,
  certificatesBelow: readonly ParsedCertificateForVerification[],
  certificateIndex: number
): VerificationFailure | undefined {
  if (issuer.pathLenConstraint === undefined) return undefined;
  const caCountBelow = certificatesBelow.filter((certificate) => certificate.isCA).length;
  return caCountBelow > issuer.pathLenConstraint
    ? failure("path-length-exceeded", certificateIndex)
    : undefined;
}

function targetProfileFailure(
  target: ParsedCertificateForVerification,
  purpose: CertificateVerificationPurpose | undefined
): CertificateVerificationFailureReason | undefined {
  if (purpose === undefined) return undefined;
  if (purpose === "ca") {
    return target.basicConstraintsPresent && target.isCA &&
      target.keyUsagePresent && target.keyUsage.keyCertSign
      ? undefined
      : "target-profile-invalid";
  }

  if (!target.basicConstraintsPresent || target.isCA || !target.keyUsagePresent) {
    return "target-profile-invalid";
  }
  if (!target.keyUsage.digitalSignature || !target.extendedKeyUsagePresent) {
    return "target-profile-invalid";
  }
  if (purpose === "clientAuth") {
    return target.extendedKeyUsageOids.includes(OID.clientAuth)
      ? undefined
      : "target-profile-invalid";
  }
  return target.keyUsage.contentCommitment &&
    target.extendedKeyUsageOids.includes(OID.documentSigning)
    ? undefined
    : "target-profile-invalid";
}

async function linkFailure(
  child: ParsedCertificateForVerification,
  issuer: ParsedCertificateForVerification,
  childIndex: number
): Promise<VerificationFailure | undefined> {
  if (!bytesEqual(child.issuerNameDer, issuer.subjectNameDer)) {
    return failure("issuer-name-mismatch", childIndex);
  }
  if (!(await keyIdentifierMatches(child, issuer))) {
    return failure("key-identifier-mismatch", childIndex);
  }
  const expectedAlgorithmOid = signatureAlgorithmOidForCurve(curveOf(issuer.publicKey));
  if (child.signatureAlgorithmOid !== expectedAlgorithmOid) {
    return failure("signature-algorithm-mismatch", childIndex);
  }
  if (!(await verifyDer(issuer.publicKey, child.signatureDer, child.tbsCertificateDer))) {
    return failure("invalid-signature", childIndex);
  }
  return undefined;
}

async function issuerIdentityMatches(
  child: ParsedCertificateForVerification,
  issuer: ParsedCertificateForVerification
): Promise<boolean> {
  return bytesEqual(child.issuerNameDer, issuer.subjectNameDer) &&
    await keyIdentifierMatches(child, issuer);
}

async function keyIdentifierMatches(
  child: ParsedCertificateForVerification,
  issuer: ParsedCertificateForVerification
): Promise<boolean> {
  if (!child.authorityKeyIdentifier || !issuer.subjectKeyIdentifier) return false;
  return bytesEqual(child.authorityKeyIdentifier, issuer.subjectKeyIdentifier);
}

async function rootIntegrityFailure(
  root: ParsedCertificateForVerification,
  certificateIndex: number
): Promise<VerificationFailure | undefined> {
  if (!bytesEqual(root.issuerNameDer, root.subjectNameDer)) {
    return failure("issuer-name-mismatch", certificateIndex);
  }
  if (!(await keyIdentifierMatches(root, root))) {
    return failure("key-identifier-mismatch", certificateIndex);
  }
  const expectedAlgorithmOid = signatureAlgorithmOidForCurve(curveOf(root.publicKey));
  if (root.signatureAlgorithmOid !== expectedAlgorithmOid) {
    return failure("signature-algorithm-mismatch", certificateIndex);
  }
  if (!(await verifyDer(root.publicKey, root.signatureDer, root.tbsCertificateDer))) {
    return failure("invalid-signature", certificateIndex);
  }
  return undefined;
}

function failure(
  reason: CertificateVerificationFailureReason,
  certificateIndex: number
): VerificationFailure {
  return { valid: false, reason, certificateIndex };
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

function assertObject(value: unknown, name: string): asserts value is object {
  if (typeof value !== "object" || value === null) {
    throw new Error(`${name} must be an object`);
  }
}
