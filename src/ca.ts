import { cloneBytes, concatBytes } from "./bytes.js";
import {
  assertKeyPairMatches,
  exportSpki,
  generateKeyPair,
  importPrivateKeyPem,
  keyIdentifierFromSpki,
  privateKeyToPem,
  publicKeyToPem,
  signDer
} from "./crypto.js";
import { encodeName } from "./name.js";
import { certificateToPem, pemToDer } from "./pem.js";
import { parseCertificateDer, type ParsedCertificate } from "./parser.js";
import type {
  CertificateAuthority,
  CreateRootCAOptions,
  ImportCertificateAuthorityOptions,
  IssueClientCertOptions,
  IssueIntermediateCAOptions,
  IssuedClientCertificate
} from "./types.js";
import {
  authorityKeyIdentifierExtension,
  basicConstraintsExtension,
  buildCertificate,
  buildTbsCertificate,
  extendedKeyUsageClientAuthExtension,
  keyUsageExtension,
  subjectAltNameExtension,
  subjectKeyIdentifierExtension
} from "./x509.js";

interface CaMetadata extends ParsedCertificate {
  issuerChainPem: string;
}

const caMetadata = new WeakMap<CertificateAuthority, CaMetadata>();

export async function createRootCA(options: CreateRootCAOptions): Promise<CertificateAuthority> {
  const keyPair = await generateKeyPair();
  const subjectNameDer = encodeName(options.subject);
  const spki = await exportSpki(keyPair.publicKey);
  const keyIdentifier = await keyIdentifierFromSpki(spki);
  const extensions = [
    basicConstraintsExtension(true, options.pathLenConstraint),
    keyUsageExtension(["keyCertSign", "cRLSign"]),
    subjectKeyIdentifierExtension(keyIdentifier),
    authorityKeyIdentifierExtension(keyIdentifier)
  ];
  const { tbsCertificateDer } = buildTbsCertificate({
    serialNumber: options.serialNumber,
    notBefore: options.notBefore,
    days: options.days,
    issuerNameDer: subjectNameDer,
    subjectNameDer,
    subjectPublicKeyInfoDer: spki,
    extensions
  });
  const signatureDer = await signDer(keyPair.privateKey, tbsCertificateDer);
  const certDer = buildCertificate(tbsCertificateDer, signatureDer);
  const ca = await assembleCertificateAuthority(certDer, keyPair, "");

  caMetadata.set(ca, {
    ...(await parseCertificateDer(certDer)),
    issuerChainPem: ""
  });

  return ca;
}

export async function issueIntermediateCA(options: IssueIntermediateCAOptions): Promise<CertificateAuthority> {
  const issuer = await ensureCaMetadata(options.ca);
  assertCanIssueCertificate(issuer);
  assertCanIssueIntermediate(issuer, options.pathLenConstraint);

  const keyPair = await generateKeyPair();
  const subjectNameDer = encodeName(options.subject);
  const spki = await exportSpki(keyPair.publicKey);
  const subjectKeyIdentifier = await keyIdentifierFromSpki(spki);
  const authorityKeyIdentifier = issuer.subjectKeyIdentifier ?? await keyIdentifierFromSpki(issuer.subjectPublicKeyInfoDer);
  const extensions = [
    basicConstraintsExtension(true, options.pathLenConstraint ?? 0),
    keyUsageExtension(["keyCertSign", "cRLSign"]),
    subjectKeyIdentifierExtension(subjectKeyIdentifier),
    authorityKeyIdentifierExtension(authorityKeyIdentifier)
  ];
  const { tbsCertificateDer } = buildTbsCertificate({
    serialNumber: options.serialNumber,
    notBefore: options.notBefore,
    days: options.days,
    issuerNameDer: issuer.subjectNameDer,
    subjectNameDer,
    subjectPublicKeyInfoDer: spki,
    extensions
  });
  const signatureDer = await signDer(options.ca.privateKey, tbsCertificateDer);
  const certDer = buildCertificate(tbsCertificateDer, signatureDer);
  const issuerChainPem = joinPemChain([options.ca.certPem, issuer.issuerChainPem]);
  const ca = await assembleCertificateAuthority(certDer, keyPair, issuerChainPem);

  caMetadata.set(ca, {
    ...(await parseCertificateDer(certDer)),
    issuerChainPem
  });

  return ca;
}

export async function issueClientCert(options: IssueClientCertOptions): Promise<IssuedClientCertificate> {
  const issuer = await ensureCaMetadata(options.ca);
  assertCanIssueCertificate(issuer);

  const keyPair = await generateKeyPair();
  const subjectNameDer = encodeName(options.subject);
  const spki = await exportSpki(keyPair.publicKey);
  const subjectKeyIdentifier = await keyIdentifierFromSpki(spki);
  const authorityKeyIdentifier = issuer.subjectKeyIdentifier ?? await keyIdentifierFromSpki(issuer.subjectPublicKeyInfoDer);
  const san = subjectAltNameExtension(options.dnsNames, options.ipAddresses);
  const extensions = [
    basicConstraintsExtension(false),
    keyUsageExtension(["digitalSignature"]),
    extendedKeyUsageClientAuthExtension(),
    subjectKeyIdentifierExtension(subjectKeyIdentifier),
    authorityKeyIdentifierExtension(authorityKeyIdentifier),
    ...(san ? [san] : [])
  ];
  const { tbsCertificateDer } = buildTbsCertificate({
    serialNumber: options.serialNumber,
    notBefore: options.notBefore,
    days: options.days,
    issuerNameDer: issuer.subjectNameDer,
    subjectNameDer,
    subjectPublicKeyInfoDer: spki,
    extensions
  });
  const signatureDer = await signDer(options.ca.privateKey, tbsCertificateDer);
  const certDer = buildCertificate(tbsCertificateDer, signatureDer);
  const certPem = certificateToPem(certDer);

  return {
    certPem,
    privateKeyPem: await privateKeyToPem(keyPair.privateKey),
    publicKeyPem: await publicKeyToPem(keyPair.publicKey),
    certDer,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    certChainPem: joinPemChain([certPem, options.ca.certPem, issuer.issuerChainPem])
  };
}

export async function importCertificateAuthority(options: ImportCertificateAuthorityOptions): Promise<CertificateAuthority> {
  const certDer = pemToDer(options.certPem);
  const parsed = await parseCertificateDer(certDer);
  const privateKey = await importPrivateKeyPem(options.privateKeyPem);
  await assertKeyPairMatches(privateKey, parsed.publicKey);

  const ca: CertificateAuthority = {
    certPem: options.certPem,
    privateKeyPem: options.privateKeyPem,
    publicKeyPem: await publicKeyToPem(parsed.publicKey),
    certDer: cloneBytes(certDer),
    privateKey,
    publicKey: parsed.publicKey,
    issuerChainPem: options.issuerChainPem ?? ""
  };

  caMetadata.set(ca, {
    ...parsed,
    issuerChainPem: ca.issuerChainPem
  });

  return ca;
}

async function assembleCertificateAuthority(
  certDer: Uint8Array,
  keyPair: CryptoKeyPair,
  issuerChainPem: string
): Promise<CertificateAuthority> {
  return {
    certPem: certificateToPem(certDer),
    privateKeyPem: await privateKeyToPem(keyPair.privateKey),
    publicKeyPem: await publicKeyToPem(keyPair.publicKey),
    certDer,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    issuerChainPem
  };
}

async function ensureCaMetadata(ca: CertificateAuthority): Promise<CaMetadata> {
  const existing = caMetadata.get(ca);
  if (existing) {
    return existing;
  }

  const parsed = await parseCertificateDer(ca.certDer?.length ? ca.certDer : pemToDer(ca.certPem));
  const metadata = {
    ...parsed,
    issuerChainPem: ca.issuerChainPem ?? ""
  };

  caMetadata.set(ca, metadata);
  return metadata;
}

function assertCanIssueCertificate(issuer: CaMetadata): void {
  if (!issuer.isCA) {
    throw new Error("Issuer certificate is not a CA");
  }

  if (!issuer.keyCertSign) {
    throw new Error("Issuer certificate keyUsage does not allow certificate signing");
  }
}

function assertCanIssueIntermediate(issuer: CaMetadata, requestedPathLenConstraint: number | undefined): void {
  if (issuer.pathLenConstraint === 0) {
    throw new Error("Issuer pathLenConstraint=0 does not allow issuing another intermediate CA");
  }

  if (issuer.pathLenConstraint !== undefined) {
    const requested = requestedPathLenConstraint ?? 0;
    if (requested > issuer.pathLenConstraint - 1) {
      throw new Error("Requested pathLenConstraint exceeds issuer limit");
    }
  }
}

function joinPemChain(parts: readonly string[]): string {
  return parts
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .join("\n") + "\n";
}
