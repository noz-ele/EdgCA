import { bytesEqual, cloneBytes } from "./bytes.js";
import {
  assertKeyPairMatches,
  curveOf,
  exportSpki,
  generateKeyPair,
  keyIdentifierFromSpki,
  signDer
} from "./crypto.js";
import { encodeName } from "./name.js";
import { certificateToPem, pemToDer, pemToDerWithLabel, splitPemBlocks } from "./pem.js";
import { parseCertificateDer, type ParsedCertificate } from "./parser.js";
import type {
  CertificateAuthority,
  CreateRootCAOptions,
  ImportCertificateAuthorityOptions,
  IssueClientCertForPublicKeyOptions,
  IssueClientCertOptions,
  IssueIntermediateCAOptions,
  IssuedClientCertificate,
  IssuedClientCertificateForPublicKey,
  Subject
} from "./types.js";
import {
  authorityKeyIdentifierExtension,
  basicConstraintsCaExtension,
  basicConstraintsLeafExtension,
  buildCertificate,
  buildTbsCertificate,
  extendedKeyUsageClientAuthExtension,
  keyUsageExtension,
  subjectAltNameExtension,
  subjectKeyIdentifierExtension
} from "./x509.js";

export async function createRootCA(options: CreateRootCAOptions): Promise<CertificateAuthority> {
  const keyPair = await resolveKeyPair(options.keyPair);
  const issuerCurve = curveOf(keyPair.privateKey);
  const subjectNameDer = encodeName(options.subject);
  const spki = await exportSpki(keyPair.publicKey);
  const keyIdentifier = await keyIdentifierFromSpki(spki);
  const pathLenConstraint = resolveRootPathLenConstraint(options.pathLenConstraint);
  const extensions = [
    basicConstraintsCaExtension(pathLenConstraint),
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
    extensions,
    issuerCurve
  });
  const signatureDer = await signDer(keyPair.privateKey, tbsCertificateDer);
  const certDer = buildCertificate(tbsCertificateDer, signatureDer, issuerCurve);
  return assembleCertificateAuthority(certDer, keyPair, "");
}

export async function issueIntermediateCA(options: IssueIntermediateCAOptions): Promise<CertificateAuthority> {
  const issuer = await parseIssuer(options.ca);
  const issuerChainPem = options.ca.issuerChainPem;
  assertCanIssueCertificate(issuer);
  assertCanIssueIntermediate(issuer, issuerChainPem, options.pathLenConstraint);

  const issuerCurve = curveOf(options.ca.privateKey);
  const keyPair = await resolveKeyPair(options.keyPair);
  const subjectNameDer = encodeName(options.subject);
  const spki = await exportSpki(keyPair.publicKey);
  const subjectKeyIdentifier = await keyIdentifierFromSpki(spki);
  const authorityKeyIdentifier = issuer.subjectKeyIdentifier ?? await keyIdentifierFromSpki(issuer.subjectPublicKeyInfoDer);
  const extensions = [
    basicConstraintsCaExtension(0),
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
    extensions,
    issuerCurve
  });
  const signatureDer = await signDer(options.ca.privateKey, tbsCertificateDer);
  const certDer = buildCertificate(tbsCertificateDer, signatureDer, issuerCurve);
  const childChainPem = joinPemChain([options.ca.certPem, issuerChainPem]);
  return assembleCertificateAuthority(certDer, keyPair, childChainPem);
}

export async function issueClientCert(options: IssueClientCertOptions): Promise<IssuedClientCertificate> {
  const keyPair = await generateKeyPair();
  const built = await buildClientCertificate(
    options.ca,
    keyPair.publicKey,
    {
      subject: options.subject,
      days: options.days,
      notBefore: options.notBefore,
      serialNumber: options.serialNumber,
      dnsNames: options.dnsNames,
      ipAddresses: options.ipAddresses
    }
  );
  return {
    certPem: built.certPem,
    certDer: built.certDer,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    certChainPem: built.certChainPem
  };
}

export async function issueClientCertForPublicKey(
  options: IssueClientCertForPublicKeyOptions
): Promise<IssuedClientCertificateForPublicKey> {
  const built = await buildClientCertificate(
    options.ca,
    options.publicKey,
    {
      subject: options.subject,
      days: options.days,
      notBefore: options.notBefore,
      serialNumber: options.serialNumber,
      dnsNames: options.dnsNames,
      ipAddresses: options.ipAddresses
    }
  );
  return {
    certPem: built.certPem,
    certDer: built.certDer,
    certChainPem: built.certChainPem
  };
}

interface ClientCertContent {
  subject: Subject;
  days: number;
  notBefore?: Date | undefined;
  serialNumber?: IssueClientCertOptions["serialNumber"];
  dnsNames?: readonly string[] | undefined;
  ipAddresses?: readonly string[] | undefined;
}

async function buildClientCertificate(
  ca: CertificateAuthority,
  subjectPublicKey: CryptoKey,
  content: ClientCertContent
): Promise<{ certPem: string; certDer: Uint8Array; certChainPem: string }> {
  const issuer = await parseIssuer(ca);
  const issuerChainPem = ca.issuerChainPem;
  assertCanIssueCertificate(issuer);

  const issuerCurve = curveOf(ca.privateKey);
  const subjectNameDer = encodeName(content.subject);
  const spki = await exportSpki(subjectPublicKey);
  const subjectKeyIdentifier = await keyIdentifierFromSpki(spki);
  const authorityKeyIdentifier = issuer.subjectKeyIdentifier ?? await keyIdentifierFromSpki(issuer.subjectPublicKeyInfoDer);
  const san = subjectAltNameExtension(content.dnsNames, content.ipAddresses);
  const extensions = [
    basicConstraintsLeafExtension(),
    keyUsageExtension(["digitalSignature"]),
    extendedKeyUsageClientAuthExtension(),
    subjectKeyIdentifierExtension(subjectKeyIdentifier),
    authorityKeyIdentifierExtension(authorityKeyIdentifier),
    ...(san ? [san] : [])
  ];
  const { tbsCertificateDer } = buildTbsCertificate({
    serialNumber: content.serialNumber,
    notBefore: content.notBefore,
    days: content.days,
    issuerNameDer: issuer.subjectNameDer,
    subjectNameDer,
    subjectPublicKeyInfoDer: spki,
    extensions,
    issuerCurve
  });
  const signatureDer = await signDer(ca.privateKey, tbsCertificateDer);
  const certDer = buildCertificate(tbsCertificateDer, signatureDer, issuerCurve);
  const certPem = certificateToPem(certDer);

  return {
    certPem,
    certDer: cloneBytes(certDer),
    certChainPem: joinPemChain([certPem, ca.certPem, issuerChainPem])
  };
}

export async function importCertificateAuthority(options: ImportCertificateAuthorityOptions): Promise<CertificateAuthority> {
  const issuerChainPem = options.issuerChainPem ?? "";
  assertIssuerChainPem(issuerChainPem);

  const certDer = pemToDerWithLabel(options.certPem, "CERTIFICATE");
  const parsed = await parseCertificateDer(certDer);
  await assertKeyPairMatches(options.privateKey, parsed.publicKey);

  return {
    certPem: options.certPem,
    certDer: cloneBytes(certDer),
    privateKey: options.privateKey,
    publicKey: parsed.publicKey,
    issuerChainPem
  };
}

function assertIssuerChainPem(chainPem: string): void {
  if (chainPem.trim().length === 0) {
    return;
  }
  const blocks = splitPemBlocks(chainPem);
  if (blocks.length === 0) {
    throw new Error("issuerChainPem must contain CERTIFICATE blocks");
  }
  for (const block of blocks) {
    pemToDerWithLabel(block, "CERTIFICATE");
  }
}

async function resolveKeyPair(provided: CryptoKeyPair | undefined): Promise<CryptoKeyPair> {
  if (provided !== undefined) {
    return provided;
  }
  return generateKeyPair();
}

async function assembleCertificateAuthority(
  certDer: Uint8Array,
  keyPair: CryptoKeyPair,
  issuerChainPem: string
): Promise<CertificateAuthority> {
  return {
    certPem: certificateToPem(certDer),
    certDer: cloneBytes(certDer),
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    issuerChainPem
  };
}

async function parseIssuer(ca: CertificateAuthority): Promise<ParsedCertificate> {
  return await parseCertificateDer(ca.certDer?.length ? ca.certDer : pemToDer(ca.certPem));
}

function assertCanIssueCertificate(issuer: ParsedCertificate): void {
  if (!issuer.isCA) {
    throw new Error("Issuer certificate is not a CA");
  }

  if (!issuer.keyCertSign) {
    throw new Error("Issuer certificate keyUsage does not allow certificate signing");
  }
}

function assertCanIssueIntermediate(
  issuer: ParsedCertificate,
  issuerChainPem: string,
  requestedPathLenConstraint: number | undefined
): void {
  if (issuer.pathLenConstraint === 0) {
    throw new Error("Issuer pathLenConstraint=0 does not allow issuing another intermediate CA");
  }

  if (!isRootCa(issuer, issuerChainPem)) {
    throw new Error("Only root CAs may issue intermediate CAs");
  }

  if (requestedPathLenConstraint === undefined) {
    return;
  }
  if (typeof requestedPathLenConstraint !== "number" || !Object.is(requestedPathLenConstraint, 0)) {
    throw new Error("Intermediate pathLenConstraint must be 0");
  }
}

function resolveRootPathLenConstraint(pathLenConstraint: number | undefined): number {
  if (pathLenConstraint === undefined) {
    return 1;
  }

  if (typeof pathLenConstraint !== "number" || !Number.isInteger(pathLenConstraint)) {
    throw new Error("Root pathLenConstraint must be 0 or 1");
  }

  if (!Object.is(pathLenConstraint, 0) && pathLenConstraint !== 1) {
    throw new Error("Root pathLenConstraint must be 0 or 1");
  }

  return pathLenConstraint;
}

function isRootCa(issuer: ParsedCertificate, issuerChainPem: string): boolean {
  return issuerChainPem.trim().length === 0 && bytesEqual(issuer.issuerNameDer, issuer.subjectNameDer);
}

function joinPemChain(parts: readonly string[]): string {
  return parts
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .join("\n") + "\n";
}
