export type ShortSubjectAttributeType =
  | "CN"
  | "O"
  | "OU"
  | "C"
  | "ST"
  | "L"
  | "E"
  | "DC"
  | "SERIALNUMBER"
  | "STREET"
  | "POSTALCODE"
  | "TITLE"
  | "GIVENNAME"
  | "SURNAME"
  | "UID";

export type DottedOid = `${number}.${number}${string}`;

export type SubjectAttributeType = ShortSubjectAttributeType | DottedOid;

export interface SubjectAttribute {
  type: SubjectAttributeType;
  value: string;
}

export type Subject = SubjectAttribute[];

export type SerialNumber = bigint | number | string | Uint8Array;

export type EcdsaSignatureFormat = "der" | "ieee-p1363";

export interface CertificateAuthority {
  certPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  issuerChainPem: string;
}

export interface IssuedClientCertificate {
  certPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  certChainPem: string;
}

export interface CreateRootCAOptions {
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  pathLenConstraint?: number;
  keyPair?: CryptoKeyPair;
}

export interface IssueIntermediateCAOptions {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  pathLenConstraint?: number;
  keyPair?: CryptoKeyPair;
}

export interface IssueClientCertOptions {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  dnsNames?: string[];
  ipAddresses?: string[];
}

export interface IssueClientCertForPublicKeyOptions {
  ca: CertificateAuthority;
  publicKey: CryptoKey;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  dnsNames?: string[];
  ipAddresses?: string[];
}

export interface IssuedClientCertificateForPublicKey {
  certPem: string;
  certDer: Uint8Array;
  certChainPem: string;
}

export interface IssueDocumentSigningCertOptions {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
}

export interface IssuedDocumentSigningCertificate {
  certPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  certChainPem: string;
}

export interface ImportCertificateAuthorityOptions {
  certPem: string;
  privateKey: CryptoKey;
  issuerChainPem?: string;
}
