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

export interface CertificateAuthority {
  certPem: string;
  privateKeyPem: string;
  publicKeyPem: string;
  certDer: Uint8Array;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  issuerChainPem: string;
}

export interface IssuedClientCertificate {
  certPem: string;
  privateKeyPem: string;
  publicKeyPem: string;
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
}

export interface IssueIntermediateCAOptions {
  ca: CertificateAuthority;
  subject: Subject;
  days: number;
  notBefore?: Date;
  serialNumber?: SerialNumber;
  pathLenConstraint?: number;
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

export interface ImportCertificateAuthorityOptions {
  certPem: string;
  privateKeyPem: string;
  issuerChainPem?: string;
}
