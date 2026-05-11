import { bytesEqual } from "../../src/bytes.js";
import {
  decodeInteger,
  decodeOid,
  readChildren,
  readElement,
  readSequenceChildren,
  TAG
} from "../../src/der.js";
import { verifyDer } from "../../src/crypto.js";
import { parseCertificateDer, type ParsedCertificate } from "../../src/parser.js";

export interface ParsedNameAttribute {
  oid: string;
  tag: number;
  value: Uint8Array;
}

export interface ParsedExtension {
  oid: string;
  critical: boolean;
  value: Uint8Array;
}

export interface ParsedKeyUsage {
  unusedBits: number;
  bytes: Uint8Array;
  digitalSignature: boolean;
  contentCommitment: boolean;
  keyCertSign: boolean;
  cRLSign: boolean;
}

export interface ParsedSubjectAltName {
  dnsNames: string[];
  ipAddresses: Uint8Array[];
}

export interface ParsedDerTime {
  tag: number;
  text: string;
  date: Date;
}

export interface ParsedValidity {
  notBefore: ParsedDerTime;
  notAfter: ParsedDerTime;
}

export async function parseCertificate(der: Uint8Array): Promise<ParsedCertificate> {
  return parseCertificateDer(der);
}

export async function expectSignatureValid(issuer: ParsedCertificate, issued: ParsedCertificate): Promise<boolean> {
  return verifyDer(issuer.publicKey, issued.signatureDer, issued.tbsCertificateDer);
}

export function namesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return bytesEqual(a, b);
}

export function parseName(nameDer: Uint8Array): ParsedNameAttribute[] {
  const root = readElement(nameDer);
  const attributes: ParsedNameAttribute[] = [];

  for (const rdn of readSequenceChildren(root)) {
    if (rdn.tag !== TAG.SET) {
      throw new Error("Expected RDN SET");
    }

    const values = readChildren(rdn.value);
    if (values.length !== 1) {
      throw new Error("Only single-valued RDNs are expected in tests");
    }

    const [oidElement, valueElement] = readSequenceChildren(values[0]!);
    if (!oidElement || !valueElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid attribute");
    }

    attributes.push({
      oid: decodeOid(oidElement.value),
      tag: valueElement.tag,
      value: valueElement.value
    });
  }

  return attributes;
}

export function assertSingleValuedRdns(nameDer: Uint8Array): void {
  const root = readElement(nameDer);

  for (const rdn of readSequenceChildren(root)) {
    if (rdn.tag !== TAG.SET) {
      throw new Error("Expected RDN SET");
    }

    const values = readChildren(rdn.value);
    if (values.length !== 1) {
      throw new Error("Expected single-valued RDN");
    }
  }
}

export function parseExtensionsFromCertificate(der: Uint8Array): ParsedExtension[] {
  const certificate = readElement(der);
  const [tbs] = readSequenceChildren(certificate);
  if (!tbs) {
    throw new Error("Missing TBSCertificate");
  }

  const extensions = readSequenceChildren(tbs).find((element) => element.tag === 0xa3);
  if (!extensions) {
    return [];
  }

  const outer = readElement(extensions.value);
  return readSequenceChildren(outer).map((extension) => {
    const children = readSequenceChildren(extension);
    const oidElement = children[0];
    if (!oidElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid extension");
    }

    let valueIndex = 1;
    let critical = false;
    if (children[valueIndex]?.tag === TAG.BOOLEAN) {
      critical = children[valueIndex]!.value[0] !== 0;
      valueIndex += 1;
    }

    const value = children[valueIndex];
    if (!value || value.tag !== TAG.OCTET_STRING) {
      throw new Error("Invalid extension value");
    }

    return {
      oid: decodeOid(oidElement.value),
      critical,
      value: value.value
    };
  });
}

export function findExtension(der: Uint8Array, oid: string): ParsedExtension | undefined {
  return parseExtensionsFromCertificate(der).find((extension) => extension.oid === oid);
}

export function getExtension(der: Uint8Array, oid: string): ParsedExtension {
  const extension = findExtension(der, oid);
  if (!extension) {
    throw new Error(`Missing extension ${oid}`);
  }
  return extension;
}

export function parseSubjectKeyIdentifier(value: Uint8Array): Uint8Array {
  const root = readElement(value);
  if (root.tag !== TAG.OCTET_STRING) {
    throw new Error("Invalid subjectKeyIdentifier payload");
  }
  return root.value;
}

export function subjectPublicKeyBits(spkiDer: Uint8Array): Uint8Array {
  const root = readElement(spkiDer);
  if (root.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid SPKI SEQUENCE");
  }
  const [, bitString] = readSequenceChildren(root);
  if (!bitString || bitString.tag !== TAG.BIT_STRING) {
    throw new Error("Invalid SPKI subjectPublicKey BIT STRING");
  }
  return bitString.value.subarray(1);
}

export function parseAuthorityKeyIdentifier(value: Uint8Array): { keyIdentifier: Uint8Array; tag: number } {
  const root = readElement(value);
  const [keyIdentifier] = readSequenceChildren(root);
  if (!keyIdentifier || keyIdentifier.tag !== 0x80) {
    throw new Error("Invalid authorityKeyIdentifier keyIdentifier");
  }
  return {
    keyIdentifier: keyIdentifier.value,
    tag: keyIdentifier.tag
  };
}

export function parseKeyUsage(value: Uint8Array): ParsedKeyUsage {
  const root = readElement(value);
  if (root.tag !== TAG.BIT_STRING || root.value.length < 2) {
    throw new Error("Invalid keyUsage payload");
  }

  const unusedBits = root.value[0]!;
  const bytes = root.value.subarray(1);
  const first = bytes[0] ?? 0;

  return {
    unusedBits,
    bytes,
    digitalSignature: (first & 0x80) !== 0,
    contentCommitment: (first & 0x40) !== 0,
    keyCertSign: (first & 0x04) !== 0,
    cRLSign: (first & 0x02) !== 0
  };
}

export function parseSubjectAltName(value: Uint8Array): ParsedSubjectAltName {
  const root = readElement(value);
  const dnsNames: string[] = [];
  const ipAddresses: Uint8Array[] = [];

  for (const name of readSequenceChildren(root)) {
    if (name.tag === 0x82) {
      dnsNames.push(asciiString(name.value));
    } else if (name.tag === 0x87) {
      ipAddresses.push(name.value);
    } else {
      throw new Error(`Unexpected subjectAltName tag ${name.tag}`);
    }
  }

  return { dnsNames, ipAddresses };
}

export function parseCertificateSerialNumber(der: Uint8Array): { value: bigint; bytes: Uint8Array } {
  const serialNumber = readTbsChild(der, 0);
  if (serialNumber.tag !== TAG.INTEGER) {
    throw new Error("Missing serialNumber");
  }

  return {
    value: decodeInteger(serialNumber.value),
    bytes: serialNumber.value
  };
}

export function parseCertificateValidity(der: Uint8Array): ParsedValidity {
  const validity = readTbsChild(der, 3);
  const [notBefore, notAfter] = readSequenceChildren(validity);
  if (!notBefore || !notAfter) {
    throw new Error("Missing validity times");
  }

  return {
    notBefore: parseDerTime(notBefore),
    notAfter: parseDerTime(notAfter)
  };
}

function readTbsChild(der: Uint8Array, indexWithoutVersion: number) {
  const certificate = readElement(der);
  const [tbs] = readSequenceChildren(certificate);
  if (!tbs) {
    throw new Error("Missing TBSCertificate");
  }

  const children = readSequenceChildren(tbs);
  const offset = children[0]?.tag === 0xa0 ? 1 : 0;
  const child = children[indexWithoutVersion + offset];
  if (!child) {
    throw new Error("Missing TBSCertificate child");
  }
  return child;
}

function parseDerTime(element: ReturnType<typeof readElement>): ParsedDerTime {
  const text = asciiString(element.value);
  if (element.tag === TAG.UTC_TIME) {
    return {
      tag: element.tag,
      text,
      date: parseUtcTime(text)
    };
  }

  if (element.tag === TAG.GENERALIZED_TIME) {
    return {
      tag: element.tag,
      text,
      date: parseGeneralizedTime(text)
    };
  }

  throw new Error("Invalid time tag");
}

function parseUtcTime(value: string): Date {
  const year = Number(value.slice(0, 2));
  return dateFromParts(year >= 50 ? 1900 + year : 2000 + year, value.slice(2));
}

function parseGeneralizedTime(value: string): Date {
  return dateFromParts(Number(value.slice(0, 4)), value.slice(4));
}

function dateFromParts(year: number, tail: string): Date {
  return new Date(Date.UTC(
    year,
    Number(tail.slice(0, 2)) - 1,
    Number(tail.slice(2, 4)),
    Number(tail.slice(4, 6)),
    Number(tail.slice(6, 8)),
    Number(tail.slice(8, 10))
  ));
}

function asciiString(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes);
}
