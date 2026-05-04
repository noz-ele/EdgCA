import { asciiBytes, concatBytes } from "./bytes.js";
import {
  bitString,
  boolean,
  contextPrimitive,
  der,
  explicit,
  generalizedTime,
  integer,
  octetString,
  oid,
  readElement,
  sequence,
  TAG,
  utcTime
} from "./der.js";
import { encodeIpAddress } from "./ip.js";
import { OID } from "./oids.js";
import type { SerialNumber } from "./types.js";

export interface CertificateBuildInput {
  serialNumber?: SerialNumber | undefined;
  notBefore?: Date | undefined;
  days: number;
  issuerNameDer: Uint8Array;
  subjectNameDer: Uint8Array;
  subjectPublicKeyInfoDer: Uint8Array;
  extensions: Uint8Array[];
}

export interface TbsCertificateResult {
  tbsCertificateDer: Uint8Array;
  serialNumberDer: Uint8Array;
  notBefore: Date;
  notAfter: Date;
}

export function buildTbsCertificate(input: CertificateBuildInput): TbsCertificateResult {
  const { notBefore, notAfter } = resolveValidity(input.notBefore, input.days);
  const serialNumberDer = encodeSerialNumber(input.serialNumber);
  const tbsCertificateDer = sequence(
    explicit(0, integer(2)),
    serialNumberDer,
    ecdsaWithSha256AlgorithmIdentifier(),
    input.issuerNameDer,
    sequence(encodeTime(notBefore), encodeTime(notAfter)),
    input.subjectNameDer,
    input.subjectPublicKeyInfoDer,
    explicit(3, sequence(...input.extensions))
  );

  return {
    tbsCertificateDer,
    serialNumberDer,
    notBefore,
    notAfter
  };
}

export function buildCertificate(tbsCertificateDer: Uint8Array, signatureDer: Uint8Array): Uint8Array {
  return sequence(tbsCertificateDer, ecdsaWithSha256AlgorithmIdentifier(), bitString(signatureDer));
}

export function ecdsaWithSha256AlgorithmIdentifier(): Uint8Array {
  return sequence(oid(OID.ecdsaWithSha256));
}

export function basicConstraintsExtension(ca: boolean, pathLenConstraint?: number): Uint8Array {
  if (pathLenConstraint !== undefined) {
    if (typeof pathLenConstraint !== "number" || !Number.isInteger(pathLenConstraint) || pathLenConstraint < 0) {
      throw new Error("pathLenConstraint must be a non-negative integer");
    }
  }

  const children = ca
    ? pathLenConstraint === undefined
      ? [boolean(true)]
      : [boolean(true), integer(pathLenConstraint)]
    : [];

  return extension(OID.basicConstraints, true, sequence(...children));
}

export function keyUsageExtension(usages: readonly KeyUsageBit[]): Uint8Array {
  let maxBit = 0;
  for (const usage of usages) {
    maxBit = Math.max(maxBit, KEY_USAGE_BITS[usage]);
  }

  const byteLength = Math.floor(maxBit / 8) + 1;
  const bytes = new Uint8Array(byteLength);

  for (const usage of usages) {
    const bit = KEY_USAGE_BITS[usage];
    bytes[Math.floor(bit / 8)]! |= 0x80 >> (bit % 8);
  }

  const unusedBits = byteLength * 8 - maxBit - 1;
  return extension(OID.keyUsage, true, bitString(bytes, unusedBits));
}

export function extendedKeyUsageClientAuthExtension(): Uint8Array {
  return extension(OID.extendedKeyUsage, false, sequence(oid(OID.clientAuth)));
}

export function subjectKeyIdentifierExtension(keyIdentifier: Uint8Array): Uint8Array {
  return extension(OID.subjectKeyIdentifier, false, octetString(keyIdentifier));
}

export function authorityKeyIdentifierExtension(keyIdentifier: Uint8Array): Uint8Array {
  return extension(OID.authorityKeyIdentifier, false, sequence(contextPrimitive(0, keyIdentifier)));
}

export function subjectAltNameExtension(dnsNames?: readonly string[], ipAddresses?: readonly string[]): Uint8Array | undefined {
  assertOptionalStringArray("dnsNames", dnsNames);
  assertOptionalStringArray("ipAddresses", ipAddresses);

  const names: Uint8Array[] = [];

  for (const dnsName of dnsNames ?? []) {
    if (typeof dnsName !== "string" || dnsName.length > 253 || !DNS_NAME_PATTERN.test(dnsName)) {
      throw new Error(`Invalid SAN dNSName: ${dnsName}`);
    }
    names.push(der(0x82, asciiBytes(dnsName)));
  }

  for (const ipAddress of ipAddresses ?? []) {
    if (typeof ipAddress !== "string") {
      throw new Error(`Invalid SAN iPAddress: ${ipAddress}`);
    }
    names.push(der(0x87, encodeIpAddress(ipAddress)));
  }

  return names.length > 0 ? extension(OID.subjectAltName, false, sequence(...names)) : undefined;
}

// RFC 1035 §2.3.1 preferred name syntax: each label starts and ends with [A-Za-z0-9],
// may contain hyphens internally, and is at most 63 characters. Optional leading "*." wildcard.
const DNS_LABEL = /[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?/;
const DNS_NAME_PATTERN = new RegExp(`^(\\*\\.)?${DNS_LABEL.source}(?:\\.${DNS_LABEL.source})*$`);

function assertOptionalStringArray(name: string, values: readonly string[] | undefined): void {
  if (values !== undefined && !Array.isArray(values)) {
    throw new Error(`${name} must be an array`);
  }
}

function extension(extensionOid: string, critical: boolean, valueDer: Uint8Array): Uint8Array {
  return sequence(
    oid(extensionOid),
    ...(critical ? [boolean(true)] : []),
    octetString(valueDer)
  );
}

function encodeSerialNumber(serialNumber?: SerialNumber): Uint8Array {
  const encoded = encodeSerialNumberDer(serialNumber);
  const element = readElement(encoded);
  if (element.length > 20) {
    throw new Error("serialNumber encoded value must not exceed 20 octets");
  }
  if (element.value.every((byte) => byte === 0)) {
    throw new Error("serialNumber must be a positive integer");
  }
  return encoded;
}

function encodeSerialNumberDer(serialNumber?: SerialNumber): Uint8Array {
  if (serialNumber === undefined) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[0] = (bytes[0] ?? 0) & 0x7f;
    if (bytes.every((byte) => byte === 0)) {
      bytes[15] = 1;
    }
    return integer(bytes);
  }

  if (serialNumber instanceof Uint8Array) {
    if (serialNumber.length === 0) {
      throw new Error("serialNumber Uint8Array must not be empty");
    }
    if (serialNumber.length > 20) {
      throw new Error("serialNumber Uint8Array must not exceed 20 octets");
    }
    return integer(serialNumber);
  }

  if (typeof serialNumber === "string") {
    if (/^\d+$/.test(serialNumber)) {
      if (serialNumber.length > SERIAL_NUMBER_MAX_DECIMAL_DIGITS) {
        throw new Error(
          `serialNumber decimal string must not exceed ${SERIAL_NUMBER_MAX_DECIMAL_DIGITS} digits`
        );
      }
      return integer(BigInt(serialNumber));
    }
    if (/^[0-9a-fA-F]+$/.test(serialNumber)) {
      if (serialNumber.length > SERIAL_NUMBER_MAX_HEX_CHARS) {
        throw new Error(
          `serialNumber hex string must not exceed ${SERIAL_NUMBER_MAX_HEX_CHARS} characters (20 octets)`
        );
      }
      const normalized = serialNumber.length % 2 === 0 ? serialNumber : `0${serialNumber}`;
      const bytes = new Uint8Array(normalized.length / 2);
      for (let i = 0; i < normalized.length; i += 2) {
        bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
      }
      return integer(bytes);
    }
    throw new Error("serialNumber string must be decimal digits or hex");
  }

  return integer(serialNumber);
}

const SERIAL_NUMBER_MAX_DECIMAL_DIGITS = 50;
const SERIAL_NUMBER_MAX_HEX_CHARS = 40;

function resolveValidity(notBeforeInput: Date | undefined, days: number): { notBefore: Date; notAfter: Date } {
  if (!Number.isFinite(days) || days <= 0) {
    throw new Error("days must be a positive number");
  }

  const notBefore = notBeforeInput === undefined ? new Date() : new Date(notBeforeInput);
  const notBeforeMs = notBefore.getTime();
  if (!Number.isFinite(notBeforeMs)) {
    throw new Error("notBefore must be a valid Date");
  }
  assertYearInRange(notBefore.getUTCFullYear(), "notBefore");

  const notAfterMs = notBeforeMs + days * 86_400_000;
  if (!Number.isFinite(notAfterMs)) {
    throw new Error("notAfter must be a valid Date");
  }
  const notAfter = new Date(notAfterMs);
  if (!Number.isFinite(notAfter.getTime())) {
    throw new Error("notAfter must be a valid Date");
  }
  assertYearInRange(notAfter.getUTCFullYear(), "notAfter");

  return {
    notBefore,
    notAfter
  };
}

function encodeTime(date: Date): Uint8Array {
  const year = date.getUTCFullYear();
  return year >= 1950 && year <= 2049 ? utcTime(date) : generalizedTime(date);
}

function assertYearInRange(year: number, fieldName: string): void {
  if (year < 1 || year > 9999) {
    throw new Error(`${fieldName} year must be between 0001 and 9999`);
  }
}

const KEY_USAGE_BITS = {
  digitalSignature: 0,
  keyCertSign: 5,
  cRLSign: 6
} as const;

type KeyUsageBit = keyof typeof KEY_USAGE_BITS;
