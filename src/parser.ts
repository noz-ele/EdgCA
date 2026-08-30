import { bytesEqual } from "./bytes.js";
import {
  decodeInteger,
  decodeOid,
  readElement,
  readSequenceChildren,
  TAG,
  type DerElement
} from "./der.js";
import { importPublicKeySpki } from "./crypto.js";
import { OID } from "./oids.js";

export interface ParsedKeyUsage {
  digitalSignature: boolean;
  contentCommitment: boolean;
  keyCertSign: boolean;
  cRLSign: boolean;
}

export interface ParsedCertificate {
  der: Uint8Array;
  tbsCertificateDer: Uint8Array;
  signatureDer: Uint8Array;
  signatureAlgorithmOid: string;
  tbsSignatureAlgorithmOid: string;
  signatureAlgorithmMatches: boolean;
  issuerNameDer: Uint8Array;
  subjectNameDer: Uint8Array;
  subjectPublicKeyInfoDer: Uint8Array;
  publicKey: CryptoKey;
  notBeforeMs?: number;
  notAfterMs?: number;
  basicConstraintsPresent: boolean;
  isCA: boolean;
  pathLenConstraint?: number;
  keyUsagePresent: boolean;
  keyUsage: ParsedKeyUsage;
  keyCertSign: boolean;
  extendedKeyUsagePresent: boolean;
  extendedKeyUsageOids: readonly string[];
  subjectKeyIdentifier?: Uint8Array;
  authorityKeyIdentifier?: Uint8Array;
  duplicateExtensionOids: readonly string[];
  unsupportedCriticalExtensionOids: readonly string[];
}

export interface ParsedCertificateForVerification extends ParsedCertificate {
  notBeforeMs: number;
  notAfterMs: number;
}

const EMPTY_KEY_USAGE: ParsedKeyUsage = {
  digitalSignature: false,
  contentCommitment: false,
  keyCertSign: false,
  cRLSign: false
};

const KNOWN_EXTENSION_OIDS = new Set<string>([
  OID.basicConstraints,
  OID.keyUsage,
  OID.extendedKeyUsage,
  OID.subjectKeyIdentifier,
  OID.authorityKeyIdentifier
]);

// Read just the SubjectPublicKeyInfo DER from a v3 X.509 certificate without
// importing the public key. Used by exportPkcs12, which needs the SPKI for
// localKeyId computation regardless of the inner key algorithm.
export function extractCertificateSpkiDer(der: Uint8Array): Uint8Array {
  const certificate = readElement(der);
  if (certificate.tag !== TAG.SEQUENCE || certificate.end !== der.length) {
    throw new Error("Invalid certificate DER");
  }
  const [tbsCertificate] = readSequenceChildren(certificate);
  if (!tbsCertificate) {
    throw new Error("Invalid certificate structure");
  }
  const tbsChildren = readSequenceChildren(tbsCertificate);
  assertV3(tbsChildren[0]);

  // tbsCertificate (v3) layout:
  //   [0] version [0] EXPLICIT INTEGER 2
  //   [1] serialNumber
  //   [2] signature (AlgorithmIdentifier)
  //   [3] issuer
  //   [4] validity
  //   [5] subject
  //   [6] subjectPublicKeyInfo
  const subjectPublicKeyInfo = tbsChildren[6];
  if (!subjectPublicKeyInfo || subjectPublicKeyInfo.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid certificate: missing subjectPublicKeyInfo");
  }
  return subjectPublicKeyInfo.raw;
}

// Compatibility parser used by issuance/import paths. It preserves the
// historical behavior for unusual-but-parseable imported certificates.
export async function parseCertificateDer(der: Uint8Array): Promise<ParsedCertificate> {
  // Await here (rather than returning the inner promise directly) so runtimes
  // with eager unhandled-rejection tracking observe this wrapper as the
  // rejection owner for synchronous parse failures.
  return await parseCertificateDerInternal(der, false);
}

// Strict parser used only by the public verification surface. It reads the
// certificate's own validity and rejects malformed X.509 structures while
// reporting policy failures (duplicates/unknown critical extensions) as data.
export async function parseCertificateDerForVerification(
  der: Uint8Array
): Promise<ParsedCertificateForVerification> {
  const parsed = await parseCertificateDerInternal(der, true);
  if (parsed.notBeforeMs === undefined || parsed.notAfterMs === undefined) {
    throw new Error("Invalid certificate validity");
  }
  return parsed as ParsedCertificateForVerification;
}

async function parseCertificateDerInternal(
  der: Uint8Array,
  strict: boolean
): Promise<ParsedCertificate> {
  const certificate = readElement(der);
  if (certificate.tag !== TAG.SEQUENCE || certificate.end !== der.length) {
    throw new Error("Invalid certificate DER");
  }

  const certificateChildren = readSequenceChildren(certificate);
  if (strict && certificateChildren.length !== 3) {
    throw new Error("Invalid certificate structure");
  }
  const [tbsCertificate, signatureAlgorithm, signatureValue] = certificateChildren;
  if (!tbsCertificate || !signatureAlgorithm || !signatureValue) {
    throw new Error("Invalid certificate structure");
  }
  if (tbsCertificate.tag !== TAG.SEQUENCE || signatureAlgorithm.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid certificate structure");
  }
  if (signatureValue.tag !== TAG.BIT_STRING || signatureValue.value.length < 1 || signatureValue.value[0] !== 0) {
    throw new Error("Invalid certificate signature value");
  }

  const tbsChildren = readSequenceChildren(tbsCertificate);
  assertV3(tbsChildren[0]);
  if (strict && tbsChildren.length < 7) {
    throw new Error("Invalid certificate TBSCertificate structure");
  }

  const tbsSignatureAlgorithm = tbsChildren[2];
  const issuer = tbsChildren[3];
  const validity = tbsChildren[4];
  const subject = tbsChildren[5];
  const subjectPublicKeyInfo = tbsChildren[6];
  if (
    !tbsSignatureAlgorithm || tbsSignatureAlgorithm.tag !== TAG.SEQUENCE ||
    !issuer || issuer.tag !== TAG.SEQUENCE ||
    !validity || validity.tag !== TAG.SEQUENCE ||
    !subject || subject.tag !== TAG.SEQUENCE ||
    !subjectPublicKeyInfo || subjectPublicKeyInfo.tag !== TAG.SEQUENCE
  ) {
    throw new Error("Invalid certificate TBSCertificate structure");
  }

  const signatureAlgorithmOid = parseAlgorithmIdentifier(signatureAlgorithm, strict);
  const tbsSignatureAlgorithmOid = parseAlgorithmIdentifier(tbsSignatureAlgorithm, strict);
  const extensionFields = tbsChildren.filter((element) => element.tag === 0xa3);
  if (strict && extensionFields.length > 1) {
    throw new Error("Invalid certificate: duplicate extensions field");
  }
  const parsedExtensions = extensionFields[0]
    ? parseExtensions(extensionFields[0].value, strict)
    : emptyParsedExtensions();
  const publicKey = await importPublicKeySpki(subjectPublicKeyInfo.raw);
  const parsedValidity = strict ? parseValidity(validity) : undefined;

  const parsed: ParsedCertificate = {
    der,
    tbsCertificateDer: tbsCertificate.raw,
    signatureDer: signatureValue.value.subarray(1),
    signatureAlgorithmOid,
    tbsSignatureAlgorithmOid,
    signatureAlgorithmMatches: bytesEqual(signatureAlgorithm.raw, tbsSignatureAlgorithm.raw),
    issuerNameDer: issuer.raw,
    subjectNameDer: subject.raw,
    subjectPublicKeyInfoDer: subjectPublicKeyInfo.raw,
    publicKey,
    basicConstraintsPresent: parsedExtensions.basicConstraintsPresent,
    isCA: parsedExtensions.isCA ?? false,
    keyUsagePresent: parsedExtensions.keyUsagePresent,
    keyUsage: parsedExtensions.keyUsage ?? { ...EMPTY_KEY_USAGE },
    keyCertSign: parsedExtensions.keyUsage?.keyCertSign ?? false,
    extendedKeyUsagePresent: parsedExtensions.extendedKeyUsagePresent,
    extendedKeyUsageOids: parsedExtensions.extendedKeyUsageOids ?? [],
    duplicateExtensionOids: parsedExtensions.duplicateExtensionOids,
    unsupportedCriticalExtensionOids: parsedExtensions.unsupportedCriticalExtensionOids
  };

  if (parsedValidity !== undefined) {
    parsed.notBeforeMs = parsedValidity.notBeforeMs;
    parsed.notAfterMs = parsedValidity.notAfterMs;
  }
  if (parsedExtensions.pathLenConstraint !== undefined) {
    parsed.pathLenConstraint = parsedExtensions.pathLenConstraint;
  }
  if (parsedExtensions.subjectKeyIdentifier !== undefined) {
    parsed.subjectKeyIdentifier = parsedExtensions.subjectKeyIdentifier;
  }
  if (parsedExtensions.authorityKeyIdentifier !== undefined) {
    parsed.authorityKeyIdentifier = parsedExtensions.authorityKeyIdentifier;
  }

  return parsed;
}

export function assertIssuerSubjectMatches(issuer: ParsedCertificate, issued: ParsedCertificate): void {
  if (!bytesEqual(issuer.subjectNameDer, issued.issuerNameDer)) {
    throw new Error("Issued certificate issuer does not match CA subject");
  }
}

interface ParsedExtensions {
  basicConstraintsPresent: boolean;
  isCA?: boolean;
  pathLenConstraint?: number;
  keyUsagePresent: boolean;
  keyUsage?: ParsedKeyUsage;
  extendedKeyUsagePresent: boolean;
  extendedKeyUsageOids?: string[];
  subjectKeyIdentifier?: Uint8Array;
  authorityKeyIdentifier?: Uint8Array;
  duplicateExtensionOids: string[];
  unsupportedCriticalExtensionOids: string[];
}

function emptyParsedExtensions(): ParsedExtensions {
  return {
    basicConstraintsPresent: false,
    keyUsagePresent: false,
    extendedKeyUsagePresent: false,
    duplicateExtensionOids: [],
    unsupportedCriticalExtensionOids: []
  };
}

function parseExtensions(explicitValue: Uint8Array, strict: boolean): ParsedExtensions {
  const outer = readElement(explicitValue);
  if (outer.tag !== TAG.SEQUENCE || (strict && outer.end !== explicitValue.length)) {
    throw new Error("Invalid extensions structure");
  }

  const parsed = emptyParsedExtensions();
  const seen = new Set<string>();

  for (const extension of readSequenceChildren(outer)) {
    const children = readSequenceChildren(extension);
    const oidElement = children[0];
    if (!oidElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid extension OID");
    }

    let valueIndex = 1;
    let critical = false;
    if (children[valueIndex]?.tag === TAG.BOOLEAN) {
      critical = parseBoolean(children[valueIndex]!, strict);
      valueIndex += 1;
    }

    const value = children[valueIndex];
    if (!value || value.tag !== TAG.OCTET_STRING || (strict && children.length !== valueIndex + 1)) {
      throw new Error("Invalid extension value");
    }

    const extensionOid = decodeOid(oidElement.value);
    if (seen.has(extensionOid) && !parsed.duplicateExtensionOids.includes(extensionOid)) {
      parsed.duplicateExtensionOids.push(extensionOid);
    }
    seen.add(extensionOid);

    if (critical && !KNOWN_EXTENSION_OIDS.has(extensionOid)) {
      parsed.unsupportedCriticalExtensionOids.push(extensionOid);
    }

    if (extensionOid === OID.basicConstraints) {
      parsed.basicConstraintsPresent = true;
      Object.assign(parsed, parseBasicConstraints(value.value, strict));
    } else if (extensionOid === OID.keyUsage) {
      parsed.keyUsagePresent = true;
      parsed.keyUsage = parseKeyUsage(value.value, strict);
    } else if (extensionOid === OID.extendedKeyUsage) {
      parsed.extendedKeyUsagePresent = true;
      parsed.extendedKeyUsageOids = parseExtendedKeyUsage(value.value, strict);
    } else if (extensionOid === OID.subjectKeyIdentifier) {
      parsed.subjectKeyIdentifier = parseOctetString(value.value, strict);
    } else if (extensionOid === OID.authorityKeyIdentifier) {
      const keyIdentifier = parseAuthorityKeyIdentifier(value.value, strict);
      if (keyIdentifier !== undefined) {
        parsed.authorityKeyIdentifier = keyIdentifier;
      }
    }
  }

  return parsed;
}

function parseAlgorithmIdentifier(element: DerElement, strict: boolean): string {
  const children = readSequenceChildren(element);
  const oidElement = children[0];
  if (!oidElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
    throw new Error("Invalid signature AlgorithmIdentifier");
  }
  if (strict && children.length !== 1) {
    throw new Error("ECDSA signature AlgorithmIdentifier must not have parameters");
  }
  return decodeOid(oidElement.value);
}

function parseValidity(validity: DerElement): { notBeforeMs: number; notAfterMs: number } {
  const children = readSequenceChildren(validity);
  if (children.length !== 2 || !children[0] || !children[1]) {
    throw new Error("Invalid certificate validity");
  }
  const notBeforeMs = parseDerTime(children[0]);
  const notAfterMs = parseDerTime(children[1]);
  if (notBeforeMs > notAfterMs) {
    throw new Error("Invalid certificate validity range");
  }
  return { notBeforeMs, notAfterMs };
}

function parseDerTime(element: DerElement): number {
  const text = asciiString(element.value, "certificate time");
  let year: number;
  let offset: number;

  if (element.tag === TAG.UTC_TIME) {
    if (!/^\d{12}Z$/.test(text)) {
      throw new Error("Invalid UTCTime");
    }
    const shortYear = Number(text.slice(0, 2));
    year = shortYear >= 50 ? 1900 + shortYear : 2000 + shortYear;
    offset = 2;
  } else if (element.tag === TAG.GENERALIZED_TIME) {
    if (!/^\d{14}Z$/.test(text)) {
      throw new Error("Invalid GeneralizedTime");
    }
    year = Number(text.slice(0, 4));
    if (year < 1 || year > 9999) {
      throw new Error("Invalid GeneralizedTime year");
    }
    offset = 4;
  } else {
    throw new Error("Unsupported certificate time type");
  }

  const month = Number(text.slice(offset, offset + 2));
  const day = Number(text.slice(offset + 2, offset + 4));
  const hour = Number(text.slice(offset + 4, offset + 6));
  const minute = Number(text.slice(offset + 6, offset + 8));
  const second = Number(text.slice(offset + 8, offset + 10));
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);

  if (
    month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 ||
    date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day || date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute || date.getUTCSeconds() !== second
  ) {
    throw new Error("Invalid certificate time value");
  }
  return date.getTime();
}

function parseBasicConstraints(
  value: Uint8Array,
  strict: boolean
): Pick<ParsedExtensions, "isCA" | "pathLenConstraint"> {
  const root = readElement(value);
  if (root.tag !== TAG.SEQUENCE || (strict && root.end !== value.length)) {
    throw new Error("Invalid basicConstraints extension");
  }
  const children = readSequenceChildren(root);
  const result: Pick<ParsedExtensions, "isCA" | "pathLenConstraint"> = { isCA: false };

  let index = 0;
  if (children[index]?.tag === TAG.BOOLEAN) {
    result.isCA = parseBoolean(children[index]!, strict);
    index += 1;
  }
  if (children[index]?.tag === TAG.INTEGER) {
    const decoded = decodeInteger(children[index]!.value);
    if (decoded > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("basicConstraints pathLenConstraint is too large");
    }
    result.pathLenConstraint = Number(decoded);
    index += 1;
  }
  if (strict && index !== children.length) {
    throw new Error("Invalid basicConstraints extension");
  }
  if (strict && result.pathLenConstraint !== undefined && result.isCA !== true) {
    throw new Error("basicConstraints pathLenConstraint requires CA=true");
  }
  return result;
}

function parseKeyUsage(value: Uint8Array, strict: boolean): ParsedKeyUsage {
  const root = readElement(value);
  if (root.tag !== TAG.BIT_STRING || root.value.length < 2 || (strict && root.end !== value.length)) {
    throw new Error("Invalid keyUsage extension");
  }
  const unusedBits = root.value[0]!;
  const bytes = root.value.subarray(1);
  if (unusedBits > 7) {
    throw new Error("Invalid keyUsage unused bits");
  }
  if (strict && unusedBits > 0 && (bytes[bytes.length - 1]! & ((1 << unusedBits) - 1)) !== 0) {
    throw new Error("Invalid keyUsage padding bits");
  }
  return {
    digitalSignature: keyUsageBit(bytes, 0),
    contentCommitment: keyUsageBit(bytes, 1),
    keyCertSign: keyUsageBit(bytes, 5),
    cRLSign: keyUsageBit(bytes, 6)
  };
}

function keyUsageBit(bytes: Uint8Array, bit: number): boolean {
  const byte = bytes[Math.floor(bit / 8)];
  return byte !== undefined && (byte & (0x80 >> (bit % 8))) !== 0;
}

function parseExtendedKeyUsage(value: Uint8Array, strict: boolean): string[] {
  const root = readElement(value);
  if (root.tag !== TAG.SEQUENCE || (strict && root.end !== value.length)) {
    throw new Error("Invalid extendedKeyUsage extension");
  }
  const children = readSequenceChildren(root);
  if (strict && children.length === 0) {
    throw new Error("extendedKeyUsage must contain at least one purpose");
  }
  return children.map((child) => {
    if (child.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid extendedKeyUsage purpose");
    }
    return decodeOid(child.value);
  });
}

function parseOctetString(value: Uint8Array, strict: boolean): Uint8Array {
  const root = readElement(value);
  if (root.tag !== TAG.OCTET_STRING || (strict && root.end !== value.length)) {
    throw new Error("Invalid OCTET STRING extension payload");
  }
  return root.value;
}

function parseAuthorityKeyIdentifier(value: Uint8Array, strict: boolean): Uint8Array | undefined {
  const root = readElement(value);
  if (root.tag !== TAG.SEQUENCE || (strict && root.end !== value.length)) {
    throw new Error("Invalid authorityKeyIdentifier extension");
  }
  let keyIdentifier: Uint8Array | undefined;
  for (const child of readSequenceChildren(root)) {
    if (child.tag === 0x80) {
      if (strict && keyIdentifier !== undefined) {
        throw new Error("Duplicate authorityKeyIdentifier keyIdentifier");
      }
      keyIdentifier = child.value;
    }
  }
  return keyIdentifier;
}

function parseBoolean(element: DerElement, strict: boolean): boolean {
  if (element.value.length !== 1) {
    throw new Error("Invalid BOOLEAN");
  }
  if (strict && element.value[0] !== 0x00 && element.value[0] !== 0xff) {
    throw new Error("Invalid DER BOOLEAN value");
  }
  return element.value[0] !== 0;
}

function assertV3(versionTag: DerElement | undefined): void {
  if (!versionTag || versionTag.tag !== 0xa0) {
    throw new Error("Unsupported X.509 version (only v3 is supported)");
  }
  const versionInner = readElement(versionTag.value);
  if (
    versionInner.tag !== TAG.INTEGER || versionInner.end !== versionTag.value.length ||
    decodeInteger(versionInner.value) !== 2n
  ) {
    throw new Error("Unsupported X.509 version (only v3 is supported)");
  }
}

function asciiString(bytes: Uint8Array, name: string): string {
  let out = "";
  for (const byte of bytes) {
    if (byte > 0x7f) {
      throw new Error(`Invalid non-ASCII ${name}`);
    }
    out += String.fromCharCode(byte);
  }
  return out;
}
