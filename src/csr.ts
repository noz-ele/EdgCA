import { cloneBytes, concatBytes } from "./bytes.js";
import {
  curveOf,
  exportSpki,
  importPublicKeySpki,
  signDer,
  signatureAlgorithmOidForCurve,
  verifyDer
} from "./crypto.js";
import {
  bitString,
  decodeInteger,
  decodeOid,
  der,
  integer,
  oid,
  readChildren,
  readElement,
  readSequenceChildren,
  sequence,
  set,
  TAG,
  type DerElement
} from "./der.js";
import { encodeName } from "./name.js";
import { OID, SUBJECT_ATTRIBUTE_OIDS } from "./oids.js";
import { csrToPem, pemToDerWithLabel, splitPemBlocks } from "./pem.js";
import type { Subject, SubjectAttributeType } from "./types.js";
import { extension, subjectAltNameExtension } from "./x509.js";

const SHORT_NAME_BY_OID: Record<string, SubjectAttributeType> = Object.fromEntries(
  Object.entries(SUBJECT_ATTRIBUTE_OIDS).map(([shortName, oid]) => [oid, shortName as SubjectAttributeType])
);

const VALUE_DECODERS = new Map<number, (bytes: Uint8Array) => string>([
  [TAG.UTF8_STRING, (b) => new TextDecoder("utf-8", { fatal: true }).decode(b)],
  [TAG.PRINTABLE_STRING, (b) => decodeAscii(b, "PrintableString")],
  [TAG.IA5_STRING, (b) => decodeAscii(b, "IA5String")]
]);

const SUPPORTED_SIGNATURE_OIDS = new Set<string>([
  OID.ecdsaWithSha256,
  OID.ecdsaWithSha384,
  OID.ecdsaWithSha512
]);

export interface CertificateSigningRequestExtension {
  oid: string;
  critical: boolean;
  valueDer: Uint8Array;
}

export interface CertificateSigningRequestAttribute {
  oid: string;
  valuesDer: ReadonlyArray<Uint8Array>;
}

export interface ParsedCertificateSigningRequest {
  subject: Subject;
  publicKey: CryptoKey;
  subjectPublicKeyInfoDer: Uint8Array;
  requestedDnsNames: readonly string[];
  requestedIpAddresses: readonly string[];
  requestedExtensions: readonly CertificateSigningRequestExtension[];
  otherAttributes: readonly CertificateSigningRequestAttribute[];
  signatureAlgorithmOid: string;
  signatureDer: Uint8Array;
  certificationRequestInfoDer: Uint8Array;
}

export async function parseCertificateSigningRequest(
  input: string | Uint8Array
): Promise<ParsedCertificateSigningRequest> {
  const derBytes = typeof input === "string" ? csrPemToDer(input) : input;
  const root = readElement(derBytes);
  if (root.tag !== TAG.SEQUENCE || root.end !== derBytes.length) {
    throw new Error("Invalid CSR DER");
  }

  const [requestInfo, signatureAlgorithm, signatureValue] = readSequenceChildren(root);
  if (!requestInfo || !signatureAlgorithm || !signatureValue) {
    throw new Error("Invalid CSR structure");
  }
  if (requestInfo.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid CSR certificationRequestInfo");
  }
  if (signatureAlgorithm.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid CSR signatureAlgorithm");
  }
  if (signatureValue.tag !== TAG.BIT_STRING || signatureValue.value[0] !== 0) {
    throw new Error("Invalid CSR signature value");
  }

  const signatureAlgorithmOid = readAlgorithmOid(signatureAlgorithm);
  if (!SUPPORTED_SIGNATURE_OIDS.has(signatureAlgorithmOid)) {
    throw new Error(`Unsupported CSR signatureAlgorithm: ${signatureAlgorithmOid}`);
  }

  const infoChildren = readSequenceChildren(requestInfo);
  const versionElement = infoChildren[0];
  const subjectElement = infoChildren[1];
  const spkiElement = infoChildren[2];
  const attributesElement = infoChildren[3];
  if (!versionElement || !subjectElement || !spkiElement) {
    throw new Error("Invalid CSR certificationRequestInfo structure");
  }
  if (versionElement.tag !== TAG.INTEGER || decodeInteger(versionElement.value) !== 0n) {
    throw new Error("Unsupported CSR version (only v1 / INTEGER 0 is supported)");
  }
  if (spkiElement.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid CSR subjectPublicKeyInfo");
  }
  if (attributesElement && attributesElement.tag !== 0xa0) {
    throw new Error("Invalid CSR attributes tag (must be IMPLICIT [0])");
  }

  const subject = decodeName(subjectElement);
  const publicKey = await importPublicKeySpki(spkiElement.raw);

  const allAttributes = attributesElement ? decodeAttributes(attributesElement.value) : [];
  const extensionRequest = allAttributes.find((attribute) => attribute.oid === OID.extensionRequest);
  const otherAttributes = allAttributes.filter((attribute) => attribute.oid !== OID.extensionRequest);

  const requestedExtensions = extensionRequest
    ? decodeRequestedExtensions(extensionRequest.valuesDer)
    : [];

  const sanExtension = requestedExtensions.find((ext) => ext.oid === OID.subjectAltName);
  const { dnsNames, ipAddresses } = sanExtension
    ? decodeSubjectAltName(sanExtension.valueDer)
    : { dnsNames: [], ipAddresses: [] };

  return {
    subject,
    publicKey,
    subjectPublicKeyInfoDer: cloneBytes(spkiElement.raw),
    requestedDnsNames: dnsNames,
    requestedIpAddresses: ipAddresses,
    requestedExtensions,
    otherAttributes,
    signatureAlgorithmOid,
    signatureDer: cloneBytes(signatureValue.value.subarray(1)),
    certificationRequestInfoDer: cloneBytes(requestInfo.raw)
  };
}

export async function verifyCertificateSigningRequestSignature(
  csr: ParsedCertificateSigningRequest
): Promise<boolean> {
  return verifyDer(csr.publicKey, csr.signatureDer, csr.certificationRequestInfoDer);
}

export interface CreateCertificateSigningRequestInput {
  subject: Subject;
  keyPair: CryptoKeyPair;
  dnsNames?: readonly string[];
  ipAddresses?: readonly string[];
  extensions?: readonly CertificateSigningRequestExtension[];
}

export interface CreatedCertificateSigningRequest {
  der: Uint8Array;
  pem: string;
}

export async function createCertificateSigningRequest(
  input: CreateCertificateSigningRequestInput
): Promise<CreatedCertificateSigningRequest> {
  const privateCurve = curveOf(input.keyPair.privateKey);
  const publicCurve = curveOf(input.keyPair.publicKey);
  if (privateCurve !== publicCurve) {
    throw new Error("CSR keyPair private/public curve mismatch");
  }

  const subjectNameDer = encodeName(input.subject);
  const spki = await exportSpki(input.keyPair.publicKey);

  const requestedExtensions = collectRequestedExtensions(
    input.dnsNames,
    input.ipAddresses,
    input.extensions
  );

  const attributes: Uint8Array[] = [];
  if (requestedExtensions.length > 0) {
    attributes.push(
      sequence(
        oid(OID.extensionRequest),
        set(sequence(...requestedExtensions))
      )
    );
  }
  // CertificationRequestInfo.attributes is IMPLICIT [0] SET OF Attribute.
  // Wire form: tag 0xa0 wrapping the concatenated Attribute SEQUENCEs.
  const attributesField = der(0xa0, concatBytes(attributes));

  const certificationRequestInfoDer = sequence(
    integer(0),
    subjectNameDer,
    spki,
    attributesField
  );

  const signatureDer = await signDer(input.keyPair.privateKey, certificationRequestInfoDer);
  const signatureAlgorithmOid = signatureAlgorithmOidForCurve(privateCurve);

  const csrDer = sequence(
    certificationRequestInfoDer,
    sequence(oid(signatureAlgorithmOid)),
    bitString(signatureDer)
  );

  return {
    der: csrDer,
    pem: csrToPem(csrDer)
  };
}

function collectRequestedExtensions(
  dnsNames: readonly string[] | undefined,
  ipAddresses: readonly string[] | undefined,
  extraExtensions: readonly CertificateSigningRequestExtension[] | undefined
): Uint8Array[] {
  const seenOids = new Set<string>();
  const out: Uint8Array[] = [];

  const san = subjectAltNameExtension(dnsNames, ipAddresses);
  if (san) {
    seenOids.add(OID.subjectAltName);
    out.push(san);
  }

  for (const ext of extraExtensions ?? []) {
    if (seenOids.has(ext.oid)) {
      throw new Error(`Duplicate CSR extension OID: ${ext.oid}`);
    }
    seenOids.add(ext.oid);
    out.push(extension(ext.oid, ext.critical, ext.valueDer));
  }

  return out;
}


function csrPemToDer(pem: string): Uint8Array {
  // RFC 7468 §7 uses "CERTIFICATE REQUEST"; some legacy tools emit "NEW CERTIFICATE REQUEST".
  const blocks = splitPemBlocks(pem);
  for (const block of blocks) {
    const labelMatch = /-----BEGIN (.+?)-----/.exec(block);
    const label = labelMatch?.[1];
    if (label === "CERTIFICATE REQUEST" || label === "NEW CERTIFICATE REQUEST") {
      return pemToDerWithLabel(block, label);
    }
  }
  throw new Error("Invalid CSR PEM: expected CERTIFICATE REQUEST or NEW CERTIFICATE REQUEST block");
}

function readAlgorithmOid(algorithm: DerElement): string {
  const children = readSequenceChildren(algorithm);
  const oidElement = children[0];
  if (!oidElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
    throw new Error("Invalid AlgorithmIdentifier OID");
  }
  return decodeOid(oidElement.value);
}

function decodeName(nameElement: DerElement): Subject {
  if (nameElement.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid Name structure");
  }

  const subject: Subject = [];

  for (const rdn of readSequenceChildren(nameElement)) {
    if (rdn.tag !== TAG.SET) {
      throw new Error("Invalid RDN (expected SET)");
    }
    const attributes = readChildren(rdn.value);
    if (attributes.length !== 1) {
      throw new Error("Multi-valued RDNs are not supported");
    }
    const attribute = attributes[0]!;
    if (attribute.tag !== TAG.SEQUENCE) {
      throw new Error("Invalid AttributeTypeAndValue");
    }
    const [oidElement, valueElement] = readSequenceChildren(attribute);
    if (!oidElement || !valueElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid AttributeTypeAndValue contents");
    }
    const attributeOid = decodeOid(oidElement.value);
    const decoder = VALUE_DECODERS.get(valueElement.tag);
    if (!decoder) {
      throw new Error(`Unsupported AttributeValue string type: tag 0x${valueElement.tag.toString(16)}`);
    }
    const value = decoder(valueElement.value);
    const shortName = SHORT_NAME_BY_OID[attributeOid];
    subject.push({
      type: shortName ?? (attributeOid as SubjectAttributeType),
      value
    });
  }

  return subject;
}

function decodeAttributes(value: Uint8Array): CertificateSigningRequestAttribute[] {
  const attributes: CertificateSigningRequestAttribute[] = [];
  for (const attribute of readChildren(value)) {
    if (attribute.tag !== TAG.SEQUENCE) {
      throw new Error("Invalid CSR attribute");
    }
    const children = readSequenceChildren(attribute);
    const oidElement = children[0];
    const valuesElement = children[1];
    if (!oidElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid CSR attribute OID");
    }
    if (!valuesElement || valuesElement.tag !== TAG.SET) {
      throw new Error("Invalid CSR attribute values (expected SET)");
    }
    const valuesDer = readChildren(valuesElement.value).map((value) => cloneBytes(value.raw));
    attributes.push({
      oid: decodeOid(oidElement.value),
      valuesDer
    });
  }
  return attributes;
}

function decodeRequestedExtensions(
  valuesDer: ReadonlyArray<Uint8Array>
): CertificateSigningRequestExtension[] {
  if (valuesDer.length !== 1) {
    throw new Error("extensionRequest attribute must contain exactly one SEQUENCE OF Extension");
  }
  const outer = readElement(valuesDer[0]!);
  if (outer.tag !== TAG.SEQUENCE) {
    throw new Error("extensionRequest value must be a SEQUENCE OF Extension");
  }

  const extensions: CertificateSigningRequestExtension[] = [];
  for (const extension of readSequenceChildren(outer)) {
    if (extension.tag !== TAG.SEQUENCE) {
      throw new Error("Invalid Extension");
    }
    const children = readSequenceChildren(extension);
    const oidElement = children[0];
    if (!oidElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid Extension OID");
    }
    let cursor = 1;
    let critical = false;
    if (children[cursor]?.tag === TAG.BOOLEAN) {
      critical = children[cursor]!.value[0] !== 0;
      cursor += 1;
    }
    const valueElement = children[cursor];
    if (!valueElement || valueElement.tag !== TAG.OCTET_STRING) {
      throw new Error("Invalid Extension value");
    }
    extensions.push({
      oid: decodeOid(oidElement.value),
      critical,
      valueDer: cloneBytes(valueElement.value)
    });
  }
  return extensions;
}

function decodeSubjectAltName(value: Uint8Array): { dnsNames: string[]; ipAddresses: string[] } {
  const root = readElement(value);
  if (root.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid SubjectAltName extension");
  }
  const dnsNames: string[] = [];
  const ipAddresses: string[] = [];
  for (const generalName of readChildren(root.value)) {
    if (generalName.tag === 0x82) {
      dnsNames.push(decodeAscii(generalName.value, "SAN dNSName"));
    } else if (generalName.tag === 0x87) {
      ipAddresses.push(formatIpAddress(generalName.value));
    }
  }
  return { dnsNames, ipAddresses };
}

function decodeAscii(bytes: Uint8Array, label: string): string {
  for (const byte of bytes) {
    if (byte > 0x7f) {
      throw new Error(`${label} contains a non-ASCII byte`);
    }
  }
  return new TextDecoder("ascii").decode(bytes);
}

function formatIpAddress(bytes: Uint8Array): string {
  if (bytes.length === 4) {
    return Array.from(bytes).join(".");
  }
  if (bytes.length === 16) {
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
    }
    return compressIpv6(groups);
  }
  throw new Error(`Invalid SAN iPAddress length: ${bytes.length}`);
}

// RFC 5952: collapse the longest run of consecutive "0" groups (length ≥ 2) into "::".
function compressIpv6(groups: string[]): string {
  let bestStart = -1;
  let bestLength = 0;
  let currentStart = -1;
  let currentLength = 0;
  for (let i = 0; i < groups.length; i += 1) {
    if (groups[i] === "0") {
      if (currentStart === -1) {
        currentStart = i;
        currentLength = 0;
      }
      currentLength += 1;
      if (currentLength > bestLength) {
        bestStart = currentStart;
        bestLength = currentLength;
      }
    } else {
      currentStart = -1;
      currentLength = 0;
    }
  }
  if (bestLength < 2) {
    return groups.join(":");
  }
  const head = groups.slice(0, bestStart).join(":");
  const tail = groups.slice(bestStart + bestLength).join(":");
  return `${head}::${tail}`;
}
