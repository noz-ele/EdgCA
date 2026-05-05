import { bytesEqual } from "./bytes.js";
import {
  decodeInteger,
  decodeOid,
  readChildren,
  readElement,
  readSequenceChildren,
  TAG
} from "./der.js";
import { importPublicKeySpki } from "./crypto.js";
import { OID } from "./oids.js";

export interface ParsedCertificate {
  der: Uint8Array;
  tbsCertificateDer: Uint8Array;
  signatureDer: Uint8Array;
  issuerNameDer: Uint8Array;
  subjectNameDer: Uint8Array;
  subjectPublicKeyInfoDer: Uint8Array;
  publicKey: CryptoKey;
  isCA: boolean;
  pathLenConstraint?: number;
  keyCertSign: boolean;
  subjectKeyIdentifier?: Uint8Array;
  authorityKeyIdentifier?: Uint8Array;
}

export async function parseCertificateDer(der: Uint8Array): Promise<ParsedCertificate> {
  const certificate = readElement(der);
  if (certificate.tag !== TAG.SEQUENCE || certificate.end !== der.length) {
    throw new Error("Invalid certificate DER");
  }

  const [tbsCertificate, signatureAlgorithm, signatureValue] = readSequenceChildren(certificate);
  if (!tbsCertificate || !signatureAlgorithm || !signatureValue) {
    throw new Error("Invalid certificate structure");
  }
  if (signatureValue.tag !== TAG.BIT_STRING || signatureValue.value[0] !== 0) {
    throw new Error("Invalid certificate signature value");
  }

  const tbsChildren = readSequenceChildren(tbsCertificate);
  // RFC 5280 §4.1.2.1: version is [0] EXPLICIT INTEGER. EdgCA only emits and
  // accepts v3 (= INTEGER 2); v1 (field omitted) and v2 (INTEGER 1) are rejected.
  // See docs/NON_GOALS.md §4.
  const versionTag = tbsChildren[0];
  if (!versionTag || versionTag.tag !== 0xa0) {
    throw new Error("Unsupported X.509 version (only v3 is supported)");
  }
  const versionInner = readElement(versionTag.value);
  if (versionInner.tag !== TAG.INTEGER || decodeInteger(versionInner.value) !== 2n) {
    throw new Error("Unsupported X.509 version (only v3 is supported)");
  }
  let index = 1;

  index += 1; // serialNumber
  index += 1; // signature
  const issuer = tbsChildren[index++];
  index += 1; // validity
  const subject = tbsChildren[index++];
  const subjectPublicKeyInfo = tbsChildren[index++];

  if (!issuer || !subject || !subjectPublicKeyInfo) {
    throw new Error("Invalid certificate TBSCertificate structure");
  }

  const extensions = tbsChildren.find((element) => element.tag === 0xa3);
  const parsedExtensions = extensions ? parseExtensions(extensions.value) : {};
  const publicKey = await importPublicKeySpki(subjectPublicKeyInfo.raw);

  const parsed: ParsedCertificate = {
    der,
    tbsCertificateDer: tbsCertificate.raw,
    signatureDer: signatureValue.value.subarray(1),
    issuerNameDer: issuer.raw,
    subjectNameDer: subject.raw,
    subjectPublicKeyInfoDer: subjectPublicKeyInfo.raw,
    publicKey,
    isCA: parsedExtensions.isCA ?? false,
    keyCertSign: parsedExtensions.keyCertSign ?? false
  };

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
  isCA?: boolean;
  pathLenConstraint?: number;
  keyCertSign?: boolean;
  subjectKeyIdentifier?: Uint8Array;
  authorityKeyIdentifier?: Uint8Array;
}

function parseExtensions(explicitValue: Uint8Array): ParsedExtensions {
  const outer = readElement(explicitValue);
  if (outer.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid extensions structure");
  }

  const parsed: ParsedExtensions = {};

  for (const extension of readSequenceChildren(outer)) {
    const children = readSequenceChildren(extension);
    const oidElement = children[0];
    if (!oidElement || oidElement.tag !== TAG.OBJECT_IDENTIFIER) {
      throw new Error("Invalid extension OID");
    }

    let valueIndex = 1;
    if (children[valueIndex]?.tag === TAG.BOOLEAN) {
      valueIndex += 1;
    }

    const value = children[valueIndex];
    if (!value || value.tag !== TAG.OCTET_STRING) {
      throw new Error("Invalid extension value");
    }

    const extensionOid = decodeOid(oidElement.value);
    if (extensionOid === OID.basicConstraints) {
      Object.assign(parsed, parseBasicConstraints(value.value));
    } else if (extensionOid === OID.keyUsage) {
      parsed.keyCertSign = parseKeyUsage(value.value).keyCertSign;
    } else if (extensionOid === OID.subjectKeyIdentifier) {
      parsed.subjectKeyIdentifier = parseOctetString(value.value);
    } else if (extensionOid === OID.authorityKeyIdentifier) {
      const keyIdentifier = parseAuthorityKeyIdentifier(value.value);
      if (keyIdentifier !== undefined) {
        parsed.authorityKeyIdentifier = keyIdentifier;
      }
    }
  }

  return parsed;
}

function parseBasicConstraints(value: Uint8Array): Pick<ParsedExtensions, "isCA" | "pathLenConstraint"> {
  const root = readElement(value);
  const children = readSequenceChildren(root);
  const result: Pick<ParsedExtensions, "isCA" | "pathLenConstraint"> = { isCA: false };

  if (children[0]?.tag === TAG.BOOLEAN) {
    result.isCA = children[0].value[0] !== 0;
  }

  const pathLen = children.find((child) => child.tag === TAG.INTEGER);
  if (pathLen) {
    result.pathLenConstraint = Number(decodeInteger(pathLen.value));
  }

  return result;
}

function parseKeyUsage(value: Uint8Array): { keyCertSign: boolean } {
  const root = readElement(value);
  if (root.tag !== TAG.BIT_STRING || root.value.length < 2) {
    throw new Error("Invalid keyUsage extension");
  }

  const bytes = root.value.subarray(1);
  return {
    keyCertSign: (bytes[0]! & 0x04) !== 0
  };
}

function parseOctetString(value: Uint8Array): Uint8Array {
  const root = readElement(value);
  if (root.tag !== TAG.OCTET_STRING) {
    throw new Error("Invalid OCTET STRING extension payload");
  }

  return root.value;
}

function parseAuthorityKeyIdentifier(value: Uint8Array): Uint8Array | undefined {
  const root = readElement(value);
  for (const child of readSequenceChildren(root)) {
    if (child.tag === 0x80) {
      return child.value;
    }
  }

  return undefined;
}
