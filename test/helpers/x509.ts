import { bytesEqual } from "../../src/bytes.js";
import {
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
