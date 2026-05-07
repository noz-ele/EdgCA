import { bytesToBinary } from "../../src/bytes.js";
import {
  componentSizeForCurve,
  curveOf,
  ecdsaRawToDer,
  exportSpki,
  signatureAlgorithmOidForCurve
} from "../../src/crypto.js";
import {
  bitString,
  der,
  ia5String,
  integer,
  octetString,
  oid,
  sequence,
  set
} from "../../src/der.js";
import { encodeName } from "../../src/name.js";
import { OID } from "../../src/oids.js";
import type { Subject } from "../../src/types.js";

const PEM_LINE_LENGTH = 64;

export interface CsrFixtureOptions {
  subject: Subject;
  keyPair: CryptoKeyPair;
  dnsNames?: string[];
  ipAddresses?: { v4?: number[]; v6?: number[] }[];
  // When provided, these raw extension entries are added to the
  // extensionRequest attribute in addition to (or instead of) SAN.
  extraExtensions?: { oid: string; critical: boolean; valueDer: Uint8Array }[];
  // Optional non-extensionRequest attributes (raw values).
  extraAttributes?: { oid: string; valuesDer: Uint8Array[] }[];
  // When provided, override the signature algorithm OID written into the CSR.
  signatureAlgorithmOid?: string;
}

export interface CsrFixture {
  der: Uint8Array;
  pem: string;
  legacyPem: string;
  certificationRequestInfoDer: Uint8Array;
  signatureDer: Uint8Array;
}

export async function buildCsrFixture(options: CsrFixtureOptions): Promise<CsrFixture> {
  const subjectNameDer = encodeName(options.subject);
  const spki = await exportSpki(options.keyPair.publicKey);
  const curve = curveOf(options.keyPair.privateKey);
  const componentSize = componentSizeForCurve(curve);
  const signatureAlgorithmOid = options.signatureAlgorithmOid ?? signatureAlgorithmOidForCurve(curve);

  const extensions: Uint8Array[] = [];
  if (options.dnsNames || options.ipAddresses) {
    extensions.push(buildSanExtension(options.dnsNames ?? [], options.ipAddresses ?? []));
  }
  for (const extraExtension of options.extraExtensions ?? []) {
    extensions.push(buildExtensionDer(extraExtension.oid, extraExtension.critical, extraExtension.valueDer));
  }

  const attributesContent: Uint8Array[] = [];
  if (extensions.length > 0) {
    attributesContent.push(
      sequence(
        oid(OID.extensionRequest),
        set(sequence(...extensions))
      )
    );
  }
  for (const attribute of options.extraAttributes ?? []) {
    attributesContent.push(
      sequence(
        oid(attribute.oid),
        set(...attribute.valuesDer)
      )
    );
  }

  const attributesField = der(0xa0, concat(attributesContent));

  const certificationRequestInfoDer = sequence(
    integer(0),
    subjectNameDer,
    spki,
    attributesField
  );

  const rawSignature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: hashForCurve(curve) },
      options.keyPair.privateKey,
      certificationRequestInfoDer
    )
  );
  const signatureDer = ecdsaRawToDer(rawSignature, componentSize);

  const csrDer = sequence(
    certificationRequestInfoDer,
    sequence(oid(signatureAlgorithmOid)),
    bitString(signatureDer)
  );

  return {
    der: csrDer,
    pem: derToPem("CERTIFICATE REQUEST", csrDer),
    legacyPem: derToPem("NEW CERTIFICATE REQUEST", csrDer),
    certificationRequestInfoDer,
    signatureDer
  };
}

function buildSanExtension(
  dnsNames: readonly string[],
  ipAddresses: readonly { v4?: number[]; v6?: number[] }[]
): Uint8Array {
  const generalNames: Uint8Array[] = [];
  for (const name of dnsNames) {
    generalNames.push(der(0x82, asciiBytes(name)));
  }
  for (const ip of ipAddresses) {
    if (ip.v4) {
      generalNames.push(der(0x87, new Uint8Array(ip.v4)));
    }
    if (ip.v6) {
      generalNames.push(der(0x87, new Uint8Array(ip.v6)));
    }
  }
  const sanValue = sequence(...generalNames);
  return buildExtensionDer(OID.subjectAltName, false, sanValue);
}

function buildExtensionDer(extensionOid: string, critical: boolean, valueDer: Uint8Array): Uint8Array {
  const fields: Uint8Array[] = [oid(extensionOid)];
  if (critical) {
    fields.push(new Uint8Array([0x01, 0x01, 0xff]));
  }
  fields.push(octetString(valueDer));
  return sequence(...fields);
}

function asciiBytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code > 0x7f) {
      throw new Error(`Non-ASCII character in CSR helper: ${value}`);
    }
    out[i] = code;
  }
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hashForCurve(curve: ReturnType<typeof curveOf>): "SHA-256" | "SHA-384" | "SHA-512" {
  if (curve === "P-256") return "SHA-256";
  if (curve === "P-384") return "SHA-384";
  return "SHA-512";
}

function derToPem(label: string, derBytes: Uint8Array): string {
  const base64 = btoa(bytesToBinary(derBytes));
  const lines: string[] = [];
  for (let i = 0; i < base64.length; i += PEM_LINE_LENGTH) {
    lines.push(base64.slice(i, i + PEM_LINE_LENGTH));
  }
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

// Re-exported for test convenience: caller can use ia5String inside extraExtensions if needed.
export { ia5String };
