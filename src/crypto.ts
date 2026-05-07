import { arrayBufferFromBytes, concatBytes } from "./bytes.js";
import { decodeOid, integer, readChildren, readElement, readSequenceChildren, sequence, TAG } from "./der.js";
import { OID } from "./oids.js";

export type SupportedCurve = "P-256" | "P-384" | "P-521";

const CURVE_PROFILE: Record<SupportedCurve, {
  componentSize: number;
  hash: "SHA-256" | "SHA-384" | "SHA-512";
  signatureAlgorithmOid: string;
  curveOid: string;
}> = {
  "P-256": {
    componentSize: 32,
    hash: "SHA-256",
    signatureAlgorithmOid: OID.ecdsaWithSha256,
    curveOid: OID.secp256r1
  },
  "P-384": {
    componentSize: 48,
    hash: "SHA-384",
    signatureAlgorithmOid: OID.ecdsaWithSha384,
    curveOid: OID.secp384r1
  },
  "P-521": {
    componentSize: 66,
    hash: "SHA-512",
    signatureAlgorithmOid: OID.ecdsaWithSha512,
    curveOid: OID.secp521r1
  }
};

const CURVE_OID_TO_NAME: Record<string, SupportedCurve> = {
  [OID.secp256r1]: "P-256",
  [OID.secp384r1]: "P-384",
  [OID.secp521r1]: "P-521"
};

export function curveOf(key: CryptoKey): SupportedCurve {
  const algorithm = key.algorithm as { name?: string; namedCurve?: string };
  if (algorithm.name !== "ECDSA") {
    throw new Error(`Expected ECDSA key, got ${algorithm.name}`);
  }
  const curve = algorithm.namedCurve;
  if (curve !== "P-256" && curve !== "P-384" && curve !== "P-521") {
    throw new Error(`Unsupported ECDSA curve: ${curve}`);
  }
  return curve;
}

export function componentSizeForCurve(curve: SupportedCurve): number {
  return CURVE_PROFILE[curve].componentSize;
}

export function signatureAlgorithmOidForCurve(curve: SupportedCurve): string {
  return CURVE_PROFILE[curve].signatureAlgorithmOid;
}

export async function generateKeyPair(curve: SupportedCurve = "P-256"): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);
}

export async function signDer(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const curve = curveOf(privateKey);
  const profile = CURVE_PROFILE[curve];
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: profile.hash }, privateKey, arrayBufferFromBytes(data))
  );
  return ecdsaRawToDer(raw, profile.componentSize);
}

export async function verifyDer(publicKey: CryptoKey, signatureDer: Uint8Array, data: Uint8Array): Promise<boolean> {
  const curve = curveOf(publicKey);
  const profile = CURVE_PROFILE[curve];
  return crypto.subtle.verify(
    { name: "ECDSA", hash: profile.hash },
    publicKey,
    arrayBufferFromBytes(ecdsaDerToRaw(signatureDer, profile.componentSize)),
    arrayBufferFromBytes(data)
  );
}

export async function digestSha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", arrayBufferFromBytes(data)));
}

export async function digestSha1(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-1", arrayBufferFromBytes(data)));
}

// RFC 5280 §4.2.1.2 method (1): SHA-1 of the BIT STRING subjectPublicKey value,
// excluding the tag, length, and number of unused bits.
export async function keyIdentifierFromSpki(spki: Uint8Array): Promise<Uint8Array> {
  const root = readElement(spki);
  if (root.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid SubjectPublicKeyInfo");
  }
  const children = readSequenceChildren(root);
  const subjectPublicKey = children[1];
  if (!subjectPublicKey || subjectPublicKey.tag !== TAG.BIT_STRING || subjectPublicKey.value.length < 1) {
    throw new Error("Invalid SubjectPublicKeyInfo subjectPublicKey");
  }
  return digestSha1(subjectPublicKey.value.subarray(1));
}

export async function exportSpki(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("spki", key));
}

export async function importPublicKeySpki(spki: Uint8Array): Promise<CryptoKey> {
  const curve = curveFromSpki(spki);
  return crypto.subtle.importKey(
    "spki",
    arrayBufferFromBytes(spki),
    { name: "ECDSA", namedCurve: curve },
    true,
    ["verify"]
  );
}

// SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY }
// For EC keys, parameters is the named-curve OID.
function curveFromSpki(spki: Uint8Array): SupportedCurve {
  const root = readElement(spki);
  if (root.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid SubjectPublicKeyInfo");
  }
  const algorithm = readSequenceChildren(root)[0];
  if (!algorithm || algorithm.tag !== TAG.SEQUENCE) {
    throw new Error("Invalid SubjectPublicKeyInfo algorithm");
  }
  const algorithmChildren = readSequenceChildren(algorithm);
  const algorithmOidElement = algorithmChildren[0];
  const parametersElement = algorithmChildren[1];
  if (!algorithmOidElement || algorithmOidElement.tag !== TAG.OBJECT_IDENTIFIER) {
    throw new Error("Invalid SubjectPublicKeyInfo algorithm OID");
  }
  if (decodeOid(algorithmOidElement.value) !== OID.ecPublicKey) {
    throw new Error("SubjectPublicKeyInfo is not an EC public key");
  }
  if (!parametersElement || parametersElement.tag !== TAG.OBJECT_IDENTIFIER) {
    throw new Error("EC SubjectPublicKeyInfo parameters must be a named-curve OID");
  }
  const curveOid = decodeOid(parametersElement.value);
  const curve = CURVE_OID_TO_NAME[curveOid];
  if (!curve) {
    throw new Error(`Unsupported EC named curve OID: ${curveOid}`);
  }
  return curve;
}

export async function assertKeyPairMatches(privateKey: CryptoKey, publicKey: CryptoKey): Promise<void> {
  const data = new TextEncoder().encode("edgca-key-pair-check");
  const signature = await signDer(privateKey, data);
  const ok = await verifyDer(publicKey, signature, data);

  if (!ok) {
    throw new Error("Private key does not match CA certificate public key");
  }
}

export function ecdsaRawToDer(raw: Uint8Array, componentSize: number): Uint8Array {
  if (raw.length !== componentSize * 2) {
    throw new Error(`ECDSA raw signature must be ${componentSize * 2} bytes`);
  }

  return sequence(integer(raw.subarray(0, componentSize)), integer(raw.subarray(componentSize)));
}

export function ecdsaDerToRaw(signature: Uint8Array, componentSize: number): Uint8Array {
  const root = readElement(signature);
  if (root.tag !== TAG.SEQUENCE || root.end !== signature.length) {
    throw new Error("Invalid DER ECDSA signature");
  }

  const [r, s] = readChildren(root.value);
  if (!r || !s || r.tag !== TAG.INTEGER || s.tag !== TAG.INTEGER) {
    throw new Error("Invalid DER ECDSA signature integers");
  }

  return concatBytes([
    integerToFixedWidth(r.value, componentSize),
    integerToFixedWidth(s.value, componentSize)
  ]);
}

function integerToFixedWidth(value: Uint8Array, size: number): Uint8Array {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start += 1;
  }

  const trimmed = value.subarray(start);
  if (trimmed.length > size) {
    throw new Error(`ECDSA integer is wider than ${size} bytes`);
  }

  const out = new Uint8Array(size);
  out.set(trimmed, size - trimmed.length);
  return out;
}
