import { arrayBufferFromBytes, concatBytes } from "./bytes.js";
import { integer, readChildren, readElement, sequence, TAG } from "./der.js";
import { pemToDerWithLabel, privateKeyDerToPem, publicKeyDerToPem } from "./pem.js";

const EC_ALGORITHM: EcKeyGenParams = {
  name: "ECDSA",
  namedCurve: "P-256"
};

const ECDSA_SIGN_ALGORITHM: EcdsaParams = {
  name: "ECDSA",
  hash: "SHA-256"
};

export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(EC_ALGORITHM, true, ["sign", "verify"]);
}

export async function signDer(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const raw = new Uint8Array(await crypto.subtle.sign(ECDSA_SIGN_ALGORITHM, privateKey, arrayBufferFromBytes(data)));
  return ecdsaRawToDer(raw);
}

export async function verifyDer(publicKey: CryptoKey, signatureDer: Uint8Array, data: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify(
    ECDSA_SIGN_ALGORITHM,
    publicKey,
    arrayBufferFromBytes(ecdsaDerToRaw(signatureDer)),
    arrayBufferFromBytes(data)
  );
}

export async function digestSha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", arrayBufferFromBytes(data)));
}

export async function keyIdentifierFromSpki(spki: Uint8Array): Promise<Uint8Array> {
  return digestSha256(spki);
}

export async function privateKeyToPem(key: CryptoKey): Promise<string> {
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key));
  return privateKeyDerToPem(der);
}

export async function publicKeyToPem(key: CryptoKey): Promise<string> {
  const der = new Uint8Array(await crypto.subtle.exportKey("spki", key));
  return publicKeyDerToPem(der);
}

export async function exportSpki(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("spki", key));
}

export async function importPrivateKeyPem(pem: string): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", arrayBufferFromBytes(pemToDerWithLabel(pem, "PRIVATE KEY")), EC_ALGORITHM, true, ["sign"]);
}

export async function keyPairFromPrivateKeyPem(pem: string): Promise<CryptoKeyPair> {
  const privateKey = await importPrivateKeyPem(pem);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  delete jwk.d;
  jwk.key_ops = ["verify"];
  const publicKey = await crypto.subtle.importKey("jwk", jwk, EC_ALGORITHM, true, ["verify"]);
  return { privateKey, publicKey };
}

export async function importPublicKeySpki(spki: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("spki", arrayBufferFromBytes(spki), EC_ALGORITHM, true, ["verify"]);
}

export async function assertKeyPairMatches(privateKey: CryptoKey, publicKey: CryptoKey): Promise<void> {
  const data = new TextEncoder().encode("edgca-key-pair-check");
  const signature = await signDer(privateKey, data);
  const ok = await verifyDer(publicKey, signature, data);

  if (!ok) {
    throw new Error("Private key does not match CA certificate public key");
  }
}

export function ecdsaRawToDer(raw: Uint8Array): Uint8Array {
  if (raw.length !== 64) {
    throw new Error("P-256 ECDSA raw signature must be 64 bytes");
  }

  return sequence(integer(raw.subarray(0, 32)), integer(raw.subarray(32)));
}

export function ecdsaDerToRaw(signature: Uint8Array): Uint8Array {
  const root = readElement(signature);
  if (root.tag !== TAG.SEQUENCE || root.end !== signature.length) {
    throw new Error("Invalid DER ECDSA signature");
  }

  const [r, s] = readChildren(root.value);
  if (!r || !s || r.tag !== TAG.INTEGER || s.tag !== TAG.INTEGER) {
    throw new Error("Invalid DER ECDSA signature integers");
  }

  return concatBytes([integerToFixedWidth(r.value), integerToFixedWidth(s.value)]);
}

function integerToFixedWidth(value: Uint8Array): Uint8Array {
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start += 1;
  }

  const trimmed = value.subarray(start);
  if (trimmed.length > 32) {
    throw new Error("ECDSA integer is wider than P-256");
  }

  const out = new Uint8Array(32);
  out.set(trimmed, 32 - trimmed.length);
  return out;
}
