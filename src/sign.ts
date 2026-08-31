import {
  componentSizeForCurve,
  curveOf,
  ecdsaRawToDer,
  signP1363
} from "./crypto.js";
import type { EcdsaSignatureFormat } from "./types.js";

export type { EcdsaSignatureFormat } from "./types.js";

export interface SignDataOptions {
  privateKey: CryptoKey;
  data: Uint8Array;
  signatureFormat: EcdsaSignatureFormat;
}

/**
 * Signs an arbitrary byte sequence with an ECDSA private key.
 *
 * This is a stateless cryptographic primitive. It does not construct a
 * challenge, canonicalize an HTTP message, persist replay state, or import
 * private-key files.
 */
export async function signData(options: SignDataOptions): Promise<Uint8Array> {
  assertObject(options, "options");
  if (!(options.data instanceof Uint8Array)) {
    throw new Error("data must be a Uint8Array");
  }
  if (options.signatureFormat !== "der" && options.signatureFormat !== "ieee-p1363") {
    throw new Error("signatureFormat must be der or ieee-p1363");
  }

  const privateKey = options.privateKey;
  if (!privateKey || typeof privateKey !== "object" || privateKey.type !== "private") {
    throw new Error("privateKey must be a private CryptoKey");
  }
  if (!privateKey.usages.includes("sign")) {
    throw new Error('privateKey usages must include "sign"');
  }

  const curve = curveOf(privateKey);
  const signatureP1363 = await signP1363(privateKey, options.data);
  if (options.signatureFormat === "ieee-p1363") {
    return signatureP1363;
  }

  try {
    return ecdsaRawToDer(signatureP1363, componentSizeForCurve(curve));
  } finally {
    signatureP1363.fill(0);
  }
}

function assertObject(value: unknown, name: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
}
