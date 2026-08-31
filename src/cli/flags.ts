import type { SupportedCurve } from "../index.js";
import type { EcdsaSignatureFormat } from "../types.js";

export class UsageError extends Error {
  override name = "UsageError";
}

// Accept only positive decimal integers with no leading zero, surrounding
// whitespace, sign, scientific notation, or fractional part. Number() is too
// permissive (it accepts " 365 ", "1e3", "0x10", "01", "1.0", and silently
// rounds beyond MAX_SAFE_INTEGER), which would let surprising values slip
// past CLI validation into the issuance API.
const POSITIVE_DECIMAL_INTEGER = /^[1-9]\d*$/;

export function parseDaysFlag(value: string): number {
  if (!POSITIVE_DECIMAL_INTEGER.test(value)) {
    throw new UsageError(`--days must be a positive decimal integer, got: ${JSON.stringify(value)}`);
  }
  const n = Number(value);
  if (!Number.isSafeInteger(n)) {
    throw new UsageError(`--days exceeds the safe integer range: ${value}`);
  }
  return n;
}

const SUPPORTED_CURVES: readonly SupportedCurve[] = ["P-256", "P-384", "P-521"];

export function parseCurveFlag(value: string): SupportedCurve {
  if ((SUPPORTED_CURVES as readonly string[]).includes(value)) {
    return value as SupportedCurve;
  }
  throw new UsageError(`--curve must be one of P-256, P-384, P-521 (got: ${value})`);
}

export function parseSignatureFormatFlag(value: string): EcdsaSignatureFormat {
  if (value === "der" || value === "ieee-p1363") {
    return value;
  }
  throw new UsageError(`--signature-format must be one of der, ieee-p1363 (got: ${value})`);
}

export function requireString(value: string | undefined, flagName: string): string {
  if (value === undefined || value === "") {
    throw new UsageError(`${flagName} is required`);
  }
  return value;
}
