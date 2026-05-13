import type { SupportedCurve } from "../index.js";

export class UsageError extends Error {
  override name = "UsageError";
}

export function parseDaysFlag(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) {
    throw new UsageError(`--days must be a positive integer, got: ${value}`);
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

export function requireString(value: string | undefined, flagName: string): string {
  if (value === undefined || value === "") {
    throw new UsageError(`${flagName} is required`);
  }
  return value;
}
