import { SUBJECT_ATTRIBUTE_OIDS } from "../oids.js";
import type {
  ShortSubjectAttributeType,
  Subject,
  SubjectAttribute,
  SubjectAttributeType
} from "../types.js";

const SHORT_NAMES = new Set<ShortSubjectAttributeType>(
  Object.keys(SUBJECT_ATTRIBUTE_OIDS) as ShortSubjectAttributeType[]
);

const DOTTED_OID = /^\d+(?:\.\d+)+$/;

export function parseDnString(input: string): Subject {
  const parts: SubjectAttribute[] = [];
  for (const raw of splitTopLevel(input, ",")) {
    const part = raw.trim();
    if (part === "") continue;
    const eq = part.indexOf("=");
    if (eq < 0) {
      throw new Error(`Invalid DN component (missing '='): ${part}`);
    }
    const rawKey = part.slice(0, eq).trim();
    const value = unescape(part.slice(eq + 1).trim());
    if (rawKey === "") throw new Error(`Invalid DN component (empty key): ${part}`);
    if (value === "") throw new Error(`Invalid DN component (empty value): ${part}`);
    const type = resolveAttributeType(rawKey);
    parts.push({ type, value });
  }
  if (parts.length === 0) {
    throw new Error("Subject is empty");
  }
  return parts;
}

function resolveAttributeType(raw: string): SubjectAttributeType {
  const upper = raw.toUpperCase();
  if (SHORT_NAMES.has(upper as ShortSubjectAttributeType)) {
    return upper as ShortSubjectAttributeType;
  }
  if (DOTTED_OID.test(raw)) {
    return raw as SubjectAttributeType;
  }
  throw new Error(`Unsupported DN attribute: ${raw}`);
}

function splitTopLevel(input: string, sep: string): string[] {
  const out: string[] = [];
  let current = "";
  let escaped = false;
  for (const ch of input) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === sep) {
      out.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  out.push(current);
  return out;
}

function unescape(value: string): string {
  return value.replace(/\\(.)/g, "$1");
}
