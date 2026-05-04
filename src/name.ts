import { sequence, set, oid, printableString, utf8String } from "./der.js";
import { MAX_SUBJECT_VALUE_LENGTH, SUBJECT_ATTRIBUTE_OIDS, SUBJECT_VALUE_LENGTH_LIMITS } from "./oids.js";
import type { ShortSubjectAttributeType, Subject, SubjectAttributeType } from "./types.js";

const SHORT_TYPES = new Set<string>(Object.keys(SUBJECT_ATTRIBUTE_OIDS));
const DOTTED_OID_PATTERN = /^(?:0|1|2)\.(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))+$/;

export function encodeName(subject: Subject): Uint8Array {
  if (!Array.isArray(subject) || subject.length === 0) {
    throw new Error("subject must be a non-empty array");
  }

  return sequence(
    ...subject.map((attribute, index) => {
      if (!attribute || typeof attribute !== "object") {
        throw new Error(`subject[${index}] must be an object with type and value`);
      }
      if (typeof attribute.type !== "string") {
        throw new Error(`subject[${index}].type must be a string`);
      }
      if (typeof attribute.value !== "string") {
        throw new Error(`subject[${index}].value must be a string`);
      }
      if (attribute.value.length === 0) {
        throw new Error(`subject[${index}].value must not be empty`);
      }
      if (containsForbiddenChar(attribute.value)) {
        throw new Error(`subject[${index}].value contains forbidden control or bidi character`);
      }
      const limit = SUBJECT_VALUE_LENGTH_LIMITS[attribute.type as ShortSubjectAttributeType] ?? MAX_SUBJECT_VALUE_LENGTH;
      const codepointLength = [...attribute.value].length;
      if (codepointLength > limit) {
        throw new Error(
          `subject[${index}].value exceeds ${limit} character limit for type "${attribute.type}"`
        );
      }
      const attributeOid = resolveAttributeOid(attribute.type);
      const value = attribute.type === "C" ? printableString(attribute.value) : utf8String(attribute.value);
      return set(sequence(oid(attributeOid), value));
    })
  );
}

export function resolveAttributeOid(type: SubjectAttributeType): string {
  if (SHORT_TYPES.has(type)) {
    return SUBJECT_ATTRIBUTE_OIDS[type as ShortSubjectAttributeType];
  }

  if (DOTTED_OID_PATTERN.test(type)) {
    return type;
  }

  throw new Error(`Unsupported subject attribute type: ${type}`);
}

// Reject C0 controls (U+0000-U+001F), DEL (U+007F), LTR/RTL marks (U+200E, U+200F),
// bidi embedding/override (U+202A-U+202E), and bidi isolates (U+2066-U+2069).
// Avoids embedding raw control characters in source for review safety.
function containsForbiddenChar(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return true;
    if (code === 0x200e || code === 0x200f) return true;
    if (code >= 0x202a && code <= 0x202e) return true;
    if (code >= 0x2066 && code <= 0x2069) return true;
  }
  return false;
}
