import { sequence, set, oid, printableString, utf8String } from "./der.js";
import { SUBJECT_ATTRIBUTE_OIDS } from "./oids.js";
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
