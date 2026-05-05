import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { encodeName } from "../src/name.js";
import { decodeOid, readChildren, readElement, TAG } from "../src/der.js";
import { SUBJECT_ATTRIBUTE_OIDS, SUBJECT_VALUE_LENGTH_LIMITS } from "../src/oids.js";
import type { ShortSubjectAttributeType, Subject } from "../src/types.js";

interface ParsedAttribute {
  oid: string;
  valueTag: number;
  value: string;
}

function parseEncodedName(der: Uint8Array): ParsedAttribute[] {
  const top = readElement(der);
  expect(top.tag).toBe(TAG.SEQUENCE);
  return readChildren(top.value).map((rdn) => {
    expect(rdn.tag).toBe(TAG.SET);
    const av = readElement(rdn.value);
    expect(av.tag).toBe(TAG.SEQUENCE);
    const [oidEl, valEl] = readChildren(av.value);
    if (!oidEl || !valEl) throw new Error("malformed AttributeTypeAndValue");
    return {
      oid: decodeOid(oidEl.value),
      valueTag: valEl.tag,
      value: new TextDecoder().decode(valEl.value)
    };
  });
}

const PRINTABLE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
const printableChar = fc.constantFrom(...PRINTABLE_CHARS.split(""));
const asciiChar = fc.integer({ min: 0x20, max: 0x7e }).map((c) => String.fromCodePoint(c));
// BMP, no surrogates, no DEL, no forbidden control/bidi chars rejected by encodeName.
const utf8Char = fc
  .integer({ min: 0x20, max: 0xffff })
  .filter((c) => c !== 0x7f)
  .filter((c) => c < 0xd800 || c > 0xdfff)
  .filter((c) => c !== 0x200e && c !== 0x200f)
  .filter((c) => !(c >= 0x202a && c <= 0x202e))
  .filter((c) => !(c >= 0x2066 && c <= 0x2069))
  .map((c) => String.fromCodePoint(c));

function valueArb(chars: fc.Arbitrary<string>, maxCodepoints: number) {
  return fc
    .array(chars, { minLength: 1, maxLength: maxCodepoints })
    .map((arr) => arr.join(""));
}

describe("name encodeName round-trip", () => {
  // UTF8String-encoded short types (everything except C and E).
  const utf8Types: ShortSubjectAttributeType[] = [
    "CN",
    "O",
    "OU",
    "ST",
    "L",
    "DC",
    "SERIALNUMBER",
    "STREET",
    "POSTALCODE",
    "TITLE",
    "GIVENNAME",
    "SURNAME",
    "UID"
  ];

  const utf8Attribute = fc
    .constantFrom(...utf8Types)
    .chain((type) =>
      valueArb(utf8Char, SUBJECT_VALUE_LENGTH_LIMITS[type]).map((value) => ({ type, value }))
    );

  it("UTF8String types preserve type, OID, and Unicode value", () => {
    fc.assert(
      fc.property(fc.array(utf8Attribute, { minLength: 1, maxLength: 4 }), (subject: Subject) => {
        const parsed = parseEncodedName(encodeName(subject));
        expect(parsed.length).toBe(subject.length);
        parsed.forEach((p, i) => {
          const attr = subject[i]!;
          expect(p.oid).toBe(SUBJECT_ATTRIBUTE_OIDS[attr.type as ShortSubjectAttributeType]);
          expect(p.valueTag).toBe(TAG.UTF8_STRING);
          expect(p.value).toBe(attr.value);
        });
      })
    );
  });

  it("C uses PrintableString and round-trips its character set", () => {
    const cAttribute = valueArb(printableChar, SUBJECT_VALUE_LENGTH_LIMITS.C).map((value) => ({
      type: "C" as const,
      value
    }));
    fc.assert(
      fc.property(cAttribute, (attr) => {
        const [parsed] = parseEncodedName(encodeName([attr]));
        expect(parsed!.oid).toBe(SUBJECT_ATTRIBUTE_OIDS.C);
        expect(parsed!.valueTag).toBe(TAG.PRINTABLE_STRING);
        expect(parsed!.value).toBe(attr.value);
      })
    );
  });

  it("E uses IA5String and round-trips ASCII", () => {
    const eAttribute = valueArb(asciiChar, SUBJECT_VALUE_LENGTH_LIMITS.E).map((value) => ({
      type: "E" as const,
      value
    }));
    fc.assert(
      fc.property(eAttribute, (attr) => {
        const [parsed] = parseEncodedName(encodeName([attr]));
        expect(parsed!.oid).toBe(SUBJECT_ATTRIBUTE_OIDS.E);
        expect(parsed!.valueTag).toBe(TAG.IA5_STRING);
        expect(parsed!.value).toBe(attr.value);
      })
    );
  });

  it("dotted-OID custom types pass through verbatim with UTF8String", () => {
    const dottedOid = fc
      .tuple(
        fc.integer({ min: 0, max: 2 }),
        fc.integer({ min: 0, max: 39 }),
        fc.array(fc.integer({ min: 0, max: 100000 }), { minLength: 1, maxLength: 4 })
      )
      .map(([a, b, rest]) => [a, b, ...rest].join("."));
    const attr = fc
      .tuple(dottedOid, valueArb(utf8Char, 256))
      .map(([type, value]) => ({ type: type as `${number}.${number}${string}`, value }));
    fc.assert(
      fc.property(attr, (a) => {
        const [parsed] = parseEncodedName(encodeName([a]));
        expect(parsed!.oid).toBe(a.type);
        expect(parsed!.valueTag).toBe(TAG.UTF8_STRING);
        expect(parsed!.value).toBe(a.value);
      })
    );
  });
});
