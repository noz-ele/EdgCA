import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  bitString,
  decodeInteger,
  decodeOid,
  generalizedTime,
  integer,
  octetString,
  oid,
  readChildren,
  readElement,
  sequence,
  TAG,
  utcTime,
  utf8String
} from "../src/der.js";

describe("der INTEGER", () => {
  it("round-trips non-negative bigint via integer/decodeInteger", () => {
    const max = (1n << 256n) - 1n;
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max }), (n) => {
        const decoded = decodeInteger(readElement(integer(n)).value);
        expect(decoded).toBe(n);
      })
    );
  });

  it("round-trips non-negative safe integers", () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: Number.MAX_SAFE_INTEGER }), (n) => {
        const decoded = decodeInteger(readElement(integer(n)).value);
        expect(decoded).toBe(BigInt(n));
      })
    );
  });

  it("normalizes raw bytes to the same value as their numeric reading", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), (bytes) => {
        const expected = bytes.reduce((acc, b) => (acc << 8n) | BigInt(b), 0n);
        const decoded = decodeInteger(readElement(integer(bytes)).value);
        expect(decoded).toBe(expected);
      })
    );
  });
});

describe("der OID", () => {
  const oidArb = fc
    .tuple(
      fc.integer({ min: 0, max: 2 }),
      fc.integer({ min: 0, max: 1_000_000 }),
      fc.array(fc.integer({ min: 0, max: 1_000_000 }), { maxLength: 8 })
    )
    .filter(([first, second]) => (first === 2 ? true : second <= 39))
    .map(([first, second, rest]) => [first, second, ...rest].join("."));

  it("round-trips via oid/decodeOid", () => {
    fc.assert(
      fc.property(oidArb, (s) => {
        const element = readElement(oid(s));
        expect(element.tag).toBe(TAG.OBJECT_IDENTIFIER);
        expect(decodeOid(element.value)).toBe(s);
      })
    );
  });

  it("handles joint-iso-itu-t arcs with second > 39", () => {
    fc.assert(
      fc.property(fc.integer({ min: 40, max: 1_000_000 }), (second) => {
        const s = `2.${second}`;
        expect(decodeOid(readElement(oid(s)).value)).toBe(s);
      })
    );
  });
});

describe("der length / TLV", () => {
  it("octetString preserves arbitrary value bytes through TLV framing", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 4096 }), (bytes) => {
        const element = readElement(octetString(bytes));
        expect(element.tag).toBe(TAG.OCTET_STRING);
        expect(element.length).toBe(bytes.length);
        expect(element.value).toEqual(bytes);
      })
    );
  });

  it("bitString preserves bytes and unusedBits", () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ maxLength: 256 }),
        fc.integer({ min: 0, max: 7 }),
        (bytes, unused) => {
          const element = readElement(bitString(bytes, unused));
          expect(element.tag).toBe(TAG.BIT_STRING);
          expect(element.value[0]).toBe(unused);
          expect(element.value.subarray(1)).toEqual(bytes);
        }
      )
    );
  });

  it("readChildren recovers a SEQUENCE of OCTET STRING children", () => {
    fc.assert(
      fc.property(
        fc.array(fc.uint8Array({ maxLength: 64 }), { minLength: 0, maxLength: 8 }),
        (parts) => {
          const seq = sequence(...parts.map((p) => octetString(p)));
          const outer = readElement(seq);
          const children = readChildren(outer.value);
          expect(children.length).toBe(parts.length);
          children.forEach((child, i) => {
            expect(child.tag).toBe(TAG.OCTET_STRING);
            expect(child.value).toEqual(parts[i]);
          });
        }
      )
    );
  });
});

describe("der length encoding boundaries", () => {
  // Cover short-form (<0x80), 1/2/3-byte long-form transitions where off-by-ones
  // in encodeLength/decodeLength tend to live. Bias toward boundary values; cap
  // the 3-byte form at 0x10010 so we exercise the path without timing out on
  // 64KB allocations.
  const lengthAroundBoundary = fc.oneof(
    fc.constantFrom(0, 1, 0x7f, 0x80, 0x81, 0xff, 0x100, 0x101, 0xffff, 0x10000, 0x10001),
    fc.integer({ min: 0, max: 0x7f }),
    fc.integer({ min: 0x80, max: 0xff }),
    fc.integer({ min: 0x100, max: 0xfff })
  );

  it("OCTET STRING preserves length and value across all length-form transitions", () => {
    fc.assert(
      fc.property(lengthAroundBoundary, (size) => {
        const value = new Uint8Array(size);
        for (let i = 0; i < size; i += 1) value[i] = i & 0xff;
        const element = readElement(octetString(value));
        expect(element.tag).toBe(TAG.OCTET_STRING);
        expect(element.length).toBe(size);
        expect(element.value).toEqual(value);
      }),
      { numRuns: 60 }
    );
  });
});

describe("der UTF8String", () => {
  // Codepoints in BMP, excluding surrogates (TextEncoder mangles lone halves)
  // and DEL. Range stays multi-byte-friendly to exercise UTF-8 length math.
  const utf8Codepoint = fc
    .integer({ min: 0x20, max: 0xffff })
    .filter((c) => c !== 0x7f)
    .filter((c) => c < 0xd800 || c > 0xdfff);
  const utf8Body = fc
    .array(utf8Codepoint, { minLength: 0, maxLength: 64 })
    .map((arr) => arr.map((c) => String.fromCodePoint(c)).join(""));

  it("round-trips arbitrary Unicode strings via UTF8String", () => {
    fc.assert(
      fc.property(utf8Body, (s) => {
        const element = readElement(utf8String(s));
        expect(element.tag).toBe(TAG.UTF8_STRING);
        expect(new TextDecoder().decode(element.value)).toBe(s);
      })
    );
  });
});

describe("der time year boundary", () => {
  const yearArb = fc.oneof(
    fc.integer({ min: 100, max: 9999 }),
    fc.constantFrom(1949, 1950, 1951, 2048, 2049, 2050)
  );

  const dateArb = yearArb.chain((year) =>
    fc
      .tuple(
        fc.integer({ min: 0, max: 11 }),
        fc.integer({ min: 1, max: 28 }),
        fc.integer({ min: 0, max: 23 }),
        fc.integer({ min: 0, max: 59 }),
        fc.integer({ min: 0, max: 59 })
      )
      .map(([month, day, h, m, s]) => {
        const d = new Date(0);
        d.setUTCFullYear(year, month, day);
        d.setUTCHours(h, m, s, 0);
        return d;
      })
  );

  it("utcTime tags as UTC_TIME inside [1950,2049] and falls back to GENERALIZED_TIME outside", () => {
    fc.assert(
      fc.property(dateArb, (date) => {
        const element = readElement(utcTime(date));
        const year = date.getUTCFullYear();
        if (year >= 1950 && year <= 2049) {
          expect(element.tag).toBe(TAG.UTC_TIME);
          expect(element.length).toBe(13);
        } else {
          expect(element.tag).toBe(TAG.GENERALIZED_TIME);
          expect(element.length).toBe(15);
        }
      })
    );
  });

  it("utcTime/generalizedTime preserve every encoded field at second resolution", () => {
    fc.assert(
      fc.property(dateArb, (date) => {
        const element = readElement(utcTime(date));
        const text = new TextDecoder().decode(element.value);
        expect(parseEncodedTime(text, element.tag).getTime()).toBe(date.getTime());
      })
    );
  });

  it("generalizedTime always uses 4-digit year regardless of value", () => {
    fc.assert(
      fc.property(dateArb, (date) => {
        const element = readElement(generalizedTime(date));
        expect(element.tag).toBe(TAG.GENERALIZED_TIME);
        const text = new TextDecoder().decode(element.value);
        const expectedYear = date.getUTCFullYear().toString().padStart(4, "0");
        expect(text.substring(0, 4)).toBe(expectedYear);
        expect(parseEncodedTime(text, element.tag).getTime()).toBe(date.getTime());
      })
    );
  });
});

describe("der OID base-128 component boundaries", () => {
  // Densely target sub-identifier byte-count transitions in encodeBase128.
  const boundaryComponent = fc.constantFrom(
    0,
    1,
    0x7f,
    0x80,
    0x81,
    0x3fff,
    0x4000,
    0x4001,
    0x1fffff,
    0x200000,
    0x200001,
    0xfffffff,
    0x10000000
  );

  it("round-trips trailing components at every base-128 byte transition", () => {
    fc.assert(
      fc.property(fc.array(boundaryComponent, { minLength: 1, maxLength: 6 }), (rest) => {
        // Prefix "2.999" forces the joint sub-id (= 1079) to cross the 7-bit
        // boundary too, so this exercises the joint encoder in tandem.
        const s = ["2", "999", ...rest.map((c) => c.toString())].join(".");
        const element = readElement(oid(s));
        expect(element.tag).toBe(TAG.OBJECT_IDENTIFIER);
        expect(decodeOid(element.value)).toBe(s);
      })
    );
  });

  it("round-trips boundary values in the joint first sub-identifier (first*40+second)", () => {
    // For first=2 the joint = 80 + second, so second values around the byte
    // boundaries land the joint exactly on 0x7f / 0x80 / 0x3fff / 0x4000.
    const secondAtJointBoundary = fc.constantFrom(
      0,
      0x7f - 80,
      0x80 - 80,
      0x81 - 80,
      0x3fff - 80,
      0x4000 - 80,
      0x4001 - 80
    );
    fc.assert(
      fc.property(secondAtJointBoundary, (second) => {
        const s = `2.${second}`;
        expect(decodeOid(readElement(oid(s)).value)).toBe(s);
      })
    );
  });
});

describe("der INTEGER canonical normalization", () => {
  it("re-encoding the canonical bytes is a fixed point", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), (bytes) => {
        const once = readElement(integer(bytes)).value;
        const twice = readElement(integer(once)).value;
        expect(twice).toEqual(once);
      })
    );
  });

  it("equivalent representations (extra leading zeros) collapse to the same DER", () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: (1n << 200n) - 1n }),
        fc.integer({ min: 0, max: 8 }),
        (n, leadingZeros) => {
          const canonical = readElement(integer(n)).value;
          const padded = new Uint8Array(canonical.length + leadingZeros);
          padded.set(canonical, leadingZeros);
          const renormalized = readElement(integer(padded)).value;
          expect(renormalized).toEqual(canonical);
          expect(decodeInteger(renormalized)).toBe(n);
        }
      )
    );
  });
});

describe("der INTEGER sign-bit padding boundary", () => {
  // Densely cover byte-count and sign-bit transitions: 0x80, 0x8000, 0x800000,
  // ... force a leading 0x00 padding byte to keep the value non-negative.
  const boundaryValue = fc.constantFrom<bigint>(
    0n,
    1n,
    0x7fn,
    0x80n,
    0x81n,
    0xffn,
    0x100n,
    0x7fffn,
    0x8000n,
    0x8001n,
    0xffffn,
    0x10000n,
    0x7fffffn,
    0x800000n,
    0xffffffn,
    0x1000000n,
    (1n << 63n) - 1n,
    1n << 63n,
    (1n << 64n) - 1n
  );

  it("encodes canonical TLV with sign-bit padding only when needed", () => {
    fc.assert(
      fc.property(boundaryValue, (n) => {
        const element = readElement(integer(n));
        expect(element.tag).toBe(TAG.INTEGER);
        expect(decodeInteger(element.value)).toBe(n);
        // Canonical: a leading 0x00 byte is allowed only when the next byte's
        // high bit is set (sign-bit guard).
        if (element.value.length >= 2 && element.value[0] === 0) {
          expect((element.value[1]! & 0x80) !== 0).toBe(true);
        }
      })
    );
  });
});

function parseEncodedTime(text: string, tag: number): Date {
  const date = new Date(0);
  if (tag === TAG.UTC_TIME) {
    const yy = parseInt(text.substring(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    date.setUTCFullYear(year, parseInt(text.substring(2, 4), 10) - 1, parseInt(text.substring(4, 6), 10));
    date.setUTCHours(
      parseInt(text.substring(6, 8), 10),
      parseInt(text.substring(8, 10), 10),
      parseInt(text.substring(10, 12), 10),
      0
    );
    return date;
  }
  date.setUTCFullYear(
    parseInt(text.substring(0, 4), 10),
    parseInt(text.substring(4, 6), 10) - 1,
    parseInt(text.substring(6, 8), 10)
  );
  date.setUTCHours(
    parseInt(text.substring(8, 10), 10),
    parseInt(text.substring(10, 12), 10),
    parseInt(text.substring(12, 14), 10),
    0
  );
  return date;
}
