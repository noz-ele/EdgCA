import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  bitString,
  decodeInteger,
  decodeOid,
  integer,
  octetString,
  oid,
  readChildren,
  readElement,
  sequence,
  TAG
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
