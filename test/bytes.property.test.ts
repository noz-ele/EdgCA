import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  binaryToBytes,
  bytesEqual,
  bytesToBinary,
  cloneBytes,
  concatBytes
} from "../src/bytes.js";

describe("bytes concatBytes", () => {
  it("preserves total length", () => {
    fc.assert(
      fc.property(fc.array(fc.uint8Array({ maxLength: 64 }), { maxLength: 8 }), (parts) => {
        const total = parts.reduce((sum, p) => sum + p.length, 0);
        expect(concatBytes(parts).length).toBe(total);
      })
    );
  });

  it("preserves contents at the right offsets", () => {
    fc.assert(
      fc.property(fc.array(fc.uint8Array({ maxLength: 64 }), { maxLength: 8 }), (parts) => {
        const out = concatBytes(parts);
        let offset = 0;
        for (const part of parts) {
          expect(out.subarray(offset, offset + part.length)).toEqual(part);
          offset += part.length;
        }
      })
    );
  });
});

describe("bytes binaryToBytes / bytesToBinary", () => {
  it("round-trips arbitrary byte sequences", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 0x10000 + 17 }), (bytes) => {
        expect(binaryToBytes(bytesToBinary(bytes))).toEqual(bytes);
      })
    );
  });
});

describe("bytes bytesEqual", () => {
  it("is reflexive", () => {
    fc.assert(
      fc.property(fc.uint8Array(), (b) => {
        expect(bytesEqual(b, b)).toBe(true);
      })
    );
  });

  it("returns true iff contents match", () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 64 }), fc.uint8Array({ maxLength: 64 }), (a, b) => {
        const sameContent =
          a.length === b.length && a.every((byte, i) => byte === b[i]);
        expect(bytesEqual(a, b)).toBe(sameContent);
      })
    );
  });
});

describe("bytes cloneBytes", () => {
  it("produces an equal but independent copy", () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), (bytes) => {
        const copy = cloneBytes(bytes);
        expect(copy).toEqual(bytes);
        copy[0] = (copy[0]! + 1) & 0xff;
        expect(copy[0]).not.toBe(bytes[0]);
      })
    );
  });
});
