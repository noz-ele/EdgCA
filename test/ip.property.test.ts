import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { encodeIpAddress } from "../src/ip.js";

describe("ip IPv4", () => {
  it("encodes any dotted-quad to its 4 raw octets", () => {
    fc.assert(
      fc.property(
        fc.tuple(
          fc.integer({ min: 0, max: 255 }),
          fc.integer({ min: 0, max: 255 }),
          fc.integer({ min: 0, max: 255 }),
          fc.integer({ min: 0, max: 255 })
        ),
        (octets) => {
          const encoded = encodeIpAddress(octets.join("."));
          expect(encoded).toEqual(new Uint8Array(octets));
        }
      )
    );
  });
});

describe("ip IPv6", () => {
  const groupArb = fc.integer({ min: 0, max: 0xffff });

  it("encodes full 8-group form to its 16 raw bytes", () => {
    fc.assert(
      fc.property(fc.array(groupArb, { minLength: 8, maxLength: 8 }), (groups) => {
        const text = groups.map((g) => g.toString(16)).join(":");
        const encoded = encodeIpAddress(text);
        const expected = new Uint8Array(16);
        groups.forEach((g, i) => {
          expected[i * 2] = g >> 8;
          expected[i * 2 + 1] = g & 0xff;
        });
        expect(encoded).toEqual(expected);
      })
    );
  });

  it("encodes :: compression to the same bytes as the expanded form", () => {
    const compressedArb = fc
      .tuple(
        fc.array(groupArb, { maxLength: 6 }),
        fc.array(groupArb, { maxLength: 6 }),
        fc.integer({ min: 2, max: 8 })
      )
      .filter(([left, right, zeros]) => left.length + right.length + zeros === 8)
      .map(([left, right]) => {
        const text = `${left.map((g) => g.toString(16)).join(":")}::${right
          .map((g) => g.toString(16))
          .join(":")}`;
        const groups = [
          ...left,
          ...new Array<number>(8 - left.length - right.length).fill(0),
          ...right
        ];
        const expected = new Uint8Array(16);
        groups.forEach((g, i) => {
          expected[i * 2] = g >> 8;
          expected[i * 2 + 1] = g & 0xff;
        });
        return { text, expected };
      });

    fc.assert(
      fc.property(compressedArb, ({ text, expected }) => {
        expect(encodeIpAddress(text)).toEqual(expected);
      })
    );
  });
});
