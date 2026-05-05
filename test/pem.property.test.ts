import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  certificateToPem,
  privateKeyDerToPem,
  publicKeyDerToPem,
  pemToDer,
  pemToDerWithLabel,
  splitPemBlocks
} from "../src/pem.js";

const nonEmptyBytes = fc.uint8Array({ minLength: 1, maxLength: 4096 });

describe("pem round-trip", () => {
  it("certificateToPem ↔ pemToDer", () => {
    fc.assert(
      fc.property(nonEmptyBytes, (der) => {
        expect(pemToDer(certificateToPem(der))).toEqual(der);
      })
    );
  });

  it("privateKeyDerToPem ↔ pemToDerWithLabel", () => {
    fc.assert(
      fc.property(nonEmptyBytes, (der) => {
        expect(pemToDerWithLabel(privateKeyDerToPem(der), "PRIVATE KEY")).toEqual(der);
      })
    );
  });

  it("publicKeyDerToPem ↔ pemToDerWithLabel", () => {
    fc.assert(
      fc.property(nonEmptyBytes, (der) => {
        expect(pemToDerWithLabel(publicKeyDerToPem(der), "PUBLIC KEY")).toEqual(der);
      })
    );
  });
});

describe("pem splitPemBlocks", () => {
  it("recovers each block from a concatenated stream", () => {
    fc.assert(
      fc.property(fc.array(nonEmptyBytes, { minLength: 1, maxLength: 4 }), (ders) => {
        const stream = ders.map((d) => certificateToPem(d)).join("");
        const blocks = splitPemBlocks(stream);
        expect(blocks.length).toBe(ders.length);
        blocks.forEach((block, i) => {
          expect(pemToDer(block)).toEqual(ders[i]);
        });
      })
    );
  });
});
