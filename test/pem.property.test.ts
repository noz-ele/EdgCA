import { describe, expect, it } from "vitest";
import fc from "fast-check";
import {
  certificateToPem,
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

  it("certificateToPem ↔ pemToDerWithLabel CERTIFICATE", () => {
    fc.assert(
      fc.property(nonEmptyBytes, (der) => {
        expect(pemToDerWithLabel(certificateToPem(der), "CERTIFICATE")).toEqual(der);
      })
    );
  });
});

describe("pem line-length structure", () => {
  it("body lines are all exactly 64 chars except the last (≤64)", () => {
    fc.assert(
      fc.property(nonEmptyBytes, (der) => {
        const pem = certificateToPem(der);
        // certificateToPem ends with "\n", so split yields a trailing "" entry.
        const lines = pem.split("\n");
        expect(lines[0]).toBe("-----BEGIN CERTIFICATE-----");
        expect(lines[lines.length - 2]).toBe("-----END CERTIFICATE-----");
        expect(lines[lines.length - 1]).toBe("");
        const bodyLines = lines.slice(1, -2);
        expect(bodyLines.length).toBeGreaterThan(0);
        bodyLines.slice(0, -1).forEach((line) => {
          expect(line.length).toBe(64);
        });
        expect(bodyLines[bodyLines.length - 1]!.length).toBeGreaterThan(0);
        expect(bodyLines[bodyLines.length - 1]!.length).toBeLessThanOrEqual(64);
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

  it("recovers each block when arbitrary noise text is interleaved between blocks", () => {
    // Curated character set avoids "-" so noise can never spoof a BEGIN/END marker.
    const noiseChar = fc.constantFrom(
      ...("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n\r\t.,;:!?#").split("")
    );
    const noise = fc.array(noiseChar, { maxLength: 48 }).map((a) => a.join(""));
    const scenario = fc
      .array(nonEmptyBytes, { minLength: 1, maxLength: 4 })
      .chain((ders) =>
        fc
          .array(noise, { minLength: ders.length + 1, maxLength: ders.length + 1 })
          .map((noises) => ({ ders, noises }))
      );

    fc.assert(
      fc.property(scenario, ({ ders, noises }) => {
        const pems = ders.map((d) => certificateToPem(d));
        let stream = noises[0]!;
        pems.forEach((pem, i) => {
          stream += pem + noises[i + 1]!;
        });
        const blocks = splitPemBlocks(stream);
        expect(blocks.length).toBe(ders.length);
        blocks.forEach((block, i) => {
          expect(pemToDer(block)).toEqual(ders[i]);
        });
      })
    );
  });
});
