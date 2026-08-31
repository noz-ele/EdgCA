import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  arrayBufferFromBytes,
  bytesEqual,
  encodePem,
  importCertificateAuthority,
  pemToDer,
  pemToDerWithLabel,
  splitPemBlocks,
  type CertificateAuthority,
  type IssuedClientCertificate
} from "../index.js";

const EC_CURVES = ["P-256", "P-384", "P-521"] as const;
type EcCurve = (typeof EC_CURVES)[number];

export async function importPkcs8PrivateKeyFromPem(
  pem: string,
  extractable = true
): Promise<CryptoKey> {
  const der = pemToDerWithLabel(pem, "PRIVATE KEY");
  let lastError: unknown;
  try {
    for (const namedCurve of EC_CURVES) {
      const importBuffer = arrayBufferFromBytes(der);
      try {
        return await crypto.subtle.importKey(
          "pkcs8",
          importBuffer,
          { name: "ECDSA", namedCurve },
          extractable,
          ["sign"]
        );
      } catch (err) {
        lastError = err;
      } finally {
        new Uint8Array(importBuffer).fill(0);
      }
    }
    throw new Error(
      `Unable to import PRIVATE KEY as ECDSA P-256/P-384/P-521 PKCS#8: ${describe(lastError)}`
    );
  } finally {
    der.fill(0);
  }
}

export async function cryptoKeyToPkcs8Pem(key: CryptoKey): Promise<string> {
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key));
  return encodePem("PRIVATE KEY", der);
}

export interface WriteCaResult {
  certPath: string;
  keyPath: string;
  chainPath?: string;
}

export async function writeCaTriplet(
  ca: CertificateAuthority,
  outDir: string,
  basename: string
): Promise<WriteCaResult> {
  const certPath = path.join(outDir, `${basename}.crt.pem`);
  const keyPath = path.join(outDir, `${basename}.key.pem`);
  const keyPem = await cryptoKeyToPkcs8Pem(ca.privateKey);

  const writes: Promise<void>[] = [
    writeFile(certPath, ca.certPem, "utf8"),
    writeFile(keyPath, keyPem, "utf8")
  ];

  const hasChain = ca.issuerChainPem.trim().length > 0;
  const chainPath = hasChain ? path.join(outDir, `${basename}.chain.pem`) : undefined;
  if (hasChain && chainPath) {
    writes.push(writeFile(chainPath, ca.issuerChainPem, "utf8"));
  }

  await Promise.all(writes);
  return chainPath !== undefined
    ? { certPath, keyPath, chainPath }
    : { certPath, keyPath };
}

export async function writeIssuedLeafTriplet(
  issued: IssuedClientCertificate,
  outDir: string,
  basename: string
): Promise<WriteCaResult> {
  const certPath = path.join(outDir, `${basename}.crt.pem`);
  const keyPath = path.join(outDir, `${basename}.key.pem`);
  const chainPath = path.join(outDir, `${basename}.chain.pem`);
  const keyPem = await cryptoKeyToPkcs8Pem(issued.privateKey);

  // The library's `certChainPem` is a fullchain (leaf + issuers) suitable for
  // nginx-style server config. The CLI convention for `*.chain.pem` is the
  // issuer-only chain (no leaf), matching what `pem-to-pfx --chain` expects.
  // Strip the leaf out by DER match so the file faithfully represents an
  // issuer-only chain regardless of where the leaf sits in certChainPem.
  const issuerOnlyChainPem = stripLeafFromChain(issued.certPem, issued.certChainPem);

  await Promise.all([
    writeFile(certPath, issued.certPem, "utf8"),
    writeFile(keyPath, keyPem, "utf8"),
    writeFile(chainPath, issuerOnlyChainPem, "utf8")
  ]);

  return { certPath, keyPath, chainPath };
}

export function stripLeafFromChain(leafPem: string, chainPem: string): string {
  const leafDer = pemToDer(leafPem);
  const issuerBlocks = splitPemBlocks(chainPem).filter((block) => {
    const blockDer = pemToDerWithLabel(block, "CERTIFICATE");
    return !bytesEqual(blockDer, leafDer);
  });
  if (issuerBlocks.length === 0) return "";
  return issuerBlocks.join("\n") + "\n";
}

export interface LoadCaInput {
  certPath: string;
  keyPath: string;
  chainPath?: string;
}

export async function loadCaFromDisk(input: LoadCaInput): Promise<CertificateAuthority> {
  const [certPem, keyPem, chainPem] = await Promise.all([
    readFile(input.certPath, "utf8"),
    readFile(input.keyPath, "utf8"),
    input.chainPath ? readFile(input.chainPath, "utf8") : Promise.resolve("")
  ]);
  return importCertificateAuthority({
    certPem,
    privateKey: await importPkcs8PrivateKeyFromPem(keyPem),
    issuerChainPem: chainPem
  });
}

export function defaultPfxPath(certPath: string): string {
  const dir = path.dirname(certPath);
  const base = path
    .basename(certPath)
    .replace(/\.crt\.pem$/i, "")
    .replace(/\.pem$/i, "");
  return path.join(dir, `${base}.pfx`);
}

function describe(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
