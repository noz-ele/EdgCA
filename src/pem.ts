import { binaryToBytes, bytesToBinary } from "./bytes.js";

const PEM_LINE_LENGTH = 64;

export function certificateToPem(der: Uint8Array): string {
  return encodePem("CERTIFICATE", der);
}

export function privateKeyDerToPem(der: Uint8Array): string {
  return encodePem("PRIVATE KEY", der);
}

export function publicKeyDerToPem(der: Uint8Array): string {
  return encodePem("PUBLIC KEY", der);
}

export function pemToDer(pem: string): Uint8Array {
  const match = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(pem);
  if (!match?.[1]) {
    throw new Error("Invalid PEM block");
  }

  const base64 = match[1].replace(/\s+/g, "");
  return binaryToBytes(atob(base64));
}

export function pemToDerWithLabel(pem: string, label: string): Uint8Array {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`-----BEGIN ${escaped}-----([\\s\\S]*?)-----END ${escaped}-----`);
  const match = pattern.exec(pem);
  if (!match?.[1]) {
    throw new Error(`Invalid PEM block: expected ${label}`);
  }

  const base64 = match[1].replace(/\s+/g, "");
  return binaryToBytes(atob(base64));
}

export function splitPemBlocks(pem: string): string[] {
  const blocks: string[] = [];
  const pattern = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(pem)) !== null) {
    blocks.push(match[0]);
  }

  return blocks;
}

function encodePem(label: string, der: Uint8Array): string {
  const base64 = btoa(bytesToBinary(der));
  const lines: string[] = [];

  for (let i = 0; i < base64.length; i += PEM_LINE_LENGTH) {
    lines.push(base64.slice(i, i + PEM_LINE_LENGTH));
  }

  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}
