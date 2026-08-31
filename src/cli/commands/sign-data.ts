import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { signData } from "../../sign.js";
import { parseSignatureFormatFlag, requireString, UsageError } from "../flags.js";
import { importPkcs8PrivateKeyFromPem } from "../io.js";

export async function signDataCommand(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      key: { type: "string" },
      "data-file": { type: "string" },
      "data-base64url": { type: "string" },
      "signature-format": { type: "string" }
    },
    strict: true
  });

  const keyPath = requireString(values.key, "--key");
  const signatureFormat = parseSignatureFormatFlag(
    requireString(values["signature-format"], "--signature-format")
  );
  const hasDataFile = values["data-file"] !== undefined;
  const hasDataBase64Url = values["data-base64url"] !== undefined;
  if (hasDataFile === hasDataBase64Url) {
    throw new UsageError("exactly one of --data-file or --data-base64url is required");
  }

  // Validate inline data before starting file I/O so a malformed value always
  // produces the documented UsageError rather than racing a file-read error.
  const inlineData = hasDataBase64Url
    ? decodeUnpaddedBase64Url(
        requireString(values["data-base64url"], "--data-base64url")
      )
    : undefined;
  const [keyPem, fileData] = await Promise.all([
    readFile(keyPath, "utf8"),
    hasDataFile
      ? readFile(requireString(values["data-file"], "--data-file")).then(
          (bytes) => new Uint8Array(bytes)
        )
      : Promise.resolve(undefined)
  ]);
  const data = inlineData ?? fileData;
  if (!data) {
    throw new UsageError("exactly one of --data-file or --data-base64url is required");
  }

  const privateKey = await importPkcs8PrivateKeyFromPem(keyPem, false);
  const signature = await signData({ privateKey, data, signatureFormat });
  process.stdout.write(`${Buffer.from(signature).toString("base64url")}\n`);
}

function decodeUnpaddedBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new UsageError("--data-base64url must be non-empty unpadded base64url");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) {
    throw new UsageError("--data-base64url must use canonical unpadded base64url");
  }
  return new Uint8Array(bytes);
}
