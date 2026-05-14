import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import {
  exportPkcs12,
  pemToDer,
  pemToDerWithLabel,
  splitPemBlocks
} from "../../index.js";
import { requireString } from "../flags.js";
import { defaultPfxPath } from "../io.js";

export async function pemToPfxCommand(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      cert: { type: "string" },
      key: { type: "string" },
      chain: { type: "string" },
      out: { type: "string" },
      password: { type: "string" }
    },
    strict: true
  });

  const certPath = requireString(values.cert, "--cert");
  const keyPath = requireString(values.key, "--key");
  const password = requireString(values.password, "--password");
  const chainPath = values.chain;
  const outPath = values.out ?? defaultPfxPath(certPath);

  const [certPem, keyPem, chainPem] = await Promise.all([
    readFile(certPath, "utf8"),
    readFile(keyPath, "utf8"),
    chainPath ? readFile(chainPath, "utf8") : Promise.resolve("")
  ]);

  const certDer = pemToDer(certPem);
  const chainDer = chainPem
    ? splitPemBlocks(chainPem).map((block) => pemToDerWithLabel(block, "CERTIFICATE"))
    : [];
  const privateKey = pemToDerWithLabel(keyPem, "PRIVATE KEY");

  const pfx = await exportPkcs12({
    certDer,
    ...(chainDer.length > 0 ? { chainDer } : {}),
    privateKey,
    password: new TextEncoder().encode(password)
  });

  await writeFile(outPath, pfx);
  console.log(`wrote ${outPath}`);
}
