import { parseArgs } from "node:util";
import { createRootCA, generateKeyPair } from "../../index.js";
import { parseDnString } from "../dn.js";
import { parseCurveFlag, parseDaysFlag, requireString } from "../flags.js";
import { writeCaTriplet } from "../io.js";

export async function createRootCaCommand(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      subject: { type: "string" },
      days: { type: "string", default: "3650" },
      curve: { type: "string", default: "P-256" },
      name: { type: "string", default: "root" }
    },
    strict: true
  });

  const subject = parseDnString(requireString(values.subject, "--subject"));
  const days = parseDaysFlag(values.days as string);
  const curve = parseCurveFlag(values.curve as string);
  const basename = values.name as string;

  const keyPair = await generateKeyPair(curve);
  const ca = await createRootCA({ subject, days, keyPair });

  const written = await writeCaTriplet(ca, ".", basename);
  console.log(`wrote ${written.certPath}`);
  console.log(`wrote ${written.keyPath}`);
}
