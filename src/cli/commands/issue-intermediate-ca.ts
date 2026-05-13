import { parseArgs } from "node:util";
import { generateKeyPair, issueIntermediateCA } from "../../index.js";
import { parseDnString } from "../dn.js";
import { parseCurveFlag, parseDaysFlag, requireString } from "../flags.js";
import { loadCaFromDisk, writeCaTriplet } from "../io.js";

export async function issueIntermediateCaCommand(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      "ca-cert": { type: "string" },
      "ca-key": { type: "string" },
      subject: { type: "string" },
      days: { type: "string", default: "1825" },
      curve: { type: "string", default: "P-256" },
      name: { type: "string", default: "intermediate" }
    },
    strict: true
  });

  const caCertPath = requireString(values["ca-cert"], "--ca-cert");
  const caKeyPath = requireString(values["ca-key"], "--ca-key");
  const subject = parseDnString(requireString(values.subject, "--subject"));
  const days = parseDaysFlag(values.days as string);
  const curve = parseCurveFlag(values.curve as string);
  const basename = values.name as string;

  const root = await loadCaFromDisk({ certPath: caCertPath, keyPath: caKeyPath });
  const keyPair = await generateKeyPair(curve);
  const intermediate = await issueIntermediateCA({ ca: root, subject, days, keyPair });

  const written = await writeCaTriplet(intermediate, ".", basename);
  console.log(`wrote ${written.certPath}`);
  console.log(`wrote ${written.keyPath}`);
  if (written.chainPath) console.log(`wrote ${written.chainPath}`);
}
