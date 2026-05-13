import { parseArgs } from "node:util";
import { issueClientCert } from "../../index.js";
import { parseDnString } from "../dn.js";
import { parseDaysFlag, requireString } from "../flags.js";
import { loadCaFromDisk, writeIssuedLeafTriplet } from "../io.js";

export async function issueClientCommand(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      "ca-cert": { type: "string" },
      "ca-key": { type: "string" },
      "ca-chain": { type: "string" },
      subject: { type: "string" },
      "dns-name": { type: "string", multiple: true, default: [] },
      ip: { type: "string", multiple: true, default: [] },
      days: { type: "string", default: "365" },
      name: { type: "string", default: "client" }
    },
    strict: true
  });

  const caCertPath = requireString(values["ca-cert"], "--ca-cert");
  const caKeyPath = requireString(values["ca-key"], "--ca-key");
  const caChainPath = values["ca-chain"];
  const subject = parseDnString(requireString(values.subject, "--subject"));
  const days = parseDaysFlag(values.days as string);
  const basename = values.name as string;
  const dnsNames = values["dns-name"] as string[];
  const ipAddresses = values.ip as string[];

  const ca = await loadCaFromDisk({
    certPath: caCertPath,
    keyPath: caKeyPath,
    ...(caChainPath !== undefined ? { chainPath: caChainPath } : {})
  });

  const issued = await issueClientCert({
    ca,
    subject,
    days,
    ...(dnsNames.length > 0 ? { dnsNames } : {}),
    ...(ipAddresses.length > 0 ? { ipAddresses } : {})
  });

  const written = await writeIssuedLeafTriplet(issued, ".", basename);
  console.log(`wrote ${written.certPath}`);
  console.log(`wrote ${written.keyPath}`);
  if (written.chainPath) console.log(`wrote ${written.chainPath}`);
}
