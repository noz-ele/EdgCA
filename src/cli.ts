#!/usr/bin/env node
import { createRootCaCommand } from "./cli/commands/create-root-ca.js";
import { issueClientCommand } from "./cli/commands/issue-client.js";
import { issueIntermediateCaCommand } from "./cli/commands/issue-intermediate-ca.js";
import { pemToPfxCommand } from "./cli/commands/pem-to-pfx.js";
import { signDataCommand } from "./cli/commands/sign-data.js";
import { UsageError } from "./cli/flags.js";

const USAGE = `Usage:
  edgca create-root-ca --subject <dn> [--days 3650] [--curve P-256] [--name root]

  edgca issue-intermediate-ca --ca-cert <pem> --ca-key <pem>
                              --subject <dn>
                              [--days 1825] [--curve P-256] [--name intermediate]

  edgca issue-client --ca-cert <pem> --ca-key <pem> [--ca-chain <pem>]
                     --subject <dn>
                     [--dns-name <name>]... [--ip <addr>]...
                     [--days 365] [--name client]

  edgca pem-to-pfx --cert <pem> --key <pem> --password <pw>
                   [--chain <pem>] [--out <pfx>]

  edgca sign-data --key <private-key.pem>
                  (--data-file <path> | --data-base64url <value>)
                  --signature-format <der|ieee-p1363>
`;

async function main(): Promise<void> {
  const [sub, ...rest] = process.argv.slice(2);

  switch (sub) {
    case "create-root-ca":
      await createRootCaCommand(rest);
      return;
    case "issue-intermediate-ca":
      await issueIntermediateCaCommand(rest);
      return;
    case "issue-client":
      await issueClientCommand(rest);
      return;
    case "pem-to-pfx":
      await pemToPfxCommand(rest);
      return;
    case "sign-data":
      await signDataCommand(rest);
      return;
    case undefined:
    case "-h":
    case "--help":
      process.stdout.write(USAGE);
      return;
    default:
      process.stderr.write(`unknown subcommand: ${sub}\n\n${USAGE}`);
      process.exitCode = 2;
      return;
  }
}

main().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`${message}\n`);
  process.exitCode = err instanceof UsageError ? 2 : 1;
});
