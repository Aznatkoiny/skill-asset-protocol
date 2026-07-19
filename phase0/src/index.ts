import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

import { FileOperationJournal } from "./transactions";
import type { AttestationCommand, AttestationCommandOptions } from "./attestation-cli";
import { renderTopLevelError } from "./terminal";

const registrationsPath = fileURLToPath(new URL("../registrations.json", import.meta.url));
const pendingTransactionsPath = fileURLToPath(
  new URL("../pending-transactions.json", import.meta.url),
);

async function storyBoundary() {
  const [client, { StoryChain }] = await Promise.all([
    import("./client"),
    import("./story"),
  ]);
  return {
    account: client.getAccount(),
    chain: new StoryChain({
      sdk: client.getClient(),
      wallet: client.getWalletClient(),
      publicClient: client.getPublicClient(),
    }),
  };
}

async function check(): Promise<void> {
  const [{ buildCheckReport, renderCheckReport }, { FileRegistrationStore }, boundary] = await Promise.all([
    import("./check"),
    import("./registrations"),
    storyBoundary(),
  ]);
  const report = await buildCheckReport({
    wallet: boundary.account.address,
    chain: boundary.chain,
    store: new FileRegistrationStore(registrationsPath),
    journal: new FileOperationJournal(pendingTransactionsPath),
  });
  for (const line of renderCheckReport(report)) console.log(line);
}

async function demo(): Promise<void> {
  const [
    { runDemo },
    { HttpMetadataProvider },
    { FileRegistrationStore },
    boundary,
  ] = await Promise.all([
    import("./demo"),
    import("./metadata"),
    import("./registrations"),
    storyBoundary(),
  ]);
  const journal = new FileOperationJournal(pendingTransactionsPath);
  const manifest = await journal.withExclusiveLease((leasedJournal) => runDemo({
    wallet: boundary.account.address,
    chain: boundary.chain,
    metadata: new HttpMetadataProvider(),
    store: new FileRegistrationStore(registrationsPath),
    journal: leasedJournal,
  }));
  console.log("✓ Phase 0 wallet-attested registration status:", manifest.status);
  console.log("evidence level : wallet_asserted");
  console.log("scope          : wallet registration + declared Derivative ancestry; not authorship, originality, or safety");
  console.log("wallet        :", manifest.wallet);
  console.log("spgNftContract:", manifest.spgNftContract);
  for (const stage of ["root", "child", "grandchild"] as const) {
    const registration = manifest.registrations[stage];
    console.log(`${stage.padEnd(10)}:`, registration?.ipId ?? "not registered");
  }
  console.log("registration evidence artifact:", registrationsPath);
}

async function recoverStaleLock(expectedLeaseId: string): Promise<void> {
  const journal = new FileOperationJournal(pendingTransactionsPath);
  await journal.recoverStaleLock({ expectedLeaseId });
  console.log(`Recovered stale journal lock ${pendingTransactionsPath}.lock for lease ${expectedLeaseId}`);
}

export interface CommandDependencies {
  check(): Promise<void>;
  demo(): Promise<void>;
  recoverStaleLock(expectedLeaseId: string): Promise<void>;
  attestation?(command: AttestationCommand, options: AttestationCommandOptions): Promise<void>;
  log(line?: string): void;
}

const REAL_DEPENDENCIES: CommandDependencies = {
  check,
  demo,
  recoverStaleLock,
  attestation: async (command, options) => {
    const { executeAttestationCommand } = await import("./attestation-cli");
    await executeAttestationCommand(command, options);
  },
  log: (line = "") => console.log(line),
};

function printHelp(log: CommandDependencies["log"]): void {
  log("Phase 0 — wallet-attested Story Aeneid registration CLI");
  log();
  log("commands:");
  log("  npm run demo");
  log("  npm run check");
  log("  npm run recover-stale-lock -- <expectedLeaseId>");
  log("  npm run attestation-status -- [--artifact-hash <hash> | --registration-id <id>] [--json]");
  log("  npm run attestation-conflicts -- [--json]");
  log("  npm run attestation-verify-repository -- --bundle <absolute-path> [--json]");
  log("  npm run attestation-verify-organization -- --bundle <absolute-path> [--json]");
  log("  npm run attestation-append-challenge -- --bundle <absolute-path> [--json]");
  log("  npm run attestation-resolve -- --bundle <absolute-path> [--json]");
  log("  npm run attestation-revoke -- --bundle <absolute-path> [--json]");
  log("  npm run attestation-recover-lock -- --lock-token <exact-token> [--json]");
}

const ATTESTATION_COMMANDS = new Set<AttestationCommand>([
  "attestation-status",
  "attestation-verify-repository",
  "attestation-verify-organization",
  "attestation-append-challenge",
  "attestation-resolve",
  "attestation-conflicts",
  "attestation-revoke",
  "attestation-recover-lock",
]);

function hasOptions(options: AttestationCommandOptions): boolean {
  return Object.values(options).some((value) => value !== undefined && value !== false);
}

export async function runCommand(
  positionals: readonly string[],
  dependencies: CommandDependencies = REAL_DEPENDENCIES,
  options: AttestationCommandOptions = {},
): Promise<number> {
  const [command, ...args] = positionals;
  if (!command) {
    printHelp(dependencies.log);
    return 0;
  }
  if (command === "check") {
    if (args.length !== 0 || hasOptions(options)) throw new Error("Usage: npm run check");
    await dependencies.check();
    return 0;
  }
  if (command === "demo") {
    if (args.length !== 0 || hasOptions(options)) throw new Error("Usage: npm run demo");
    await dependencies.demo();
    return 0;
  }
  if (command === "recover-stale-lock") {
    if (args.length !== 1 || hasOptions(options)) {
      throw new Error("Usage: npm run recover-stale-lock -- <expectedLeaseId>");
    }
    if (!/^[0-9a-f]{32}$/.test(args[0])) {
      throw new Error("Usage: npm run recover-stale-lock -- <expectedLeaseId>");
    }
    await dependencies.recoverStaleLock(args[0]);
    dependencies.log(`Stale-lock recovery complete for lease ${args[0]}`);
    return 0;
  }
  if (ATTESTATION_COMMANDS.has(command as AttestationCommand)) {
    if (args.length !== 0) throw new Error(`Usage: npm run ${command} -- [options]`);
    const handler = dependencies.attestation ?? (async (selected, selectedOptions) => {
      const { executeAttestationCommand } = await import("./attestation-cli");
      await executeAttestationCommand(selected, selectedOptions, (line) => dependencies.log(line));
    });
    await handler(command as AttestationCommand, options);
    return 0;
  }
  printHelp(dependencies.log);
  return 1;
}

async function main(): Promise<void> {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    strict: true,
    options: {
      "artifact-hash": { type: "string" },
      "registration-id": { type: "string" },
      bundle: { type: "string" },
      "lock-token": { type: "string" },
      json: { type: "boolean", default: false },
    },
  });
  process.exitCode = await runCommand(positionals, REAL_DEPENDENCIES, {
    artifactHash: values["artifact-hash"],
    registrationId: values["registration-id"],
    bundle: values.bundle,
    lockToken: values["lock-token"],
    json: values.json,
  });
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main().catch((error) => {
    console.error(renderTopLevelError(error));
    process.exitCode = 1;
  });
}
