import type { Argv } from "yargs"
import { SlitherParseCommand } from "./slither-parse"
import { ImmunefiCommand } from "./immunefi"
import { TokenFlowCommand } from "./token-flow"
import { ExploitsCommand } from "./exploits"
import { PocCommand } from "./poc"
import { SnapshotCommand } from "./snapshot"
import { BackupCommand } from "./backup"
import { KbCommand } from "./kb"
import { ReportCommand } from "./report"

export const AuditCommand = {
  command: "audit-cli <subcommand>",
  describe: "audit CLIs: slither-parse, immunefi, token-flow, exploits, poc, snapshot, backup, kb, report",
  builder: (yargs: Argv) =>
    yargs
      .command(SlitherParseCommand as any)
      .command(ImmunefiCommand as any)
      .command(TokenFlowCommand as any)
      .command(ExploitsCommand as any)
      .command(PocCommand as any)
      .command(SnapshotCommand as any)
      .command(BackupCommand as any)
      .command(KbCommand as any)
      .command(ReportCommand as any)
      .demandCommand(),
  handler: () => {},
}

export {
  SlitherParseCommand,
  ImmunefiCommand,
  TokenFlowCommand,
  ExploitsCommand,
  PocCommand,
  SnapshotCommand,
  BackupCommand,
  KbCommand,
  ReportCommand,
}
