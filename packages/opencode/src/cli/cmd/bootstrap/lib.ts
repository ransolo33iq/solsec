/**
 * solsec bootstrap — first-run provisioning.
 *
 * Embeds every security-related asset (subagents, semgrep ruleset, slash
 * commands, report templates, AGENTS.md preamble) directly into the binary
 * via Bun text imports, then writes them into the user's config dir on the
 * first run. The `solsec` middleware in src/index.ts checks the sentinel
 * file and triggers `bootstrap` automatically.
 *
 * Idempotent — re-running upgrades stale files only.
 */

import * as fs from "fs/promises"
import * as path from "path"
import { spawn } from "child_process"
import { Global } from "@solsec-ai/core/global"

// ── Embedded assets (text imports — Bun bakes the bytes into the binary) ────
import AGENTS_MD from "../../../../../../AGENTS.md" with { type: "text" }

// Subagents
import LANE_ROUTER from "../../../../../../.solsec/agent/lane-router.md" with { type: "text" }
import AUDITOR from "../../../../../../.solsec/agent/auditor.md" with { type: "text" }
import SLITHER_TRIAGE from "../../../../../../.solsec/agent/slither-triage.md" with { type: "text" }
import SEMGREP_RUNNER from "../../../../../../.solsec/agent/semgrep-runner.md" with { type: "text" }
import ACCESS_CONTROL from "../../../../../../.solsec/agent/access-control.md" with { type: "text" }
import FORK_TESTER from "../../../../../../.solsec/agent/fork-tester.md" with { type: "text" }
import TVL_SIZER from "../../../../../../.solsec/agent/tvl-sizer.md" with { type: "text" }
import SIBLING_HUNTER from "../../../../../../.solsec/agent/sibling-hunter.md" with { type: "text" }
import ORACLE_TRIAGE from "../../../../../../.solsec/agent/oracle-triage.md" with { type: "text" }
import BRIDGE_VALIDATOR from "../../../../../../.solsec/agent/bridge-validator.md" with { type: "text" }
import DONATION_ATTACK from "../../../../../../.solsec/agent/donation-attack.md" with { type: "text" }
import DEEP_READER from "../../../../../../.solsec/agent/deep-reader.md" with { type: "text" }
import COMPOSABILITY_PROBER from "../../../../../../.solsec/agent/composability-prober.md" with { type: "text" }
import ECONOMIC_FLAW_CHECKER from "../../../../../../.solsec/agent/economic-flaw-checker.md" with { type: "text" }
import INVARIANT_WRITER from "../../../../../../.solsec/agent/invariant-writer.md" with { type: "text" }
import HALMOS_PROVER from "../../../../../../.solsec/agent/halmos-prover.md" with { type: "text" }

// Slash commands
import AUDIT_CMD from "../../../../../../.solsec/command/audit.md" with { type: "text" }

// Templates
import REPORT_IMMUNEFI from "../../../../../../.solsec/templates/report-immunefi.md" with { type: "text" }
import REPORT_C4 from "../../../../../../.solsec/templates/report-c4.md" with { type: "text" }
import REPORT_PRE_DEPLOY from "../../../../../../.solsec/templates/report-pre-deploy.md" with { type: "text" }
import POC_TMPL from "../../../../../../.solsec/templates/poc.t.sol.tmpl" with { type: "text" }

// Semgrep ruleset
import SEMGREP_RULES from "../../../../../../.solsec/semgrep/solidity/rules.yml" with { type: "text" }

const BUNDLE_VERSION = "1"

interface AssetEntry {
  /** Path relative to the user's solsec config dir (~/.config/solsec/). */
  rel: string
  body: string
  /** True when the user is allowed to edit it without us re-overwriting on bootstrap. */
  userEditable?: boolean
}

const ASSETS: AssetEntry[] = [
  { rel: "AGENTS.md", body: AGENTS_MD, userEditable: true },

  { rel: "agent/lane-router.md", body: LANE_ROUTER },
  { rel: "agent/auditor.md", body: AUDITOR },
  { rel: "agent/slither-triage.md", body: SLITHER_TRIAGE },
  { rel: "agent/semgrep-runner.md", body: SEMGREP_RUNNER },
  { rel: "agent/access-control.md", body: ACCESS_CONTROL },
  { rel: "agent/fork-tester.md", body: FORK_TESTER },
  { rel: "agent/tvl-sizer.md", body: TVL_SIZER },
  { rel: "agent/sibling-hunter.md", body: SIBLING_HUNTER },
  { rel: "agent/oracle-triage.md", body: ORACLE_TRIAGE },
  { rel: "agent/bridge-validator.md", body: BRIDGE_VALIDATOR },
  { rel: "agent/donation-attack.md", body: DONATION_ATTACK },
  { rel: "agent/deep-reader.md", body: DEEP_READER },
  { rel: "agent/composability-prober.md", body: COMPOSABILITY_PROBER },
  { rel: "agent/economic-flaw-checker.md", body: ECONOMIC_FLAW_CHECKER },
  { rel: "agent/invariant-writer.md", body: INVARIANT_WRITER },
  { rel: "agent/halmos-prover.md", body: HALMOS_PROVER },

  { rel: "command/audit.md", body: AUDIT_CMD },

  { rel: "templates/report-immunefi.md", body: REPORT_IMMUNEFI, userEditable: true },
  { rel: "templates/report-c4.md", body: REPORT_C4, userEditable: true },
  { rel: "templates/report-pre-deploy.md", body: REPORT_PRE_DEPLOY, userEditable: true },
  { rel: "templates/poc.t.sol.tmpl", body: POC_TMPL, userEditable: true },

  { rel: "semgrep/solidity/rules.yml", body: SEMGREP_RULES, userEditable: true },
]

const SENTINEL_REL = ".bootstrap-state.json"

interface BootstrapState {
  version: string
  bundle_version: string
  bootstrapped_at: string
  doctor_done?: string
  kb_done?: string
}

function configRoot(): string {
  return Global.Path.config
}

function sentinelPath(): string {
  return path.join(configRoot(), SENTINEL_REL)
}

async function readState(): Promise<BootstrapState | undefined> {
  try {
    return JSON.parse(await fs.readFile(sentinelPath(), "utf8")) as BootstrapState
  } catch {
    return undefined
  }
}

async function writeState(state: BootstrapState): Promise<void> {
  await fs.mkdir(configRoot(), { recursive: true })
  await fs.writeFile(sentinelPath(), JSON.stringify(state, null, 2))
}

/**
 * `needsBootstrap` is the cheap precheck used by the launch middleware.
 * Returns true when the sentinel doesn't exist OR when bundle version drifted.
 */
export async function needsBootstrap(): Promise<boolean> {
  const state = await readState()
  if (!state) return true
  if (state.bundle_version !== BUNDLE_VERSION) return true
  return false
}

/**
 * Provision embedded assets into the user's solsec config dir.
 * Re-runs are idempotent: writes only when stale (sha mismatch on
 * non-user-editable files; existence-only check for user-editable ones).
 */
export async function provisionAssets(opts: { force?: boolean } = {}): Promise<{
  written: string[]
  skipped: string[]
}> {
  const root = configRoot()
  const written: string[] = []
  const skipped: string[] = []
  for (const a of ASSETS) {
    const dst = path.join(root, a.rel)
    await fs.mkdir(path.dirname(dst), { recursive: true })
    let existing: string | undefined
    try {
      existing = await fs.readFile(dst, "utf8")
    } catch {}
    if (!opts.force && existing !== undefined) {
      // user-editable: never overwrite once present.
      if (a.userEditable) {
        skipped.push(a.rel)
        continue
      }
      // managed file: only overwrite if content drifted from the bundle.
      if (existing === a.body) {
        skipped.push(a.rel)
        continue
      }
    }
    await fs.writeFile(dst, a.body)
    written.push(a.rel)
  }
  return { written, skipped }
}

function runProc(cmd: string, args: string[], onLine?: (s: string) => void): Promise<number> {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { env: process.env })
    const handle = (s: Buffer) => {
      const lines = s.toString().split(/\r?\n/)
      for (const line of lines) if (line) onLine?.(line)
    }
    proc.stdout?.on("data", handle)
    proc.stderr?.on("data", handle)
    proc.on("error", () => resolve(127))
    proc.on("close", (code) => resolve(code ?? 1))
  })
}

interface BootstrapOpts {
  /** Skip `solsec doctor install` (e.g. unit tests). */
  skipDoctor?: boolean
  /** Skip `solsec kb update`. */
  skipKb?: boolean
  /** Force re-write all assets. */
  force?: boolean
  /** Print progress to stderr. */
  verbose?: boolean
}

/**
 * Full first-run flow: provision files → install required tools → refresh KB.
 * Marks the sentinel only when each phase is OK so a partial failure retries
 * just the failing phase next time.
 */
export async function bootstrap(opts: BootstrapOpts = {}): Promise<{
  written: string[]
  skipped: string[]
  doctorOk: boolean
  kbOk: boolean
}> {
  const log = (line: string) => {
    if (opts.verbose) process.stderr.write(line + "\n")
  }

  // 1) Files
  log("solsec: provisioning agents, templates, and rulesets…")
  const fileResult = await provisionAssets({ force: opts.force })
  if (opts.verbose) {
    log(`         wrote ${fileResult.written.length} file(s), skipped ${fileResult.skipped.length}`)
  }

  // 2) Toolchain
  let doctorOk = true
  if (!opts.skipDoctor) {
    log("solsec: checking required audit tools (slither, forge, cast, anvil)…")
    const exe = process.execPath
    // run `solsec doctor install --required-only --print-logs=false` in-process via the same binary
    const code = await runProc(
      exe,
      ["doctor", "install", "--required-only"],
      opts.verbose ? log : undefined,
    )
    doctorOk = code === 0
    if (!doctorOk) {
      log("         some required tools failed to install — run `solsec doctor install` later to retry")
    }
  }

  // 3) Knowledge base
  let kbOk = true
  if (!opts.skipKb) {
    log("solsec: refreshing exploit knowledge base…")
    const code = await runProc(
      process.execPath,
      ["kb", "update"],
      opts.verbose ? log : undefined,
    )
    kbOk = code === 0
    if (!kbOk) {
      log("         KB refresh failed (offline?) — run `solsec kb update` later")
    }
  }

  // 4) Sentinel
  const state: BootstrapState = {
    version: "1",
    bundle_version: BUNDLE_VERSION,
    bootstrapped_at: new Date().toISOString(),
    doctor_done: doctorOk ? new Date().toISOString() : undefined,
    kb_done: kbOk ? new Date().toISOString() : undefined,
  }
  await writeState(state)

  return { ...fileResult, doctorOk, kbOk }
}

/**
 * Lightweight first-launch hook used by the CLI middleware. Does NOT install
 * tools or hit the network. Just provisions embedded assets so subagents,
 * templates, and rules are available, and stamps the sentinel if missing.
 *
 * Heavy work (doctor + kb) is run by the explicit `solsec bootstrap` command.
 */
export async function autoProvisionOnLaunch(): Promise<boolean> {
  if (!(await needsBootstrap())) return false
  const { written } = await provisionAssets()
  if (written.length === 0) return false
  // Stamp partial sentinel so subsequent launches don't re-walk.
  const state: BootstrapState = {
    version: "1",
    bundle_version: BUNDLE_VERSION,
    bootstrapped_at: new Date().toISOString(),
  }
  await writeState(state)
  return true
}

export const BUNDLE = {
  version: BUNDLE_VERSION,
  count: ASSETS.length,
  configRoot,
  sentinelPath,
}
