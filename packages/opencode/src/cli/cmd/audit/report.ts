import { Effect } from "effect"
import * as fs from "fs/promises"
import * as path from "path"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec report
 *
 * Renders an audit report from `.solsec/audit-state.json` using one of the
 * shipped templates under `.solsec/templates/`.
 *
 *   solsec report --template immunefi --finding <id>     → single-finding bug bounty disclosure
 *   solsec report --template c4 --finding <id>           → Code4rena entry
 *   solsec report --template pre-deploy                  → full audit report
 *   solsec report --sarif > out.sarif                    → SARIF 2.1.0 for CI
 */

interface Finding {
  id: string
  severity: string
  title: string
  file: string
  lines: string
  swc_id: string
  confidence: string
  evidence_hash?: string
  verified?: boolean
  timestamp?: string
  detector_id?: string
  taxonomy?: string
  function?: string
  selector?: string
  description?: string
  fix?: string
  poc?: any
  cvss?: string
  immunefi_severity?: string
  chain_id?: number
  rationale?: string
  source_agent?: string
}

interface AuditState {
  version: number
  project: string
  started_at: string
  updated_at: string
  files_audited: string[]
  files_pending: string[]
  verified_facts: { claim: string; evidence: string; file: string; line: number }[]
  hypotheses: { claim: string; needs_verification: string; file?: string }[]
  debunked: { claim: string; reason: string }[]
  findings: Finding[]
  lane?: string
  targets?: any[]
  pocs?: any[]
  invariants?: any[]
}

function findStateFile(cwd: string): string {
  return path.join(cwd, ".solsec", "audit-state.json")
}

async function loadState(cwd: string): Promise<AuditState> {
  const p = findStateFile(cwd)
  const raw = await fs.readFile(p, "utf8")
  return JSON.parse(raw) as AuditState
}

function severityToSarif(s: string): "error" | "warning" | "note" | "none" {
  switch (s) {
    case "Critical":
    case "High":
      return "error"
    case "Medium":
      return "warning"
    case "Low":
    case "Informational":
      return "note"
    default:
      return "none"
  }
}

function lineRange(s?: string): { startLine: number; endLine: number } {
  if (!s) return { startLine: 1, endLine: 1 }
  const m = s.match(/(\d+)\s*-\s*(\d+)/)
  if (m) return { startLine: parseInt(m[1]!, 10), endLine: parseInt(m[2]!, 10) }
  const n = parseInt(s, 10)
  if (!isNaN(n)) return { startLine: n, endLine: n }
  return { startLine: 1, endLine: 1 }
}

function renderSarif(state: AuditState): string {
  const tools = new Map<string, Set<string>>()
  for (const f of state.findings) {
    const [tool, rule] = (f.detector_id ?? "manual:" + f.id).split(":")
    if (!tools.has(tool!)) tools.set(tool!, new Set())
    tools.get(tool!)!.add(rule ?? f.id)
  }
  const runs = [...tools.entries()].map(([tool, ruleIds]) => ({
    tool: {
      driver: {
        name: tool,
        informationUri: "https://github.com/anomalyco/solsec",
        rules: [...ruleIds].map((id) => ({
          id,
          shortDescription: { text: id },
          defaultConfiguration: { level: "warning" },
        })),
      },
    },
    results: state.findings
      .filter((f) => (f.detector_id ?? "manual:" + f.id).startsWith(tool + ":"))
      .map((f) => {
        const range = lineRange(f.lines)
        return {
          ruleId: (f.detector_id ?? "manual:" + f.id).split(":").slice(1).join(":") || f.id,
          level: severityToSarif(f.severity),
          message: { text: `${f.title}${f.swc_id ? ` (${f.swc_id})` : ""}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: range,
              },
            },
          ],
          properties: {
            severity: f.severity,
            taxonomy: f.taxonomy,
            verified: f.verified,
            poc: f.poc?.path,
            cvss: f.cvss,
          },
        }
      }),
  }))
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs,
    },
    null,
    2,
  )
}

function fillTemplate(tmpl: string, vars: Record<string, string>): string {
  return tmpl.replace(/\{\{(\w[\w_]*)\}\}/g, (m, key) => (vars[key] !== undefined ? String(vars[key]) : m))
}

function findingToImmunefi(state: AuditState, f: Finding): Record<string, string> {
  const target = state.targets?.[0] ?? {}
  return {
    TITLE: f.title,
    SEVERITY: f.severity,
    SWC_ID: f.swc_id ?? "—",
    CONTRACT_NAME: f.file.split("/").pop() ?? "?",
    ADDRESS: target.address ?? "—",
    CHAIN: target.chain ?? "—",
    CHAIN_ID: target.chain_id?.toString() ?? "—",
    VERIFIED_SOURCE: f.verified ? "yes" : "no",
    REPORTER: process.env.SOLSEC_REPORTER ?? "—",
    DATE: new Date().toISOString().slice(0, 10),
    FORK_BLOCK: f.poc?.fork_block?.toString() ?? "—",
    IMMUNEFI_PROGRAM: target.immunefi_program ?? "—",
    FILE: f.file,
    LINES: f.lines,
    FUNCTION_SIGNATURE: f.function ?? "—",
    VULNERABLE_CODE_VERBATIM: "// (paste verbatim from " + f.file + ":" + f.lines + ")",
    LOSS_USD: f.poc?.profit_usd?.toString() ?? "—",
    VICTIM: f.poc?.victim ?? "—",
    INDIRECT_IMPACT: "—",
    AFFECTED_ACTORS: "—",
    IMMUNEFI_SEVERITY: f.immunefi_severity ?? f.severity,
    IMMUNEFI_RATIONALE: f.rationale ?? "—",
    N_TXS: "1",
    RPC_URL: "<RPC_URL>",
    POC_CONTRACT_BODY: "// see " + (f.poc?.path ?? "(no PoC yet)"),
    FORGE_TEST_OUTPUT: f.poc?.trace_excerpt ?? "(forge test output)",
    PROFIT_WEI: f.poc?.profit_wei ?? "0",
    PROFIT_USD: f.poc?.profit_usd?.toString() ?? "0",
    FIX_DIFF: f.fix ?? "// (suggested fix)",
    LANE: state.lane ?? "—",
    REFERENCES: "—",
  }
}

function findingToC4(state: AuditState, f: Finding): Record<string, string> {
  const target = state.targets?.[0] ?? {}
  return {
    TITLE: f.title,
    REPO_URL: target.spec ?? "—",
    COMMIT_SHA: target.commit ?? "—",
    FILE: f.file,
    LINE_START: lineRange(f.lines).startLine.toString(),
    LINE_END: lineRange(f.lines).endLine.toString(),
    C4_SEVERITY: f.severity === "Critical" || f.severity === "High" ? "High" : f.severity,
    C4_RATIONALE: f.rationale ?? "see impact + PoC below",
    VULNERABLE_CODE_VERBATIM: "// (paste verbatim from " + f.file + ":" + f.lines + ")",
    STEP_1: "TODO",
    STEP_2: "TODO",
    STEP_N: "TODO",
    POC_CONTRACT_BODY: "// see " + (f.poc?.path ?? "(no PoC yet)"),
    CONTRACT_NAME: f.file.split("/").pop()?.replace(/\.sol$/, "") ?? "Target",
    FORGE_TEST_OUTPUT: f.poc?.trace_excerpt ?? "(forge test output)",
    TOOLS_USED: "slither, semgrep, forge",
    FIX_DIFF: f.fix ?? "(suggested fix)",
    EDGE_CASE_1: "TODO",
    EDGE_CASE_2: "TODO",
    C4_ASSESSED_TYPE: f.taxonomy ?? "Other",
  }
}

export const ReportCommand = effectCmd({
  command: "report",
  describe: "render an audit report from .solsec/audit-state.json",
  instance: false,
  builder: (yargs) =>
    yargs
      .option("template", {
        describe: "report template",
        choices: ["immunefi", "c4", "pre-deploy"] as const,
        default: "pre-deploy",
      })
      .option("finding", { describe: "finding id (for immunefi/c4)", type: "string" })
      .option("output", { describe: "output path (default: stdout)", type: "string" })
      .option("sarif", { describe: "emit SARIF 2.1.0 instead of Markdown", type: "boolean", default: false }),
  handler: Effect.fn("Cli.report")(function* (args) {
    const cwd = process.cwd()
    const state = yield* Effect.promise(() => loadState(cwd)).pipe(
      Effect.catch((e) => fail(`could not load audit-state: ${(e as Error).message}`)),
    )

    if (args.sarif) {
      const out = renderSarif(state)
      if (args.output) yield* Effect.promise(() => fs.writeFile(args.output as string, out))
      else process.stdout.write(out + "\n")
      return
    }

    const tmplPath = path.join(cwd, ".solsec", "templates", `report-${args.template}.md`)
    const tmpl = yield* Effect.promise(() => fs.readFile(tmplPath, "utf8")).pipe(
      Effect.catch((e) =>
        fail(`could not read template ${tmplPath}: ${(e as Error).message}`),
      ),
    )

    let body: string
    if (args.template === "pre-deploy") {
      // Pre-deploy template uses a more elaborate Mustache-ish syntax. We don't ship a full
      // template engine; instead, we emit the raw template plus a JSON appendix the auditor
      // pastes into. Future: integrate Handlebars.
      body =
        tmpl.replace(/\{\{[#\/]each [^}]+\}\}/g, "") +
        "\n\n<!-- audit-state.json appendix -->\n```json\n" +
        JSON.stringify(state, null, 2) +
        "\n```\n"
    } else {
      const id = args.finding as string | undefined
      const finding = id
        ? state.findings.find((f) => f.id === id)
        : state.findings.find((f) => f.severity === "Critical" || f.severity === "High")
      if (!finding) return yield* fail(`no finding to render (specify --finding <id>)`)
      const vars =
        args.template === "immunefi" ? findingToImmunefi(state, finding) : findingToC4(state, finding)
      body = fillTemplate(tmpl, vars)
    }

    if (args.output) {
      yield* Effect.promise(() => fs.writeFile(args.output as string, body))
      UI.println(`wrote ${args.output}`)
    } else {
      process.stdout.write(body)
      if (!body.endsWith("\n")) process.stdout.write("\n")
    }
  }),
})
