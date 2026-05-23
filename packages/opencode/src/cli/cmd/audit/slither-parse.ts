import { Effect } from "effect"
import * as fs from "fs/promises"
import * as path from "path"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec slither-parse <path/to/slither.json>
 *
 * Replaces the broken `solsec-slither-parse` shell wrapper. Reads slither's
 * `--json -` output, normalizes to ranked findings grouped by severity, and
 * emits a Markdown report. Optionally patches `audit-state.json`.
 */

const SEVERITY_ORDER: Record<string, number> = {
  High: 0,
  Medium: 1,
  Low: 2,
  Informational: 3,
  Optimization: 4,
}

const IMPACT_TO_SEVERITY: Record<string, string> = {
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
  optimization: "Optimization",
}

interface SlitherDetector {
  check?: string
  impact?: string
  confidence?: string
  description?: string
  markdown?: string
  elements?: Array<{
    name?: string
    type?: string
    source_mapping?: { filename_relative?: string; filename_absolute?: string; lines?: number[] }
  }>
}

function severityFor(impact?: string): string {
  if (!impact) return "Informational"
  return IMPACT_TO_SEVERITY[impact.toLowerCase()] ?? "Informational"
}

function locationOf(d: SlitherDetector): { file: string; lines: string } {
  const el = d.elements?.[0]
  const sm = el?.source_mapping
  const file = sm?.filename_relative ?? sm?.filename_absolute ?? "unknown"
  const lines = sm?.lines?.length ? `${sm.lines[0]}-${sm.lines[sm.lines.length - 1]}` : "—"
  return { file, lines }
}

export const SlitherParseCommand = effectCmd({
  command: "slither-parse <input>",
  describe: "parse slither --json output into a ranked Markdown report",
  instance: false,
  builder: (yargs) =>
    yargs
      .positional("input", { describe: "slither JSON file path or '-' for stdin", type: "string", demandOption: true })
      .option("format", { describe: "output format", choices: ["markdown", "json"] as const, default: "markdown" })
      .option("audit-state", {
        describe: "also patch .solsec/audit-state.json with new findings",
        type: "string",
      })
      .option("min-severity", {
        describe: "filter by minimum severity",
        choices: ["High", "Medium", "Low", "Informational"] as const,
      }),
  handler: Effect.fn("Cli.slitherParse")(function* (args) {
    const input = args.input as string
    const raw = yield* Effect.promise(async () => {
      if (input === "-") {
        return await new Promise<string>((resolve, reject) => {
          let data = ""
          process.stdin.setEncoding("utf8")
          process.stdin.on("data", (chunk) => (data += chunk))
          process.stdin.on("end", () => resolve(data))
          process.stdin.on("error", reject)
        })
      }
      return await fs.readFile(input, "utf8")
    })

    let json: any
    try {
      json = JSON.parse(raw)
    } catch (e) {
      return yield* fail(`failed to parse JSON: ${(e as Error).message}`)
    }

    const detectors: SlitherDetector[] = json.results?.detectors ?? json.detectors ?? []
    const minIdx = args["min-severity"] ? SEVERITY_ORDER[args["min-severity"] as string] : Infinity
    const filtered = detectors.filter((d) => SEVERITY_ORDER[severityFor(d.impact)] <= (Number.isFinite(minIdx) ? minIdx : 999))

    const findings = filtered
      .map((d) => {
        const loc = locationOf(d)
        return {
          severity: severityFor(d.impact),
          check: d.check ?? "unknown",
          confidence: d.confidence ?? "unknown",
          description: (d.description ?? d.markdown ?? "").trim(),
          file: loc.file,
          lines: loc.lines,
        }
      })
      .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])

    if (args.format === "json") {
      process.stdout.write(JSON.stringify(findings, null, 2))
      process.stdout.write("\n")
    } else {
      const lines: string[] = []
      lines.push(`# Slither Findings`)
      lines.push("")
      lines.push(`Total: ${findings.length}`)
      const byCount = new Map<string, number>()
      for (const f of findings) byCount.set(f.severity, (byCount.get(f.severity) ?? 0) + 1)
      for (const sev of Object.keys(SEVERITY_ORDER)) {
        if (byCount.has(sev)) lines.push(`- ${sev}: ${byCount.get(sev)}`)
      }
      lines.push("")
      let cur = ""
      for (const f of findings) {
        if (f.severity !== cur) {
          cur = f.severity
          lines.push(`## ${cur}`)
          lines.push("")
        }
        lines.push(`### ${f.check} (${f.confidence} confidence)`)
        lines.push(`**Location:** \`${f.file}:${f.lines}\``)
        lines.push("")
        if (f.description) {
          lines.push(f.description)
          lines.push("")
        }
      }
      process.stdout.write(lines.join("\n"))
      process.stdout.write("\n")
    }

    if (args["audit-state"]) {
      const statePath = args["audit-state"] as string
      yield* Effect.promise(async () => {
        let state: any = {}
        try {
          state = JSON.parse(await fs.readFile(statePath, "utf8"))
        } catch {}
        state.version ??= 1
        state.findings ??= []
        const seen = new Set(state.findings.map((f: any) => f.id))
        let added = 0
        for (const f of findings) {
          const id = `slither:${f.check}:${f.file}:${f.lines}`
          if (seen.has(id)) continue
          state.findings.push({
            id,
            severity: f.severity,
            title: f.check,
            file: f.file,
            lines: f.lines,
            swc_id: "",
            confidence: f.confidence,
            evidence_hash: "",
            verified: false,
            timestamp: new Date().toISOString(),
          })
          added++
        }
        state.updated_at = new Date().toISOString()
        await fs.mkdir(path.dirname(statePath), { recursive: true })
        await fs.writeFile(statePath, JSON.stringify(state, null, 2))
        UI.println(`patched ${statePath} (+${added} new findings)`)
      })
    }
  }),
})
