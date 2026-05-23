import path from "path"
import { Context, Effect, Layer } from "effect"
import { InstanceState } from "@/effect/instance-state"
import { AppFileSystem } from "@solsec-ai/core/filesystem"

export type Lane = "pre-deploy" | "1day" | "0day"
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational"
export type ImmunefiSeverity = "Critical" | "High" | "Medium" | "Low" | "None"

export interface PocRef {
  path: string
  status: "PASS" | "FAIL" | "PENDING"
  fork_url?: string
  fork_block?: number
  attacker?: string
  victim?: string
  profit_wei?: string
  profit_usd?: number
  gas_used?: number
  trace_excerpt?: string
}

export interface InvariantRef {
  name: string
  description: string
  prover: "halmos" | "kontrol" | "echidna" | "medusa" | "forge"
  status: "PROVED" | "FAILED" | "TIMEOUT" | "PENDING"
  counterexample?: string
}

export interface Finding {
  id: string
  severity: Severity
  title: string
  file: string
  lines: string
  swc_id: string
  confidence: string
  evidence_hash: string
  verified: boolean
  timestamp: string

  // — added in v2 —
  detector_id?: string // e.g. "slither:reentrancy-eth", "semgrep:solidity-reentrancy-eth-call-before-state"
  taxonomy?: string
  function?: string
  selector?: string
  description?: string
  fix?: string
  poc?: PocRef
  cvss?: string
  immunefi_severity?: ImmunefiSeverity
  chain_id?: number
  rationale?: string
  source_agent?: string
}

export interface TargetSpec {
  kind: "address" | "path" | "git"
  spec: string
  address?: string
  chain?: string
  chain_id?: number
}

export interface AuditState {
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

  // — added in v2 —
  lane?: Lane
  targets?: TargetSpec[]
  pocs?: PocRef[]
  invariants?: InvariantRef[]
  kb_version?: string
  tools_used?: string[]
}

export interface Interface {
  readonly read: () => Effect.Effect<AuditState, never>
  readonly write: (state: AuditState) => Effect.Effect<void, never>
  readonly addFinding: (finding: Finding) => Effect.Effect<void, never>
  readonly markFileAudited: (filepath: string) => Effect.Effect<void, never>
  readonly addFact: (claim: string, evidence: string, file: string, line: number) => Effect.Effect<void, never>
  readonly addHypothesis: (claim: string, needs_verification: string, file?: string) => Effect.Effect<void, never>
  readonly addDebunked: (claim: string, reason: string) => Effect.Effect<void, never>
  readonly addPoc: (poc: PocRef) => Effect.Effect<void, never>
  readonly addInvariant: (inv: InvariantRef) => Effect.Effect<void, never>
  readonly setLane: (lane: Lane) => Effect.Effect<void, never>
  readonly setTargets: (targets: TargetSpec[]) => Effect.Effect<void, never>
  readonly context: () => Effect.Effect<string, never>
}

export class Service extends Context.Service<Service, Interface>()("@solsec/AuditState") {}

const empty = (project: string): AuditState => ({
  version: 2,
  project,
  started_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  files_audited: [],
  files_pending: [],
  verified_facts: [],
  hypotheses: [],
  debunked: [],
  findings: [],
  pocs: [],
  invariants: [],
  targets: [],
  tools_used: [],
})

function migrate(parsed: any, project: string): AuditState {
  // v1 → v2 migration: copy known fields, add empty new ones.
  if (parsed && parsed.version === 1) {
    return {
      ...empty(project),
      ...parsed,
      version: 2,
      pocs: parsed.pocs ?? [],
      invariants: parsed.invariants ?? [],
      targets: parsed.targets ?? [],
      tools_used: parsed.tools_used ?? [],
    } as AuditState
  }
  if (parsed && parsed.version === 2) return parsed as AuditState
  return empty(project)
}

export const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const fs = yield* AppFileSystem.Service

    const state = yield* InstanceState.make(
      Effect.fn("AuditState.init")(function* () {
        const ctx = yield* InstanceState.context
        const dir = ctx.directory
        const statePath = path.join(dir, ".solsec", "audit-state.json")
        const raw = yield* fs.readFileString(statePath).pipe(Effect.catch(() => Effect.succeed("")))
        const parsed = raw
          ? (() => {
              try {
                return JSON.parse(raw)
              } catch {
                return null
              }
            })()
          : null
        return {
          path: statePath,
          data: migrate(parsed, path.basename(dir)),
        }
      }),
    )

    const save = Effect.fnUntraced(function* () {
      const s = yield* InstanceState.get(state)
      s.data.updated_at = new Date().toISOString()
      const json = JSON.stringify(s.data, null, 2)
      yield* fs.writeWithDirs(s.path, json).pipe(Effect.catch(() => Effect.void))
    })

    const read = Effect.fn("AuditState.read")(function* () {
      const s = yield* InstanceState.get(state)
      return s.data
    })

    const write = Effect.fn("AuditState.write")(function* (data: AuditState) {
      const s = yield* InstanceState.get(state)
      s.data = data
      yield* save()
    })

    const addFinding = Effect.fn("AuditState.addFinding")(function* (finding: Finding) {
      const s = yield* InstanceState.get(state)
      const idx = s.data.findings.findIndex((f) => f.id === finding.id)
      if (idx >= 0) s.data.findings[idx] = finding
      else s.data.findings.push(finding)
      yield* save()
    })

    const markFileAudited = Effect.fn("AuditState.markFileAudited")(function* (filepath: string) {
      const s = yield* InstanceState.get(state)
      if (!s.data.files_audited.includes(filepath)) {
        s.data.files_audited.push(filepath)
        s.data.files_pending = s.data.files_pending.filter((f) => f !== filepath)
      }
      yield* save()
    })

    const addFact = Effect.fn("AuditState.addFact")(
      function* (claim: string, evidence: string, file: string, line: number) {
        const s = yield* InstanceState.get(state)
        s.data.verified_facts.push({ claim, evidence, file, line })
        yield* save()
      },
    )

    const addHypothesis = Effect.fn("AuditState.addHypothesis")(
      function* (claim: string, needs_verification: string, file?: string) {
        const s = yield* InstanceState.get(state)
        s.data.hypotheses.push({ claim, needs_verification, file })
        yield* save()
      },
    )

    const addDebunked = Effect.fn("AuditState.addDebunked")(function* (claim: string, reason: string) {
      const s = yield* InstanceState.get(state)
      s.data.debunked.push({ claim, reason })
      yield* save()
    })

    const addPoc = Effect.fn("AuditState.addPoc")(function* (poc: PocRef) {
      const s = yield* InstanceState.get(state)
      s.data.pocs ??= []
      const idx = s.data.pocs.findIndex((p) => p.path === poc.path)
      if (idx >= 0) s.data.pocs[idx] = poc
      else s.data.pocs.push(poc)
      yield* save()
    })

    const addInvariant = Effect.fn("AuditState.addInvariant")(function* (inv: InvariantRef) {
      const s = yield* InstanceState.get(state)
      s.data.invariants ??= []
      const idx = s.data.invariants.findIndex((i) => i.name === inv.name)
      if (idx >= 0) s.data.invariants[idx] = inv
      else s.data.invariants.push(inv)
      yield* save()
    })

    const setLane = Effect.fn("AuditState.setLane")(function* (lane: Lane) {
      const s = yield* InstanceState.get(state)
      s.data.lane = lane
      yield* save()
    })

    const setTargets = Effect.fn("AuditState.setTargets")(function* (targets: TargetSpec[]) {
      const s = yield* InstanceState.get(state)
      s.data.targets = targets
      yield* save()
    })

    const context = Effect.fn("AuditState.context")(function* () {
      const s = yield* InstanceState.get(state)
      const d = s.data

      const findings = d.findings.length > 0
        ? d.findings
            .map(
              (f) =>
                `  - [${f.severity}] ${f.title} (${f.swc_id}) @ ${f.file}:${f.lines} — ${f.verified ? "VERIFIED" : "UNCONFIRMED"}`,
            )
            .join("\n")
        : "  (none yet)"

      const facts = d.verified_facts.length > 0
        ? d.verified_facts.map((f) => `  - ${f.claim} [evidence: ${f.evidence} @ ${f.file}:${f.line}]`).join("\n")
        : "  (none yet)"

      const hypotheses = d.hypotheses.length > 0
        ? d.hypotheses.map((h) => `  - ${h.claim} (needs: ${h.needs_verification})`).join("\n")
        : "  (none yet)"

      const debunked = d.debunked.length > 0
        ? d.debunked.map((d2) => `  - ${d2.claim} (reason: ${d2.reason})`).join("\n")
        : "  (none yet)"

      const pocs = (d.pocs ?? []).length > 0
        ? d.pocs!
            .map((p) => `  - ${p.path} [${p.status}] profit=${p.profit_wei ?? "—"} block=${p.fork_block ?? "—"}`)
            .join("\n")
        : "  (none yet)"

      const invariants = (d.invariants ?? []).length > 0
        ? d.invariants!.map((i) => `  - ${i.name} [${i.prover}/${i.status}] ${i.description}`).join("\n")
        : "  (none yet)"

      return [
        `<audit-state>`,
        `Project: ${d.project}`,
        `Lane: ${d.lane ?? "(unset)"}`,
        `Audit started: ${d.started_at}`,
        `Last updated: ${d.updated_at}`,
        ``,
        `Targets:`,
        (d.targets ?? []).length > 0
          ? d.targets!.map((t) => `  - ${t.kind}: ${t.spec}${t.chain ? ` @${t.chain}` : ""}`).join("\n")
          : "  (none yet)",
        ``,
        `Files audited (${d.files_audited.length}):`,
        d.files_audited.length > 0 ? d.files_audited.map((f) => `  [x] ${f}`).join("\n") : "  (none yet)",
        ``,
        `Findings (${d.findings.length}):`,
        findings,
        ``,
        `PoCs:`,
        pocs,
        ``,
        `Invariants:`,
        invariants,
        ``,
        `Verified Facts:`,
        facts,
        ``,
        `Open Hypotheses:`,
        hypotheses,
        ``,
        `Debunked Claims:`,
        debunked,
        `</audit-state>`,
      ].join("\n")
    })

    return Service.of({
      read,
      write,
      addFinding,
      markFileAudited,
      addFact,
      addHypothesis,
      addDebunked,
      addPoc,
      addInvariant,
      setLane,
      setTargets,
      context,
    })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(AppFileSystem.defaultLayer))

export * as AuditState from "./audit-state"
