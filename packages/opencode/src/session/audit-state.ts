import path from "path"
import { Context, Effect, Layer } from "effect"
import { InstanceState } from "@/effect/instance-state"
import { AppFileSystem } from "@solsec-ai/core/filesystem"

export interface Finding {
  id: string
  severity: "Critical" | "High" | "Medium" | "Low" | "Informational"
  title: string
  file: string
  lines: string
  swc_id: string
  confidence: string
  evidence_hash: string
  verified: boolean
  timestamp: string
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
}

export interface Interface {
  readonly read: () => Effect.Effect<AuditState, never>
  readonly write: (state: AuditState) => Effect.Effect<void, never>
  readonly addFinding: (finding: Finding) => Effect.Effect<void, never>
  readonly markFileAudited: (filepath: string) => Effect.Effect<void, never>
  readonly addFact: (claim: string, evidence: string, file: string, line: number) => Effect.Effect<void, never>
  readonly addHypothesis: (claim: string, needs_verification: string, file?: string) => Effect.Effect<void, never>
  readonly addDebunked: (claim: string, reason: string) => Effect.Effect<void, never>
  readonly context: () => Effect.Effect<string, never>
}

export class Service extends Context.Service<Service, Interface>()("@solsec/AuditState") {}

const empty = (project: string): AuditState => ({
  version: 1,
  project,
  started_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  files_audited: [],
  files_pending: [],
  verified_facts: [],
  hypotheses: [],
  debunked: [],
  findings: [],
})

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
        const parsed = raw ? (() => { try { return JSON.parse(raw) } catch { return null } })() : null
        return {
          path: statePath,
          data: (parsed && parsed.version === 1 ? parsed : empty(path.basename(dir))) as AuditState,
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

      return [
        `<audit-state>`,
        `Project: ${d.project}`,
        `Audit started: ${d.started_at}`,
        `Last updated: ${d.updated_at}`,
        ``,
        `Files audited (${d.files_audited.length}):`,
        d.files_audited.length > 0 ? d.files_audited.map((f) => `  [x] ${f}`).join("\n") : "  (none yet)",
        ``,
        `Findings (${d.findings.length}):`,
        findings,
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

    return Service.of({ read, write, addFinding, markFileAudited, addFact, addHypothesis, addDebunked, context })
  }),
)

export const defaultLayer = layer.pipe(Layer.provide(AppFileSystem.defaultLayer))

export * as AuditState from "./audit-state"
