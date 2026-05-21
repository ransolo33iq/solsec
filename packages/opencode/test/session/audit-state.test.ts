import { describe, expect } from "bun:test"
import { Effect } from "effect"
import { testEffect } from "../lib/effect"
import { AuditState } from "@/session/audit-state"
import { TestInstance } from "../fixture/fixture"

const it = testEffect(AuditState.defaultLayer)

describe("AuditState", () => {
  it.instance("reads empty state when no file exists", () =>
    Effect.gen(function* () {
      const svc = yield* AuditState.Service
      const state = yield* svc.read()
      expect(state.files_audited).toEqual([])
      expect(state.findings).toEqual([])
      expect(state.verified_facts).toEqual([])
      expect(state.version).toBe(1)
    }),
  )

  it.instance("addFinding persists a finding", () =>
    Effect.gen(function* () {
      const svc = yield* AuditState.Service
      yield* svc.addFinding({
        id: "VULN-001",
        severity: "Critical",
        title: "Reentrancy in withdraw",
        file: "Vault.sol",
        lines: "L45-L52",
        swc_id: "SWC-107",
        confidence: "High",
        evidence_hash: "abc123",
        verified: true,
        timestamp: new Date().toISOString(),
      })
      const state = yield* svc.read()
      expect(state.findings).toHaveLength(1)
      expect(state.findings[0].id).toBe("VULN-001")
    }),
  )

  it.instance("addFinding deduplicates by id", () =>
    Effect.gen(function* () {
      const svc = yield* AuditState.Service
      yield* svc.addFinding({
        id: "VULN-001",
        severity: "Critical",
        title: "Reentrancy in withdraw",
        file: "Vault.sol",
        lines: "L45-L52",
        swc_id: "SWC-107",
        confidence: "High",
        evidence_hash: "abc123",
        verified: true,
        timestamp: "2025-01-01",
      })
      yield* svc.addFinding({
        id: "VULN-001",
        severity: "High",
        title: "Updated title",
        file: "Vault.sol",
        lines: "L45-L53",
        swc_id: "SWC-107",
        confidence: "High",
        evidence_hash: "def456",
        verified: false,
        timestamp: "2025-01-02",
      })
      const state = yield* svc.read()
      expect(state.findings).toHaveLength(1)
      expect(state.findings[0].title).toBe("Updated title")
      expect(state.findings[0].evidence_hash).toBe("def456")
    }),
  )

  it.instance("markFileAudited adds file and removes from pending", () =>
    Effect.gen(function* () {
      const svc = yield* AuditState.Service
      yield* svc.read()
      yield* svc.markFileAudited("Vault.sol")
      yield* svc.markFileAudited("Token.sol")
      const state = yield* svc.read()
      expect(state.files_audited).toContain("Vault.sol")
      expect(state.files_audited).toContain("Token.sol")
      expect(state.files_audited).toHaveLength(2)
    }),
  )

  it.instance("addFact appends a verified fact", () =>
    Effect.gen(function* () {
      const svc = yield* AuditState.Service
      yield* svc.addFact("Balance check present", "Line 42: require(balance >= amount)", "Vault.sol", 42)
      const state = yield* svc.read()
      expect(state.verified_facts).toHaveLength(1)
      expect(state.verified_facts[0].claim).toBe("Balance check present")
    }),
  )

  it.instance("addHypothesis and addDebunked work", () =>
    Effect.gen(function* () {
      const svc = yield* AuditState.Service
      yield* svc.addHypothesis("Possible reentrancy", "Check withdraw function CEI ordering")
      yield* svc.addDebunked("tx.origin used for auth", "No tx.origin found in contract")
      const state = yield* svc.read()
      expect(state.hypotheses).toHaveLength(1)
      expect(state.debunked).toHaveLength(1)
    }),
  )

  it.instance("context returns formatted string", () =>
    Effect.gen(function* () {
      const svc = yield* AuditState.Service
      yield* svc.markFileAudited("Vault.sol")
      yield* svc.addFinding({
        id: "VULN-001",
        severity: "Critical",
        title: "Reentrancy",
        file: "Vault.sol",
        lines: "L45-L52",
        swc_id: "SWC-107",
        confidence: "High",
        evidence_hash: "abc",
        verified: true,
        timestamp: new Date().toISOString(),
      })
      const ctx = yield* svc.context()
      expect(ctx).toContain("<audit-state>")
      expect(ctx).toContain("Files audited (1):")
      expect(ctx).toContain("Vault.sol")
      expect(ctx).toContain("[Critical] Reentrancy")
      expect(ctx).toContain("VERIFIED")
      expect(ctx).toContain("</audit-state>")
    }),
  )

  it.instance("persists state to disk", () =>
    Effect.gen(function* () {
      const test = yield* TestInstance
      const svc = yield* AuditState.Service
      yield* svc.addFinding({
        id: "VULN-001",
        severity: "High",
        title: "Persistence check",
        file: "Test.sol",
        lines: "L1-L10",
        swc_id: "SWC-100",
        confidence: "Medium",
        evidence_hash: "persist",
        verified: true,
        timestamp: new Date().toISOString(),
      })

      const state = yield* svc.read()
      expect(state.findings).toHaveLength(1)
      expect(state.findings[0].title).toBe("Persistence check")

      // Read from a fresh service instance to verify disk persistence
      const fs = yield* Effect.promise(() => import("fs/promises"))
      const path = yield* Effect.promise(() => import("path"))
      const raw = yield* Effect.promise(() =>
        fs.readFile(path.join(test.directory, ".solsec", "audit-state.json"), "utf-8"),
      )
      const onDisk = JSON.parse(raw)
      expect(onDisk.findings).toHaveLength(1)
      expect(onDisk.findings[0].id).toBe("VULN-001")
    }),
  )
})
