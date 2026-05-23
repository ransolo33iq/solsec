# Pre-Deploy Audit — {{PROJECT_NAME}}

| field | value |
|---|---|
| Repository | {{REPO_URL}} |
| Commit | {{COMMIT_SHA}} |
| Auditor | {{AUDITOR}} |
| Audit window | {{START_DATE}} → {{END_DATE}} |
| solc version | {{SOLC_VERSION}} |
| Test framework | {{TEST_FRAMEWORK}} (foundry / hardhat / both) |
| Lines of code | {{LOC}} |

## Executive Summary

{{EXEC_SUMMARY_PARAGRAPH}}

| Severity | Count |
|---|---|
| Critical | {{N_CRITICAL}} |
| High | {{N_HIGH}} |
| Medium | {{N_MEDIUM}} |
| Low | {{N_LOW}} |
| Informational | {{N_INFO}} |

Overall risk assessment: **{{OVERALL_RISK}}** (Low / Moderate / High / Critical).

## Scope

| File | Purpose | LoC |
|---|---|---|
{{#each FILES}}
| `{{path}}` | {{purpose}} | {{loc}} |
{{/each}}

Out of scope: {{OUT_OF_SCOPE}}.

## Methodology

1. Source acquisition + dependency tree map.
2. Static sweep — slither, aderyn, semgrep (`.solsec/semgrep/solidity/`), wake, solhint.
3. Manual review against the AGENTS.md taxonomy (Reentrancy, Access Control, Oracle, ERC-4626, Permit, Bridge, Governance, Storage, Events).
4. Cross-function state matrix construction.
5. Invariant suite — Foundry `invariant_*` + halmos proofs of high-value claims.
6. Coverage-guided fuzz — echidna assertions, medusa.
7. PoC verification on a forked instance for any Critical/High suspicion.

## Cross-Function Reentrancy Matrix

| State Var | Function A (writes) | External call in A? | Function B (writes) | Mitigation |
|---|---|---|---|---|
{{REENTRANCY_MATRIX_ROWS}}

## Findings

{{#each FINDINGS}}
### [{{severity}}] {{title}} — {{swc}}

**File:** `{{file}}`
**Lines:** `{{lines}}`
**Function:** `{{function}}`

**Description.** {{description}}

**Vulnerable Code:**

```solidity
{{code}}
```

**Proof of Concept:** `{{poc_path}}` ({{poc_status}}: PASS / N/A).

**Recommended Fix:**

```solidity
{{fix}}
```

**Confidence:** {{confidence}}

---
{{/each}}

## Verified Facts Registry

{{#each VERIFIED_FACTS}}
- {{claim}} — evidence: `{{file}}:{{line}}`
{{/each}}

## False Positive Registry

{{#each DEBUNKED}}
- **{{claim}}** — disproven: {{reason}} (cite `{{file}}:{{line}}`)
{{/each}}

## Open Hypotheses

{{#each HYPOTHESES}}
- {{claim}} — needs verification: {{needs_verification}}
{{/each}}

## Invariants Defined

{{#each INVARIANTS}}
- `{{name}}` — {{description}} ({{prover}}: {{status}})
{{/each}}

## Tooling Output Summary

- slither: {{SLITHER_SUMMARY}}
- aderyn: {{ADERYN_SUMMARY}}
- semgrep: {{SEMGREP_SUMMARY}}
- wake: {{WAKE_SUMMARY}}
- halmos: {{HALMOS_SUMMARY}}
- echidna / medusa: {{FUZZ_SUMMARY}}

## Files Audited

{{#each AUDITED_FILES}}
- [x] `{{path}}`
{{/each}}

{{#each PENDING_FILES}}
- [ ] `{{path}}` (pending)
{{/each}}

## Recommendations Beyond Findings

- {{REC_1}}
- {{REC_2}}

## Disclaimer

This audit covers commit `{{COMMIT_SHA}}` only. Subsequent changes require re-audit. No audit guarantees absence of all bugs; this report describes what we found in the time allotted.
