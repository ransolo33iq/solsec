---
description: Run a multi-lane Solidity audit (1day / 0day / pre-deploy)
subtask: true
---

You are running the solsec `/audit` orchestrator for: **$ARGUMENTS**

`$ARGUMENTS` should be one of:
- `0xADDR@chain` — deployed contract (e.g. `0x1234...@base`)
- a path to a Solidity source directory (pre-deploy review)
- a `git+https://...` URL (clone-then-audit)

Pipeline:

1. **Pre-flight**
   - If the target spec is a path or git URL, clone/cd as needed.
   - Create a fresh run id: `runId = .solsec/audit/<UTC-timestamp>/`.
   - Make sure required tools are installed: run `solsec doctor check --required-only`. If anything is missing, prompt the user to run `solsec doctor install` and abort.
   - Take a snapshot before starting: `solsec snapshot create --reason "audit-$ARGUMENTS"`.

2. **Lane routing**
   - Spawn the **`lane-router`** subagent with the target spec.
   - Persist its JSON output to `${runId}/lane.json`.

3. **Recon (parallel)** — based on lane:
   - Always: spawn **`auditor`** to produce `${runId}/recon.json`.
   - For `1day` / `0day`: also spawn **`tvl-sizer`** (when present in `.solsec/agent/`) to estimate extractable USD.

4. **Specialist dispatch (parallel)**
   Always run:
   - **`slither-triage`**
   - **`semgrep-runner`**
   - **`access-control`**

   For `1day`: add `sibling-hunter`, `oracle-triage`, `bridge-validator`, `donation-attack` (any of these that exist as agents).
   For `0day`: add `deep-reader`, `composability-prober`, `economic-flaw-checker`.
   For `pre-deploy`: also run `invariant-writer` and `halmos-prover` if available.

   Each specialist appends to `${runId}/findings.json`.

5. **PoC verification**
   For every finding with `severity ∈ {Critical, High}`, spawn **`fork-tester`** with the finding payload. PoCs land under `test/`, `script/`, `poc/` plus `${runId}/pocs.json`.

6. **Disclosure draft**
   Render `${runId}/report.md` from the consolidated findings + PoCs using the appropriate template (`.solsec/templates/report-immunefi.md` for 1day, `report-c4.md` for pre-deploy contests, `report-pre-deploy.md` otherwise — fall back to the AGENTS.md report skeleton if templates missing).

## Final message contract

Conclude the run with a single Markdown block that contains:

```
# Audit Result — <target>
- lane: <lane> (confidence: <0..1>)
- findings: <C>/<H>/<M>/<L>/<I>
- verified PoCs: <n>
- artifacts:
  - ${runId}/report.md
  - ${runId}/findings.json
  - ${runId}/pocs.json
  - ${runId}/recon.json
- next steps: <free text>
```

## Anti-hallucination guard

- Do not write findings yourself. Specialists own that.
- If a subagent fails, capture its error in the report under `## Errors` and continue with the rest of the pipeline.
- If `lane-router` returns confidence < 0.3, default to `1day` and note the uncertainty in the report.
- Never claim Critical / High without a passing PoC from `fork-tester`.

## CONTEXT

- run dir: `.solsec/audit/<UTC-timestamp>/`
- target spec: $ARGUMENTS
- AGENTS.md is auto-loaded — taxonomy and false-positive rules apply.
- Live KB lives at `.solsec/kb/`. If stale, suggest `solsec kb update` once.
