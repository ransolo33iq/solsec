# Bug Report — {{TITLE}}

| field | value |
|---|---|
| Severity | {{SEVERITY}} (Critical / High / Medium / Low / Informational) |
| SWC | {{SWC_ID}} |
| Target contract | {{CONTRACT_NAME}} |
| Address | {{ADDRESS}} |
| Chain | {{CHAIN}} (chain id {{CHAIN_ID}}) |
| Verified source | {{VERIFIED_SOURCE}} |
| Reported by | {{REPORTER}} |
| Date | {{DATE}} |
| Fork block | {{FORK_BLOCK}} |
| Bounty program | {{IMMUNEFI_PROGRAM}} |

## Summary

One paragraph in plain English: what is the bug, who can trigger it, what is the impact, and how much value is at risk.

## Vulnerability details

**File:** `{{FILE}}`
**Lines:** `{{LINES}}`
**Function:** `{{FUNCTION_SIGNATURE}}`

```solidity
{{VULNERABLE_CODE_VERBATIM}}
```

Walk through the precise execution path that hits the bug. Reference the lines above. State which preconditions an attacker needs (token approvals, on-chain liquidity, governance state, etc.).

## Impact

- **Direct loss:** $`{{LOSS_USD}}` extractable from `{{VICTIM}}`.
- **Indirect:** {{INDIRECT_IMPACT}} (DoS, rug-protection bypass, etc.)
- **Affected actors:** {{AFFECTED_ACTORS}}.

Per the [Immunefi vulnerability severity classification](https://immunefi.com/severity-system/), this maps to **{{IMMUNEFI_SEVERITY}}** because {{IMMUNEFI_RATIONALE}}.

## Proof of concept

Foundry test pinned to fork block `{{FORK_BLOCK}}` on `{{CHAIN}}`. Reproduces the attack in a single transaction (or sequence of {{N_TXS}} transactions).

```bash
RPC={{RPC_URL}} forge test --match-contract {{CONTRACT_NAME}}Test -vvvv
```

```solidity
{{POC_CONTRACT_BODY}}
```

Output (trimmed):

```
{{FORGE_TEST_OUTPUT}}
```

Profit observed: `{{PROFIT_WEI}}` wei (≈ `${{PROFIT_USD}}` at fork block).

## Root cause

Plain-English diagnosis. Reference exactly which invariant breaks and why the existing checks fail to enforce it.

## Mitigation

Minimal patch (no behavior regressions):

```solidity
{{FIX_DIFF}}
```

Why this fixes it without breaking legitimate usage. List any tests / invariants that should be added.

## Disclosure timeline

| Date (UTC) | Event |
|---|---|
| {{DATE}} | Vulnerability identified during {{LANE}} review |
| {{DATE}} | PoC reproduced against fork block {{FORK_BLOCK}} |
| | Submitted to Immunefi |
| | Patched by team |
| | Public disclosure |

## References

- {{REFERENCES}}
