# {{TITLE}}

## Lines of code

- {{REPO_URL}}/blob/{{COMMIT_SHA}}/{{FILE}}#L{{LINE_START}}-L{{LINE_END}}

## Vulnerability details

### Impact

State concretely what an attacker can extract or force, and against which actor. Map to a Code4rena severity bucket:

- **High** — direct loss of funds without (or with minimal) preconditions, broken core invariant
- **Medium** — fund loss requires specific precondition, or a non-trivial DoS / griefing
- **Low** / **QA** — informational, gas, code quality

This finding is **{{C4_SEVERITY}}** because {{C4_RATIONALE}}.

### Proof of Concept

Reference the exact lines:

```solidity
{{VULNERABLE_CODE_VERBATIM}}
```

The execution path:

1. {{STEP_1}}
2. {{STEP_2}}
3. {{STEP_N}}

Foundry coded PoC (place under `test/`, runs against the contest fork block):

```solidity
{{POC_CONTRACT_BODY}}
```

```bash
forge test --match-contract {{CONTRACT_NAME}}Test -vvv
```

Result:

```
{{FORGE_TEST_OUTPUT}}
```

### Tools Used

- Manual review
- {{TOOLS_USED}}

### Recommended Mitigation Steps

```diff
{{FIX_DIFF}}
```

Justification + edge cases that the patch must keep correct:

- {{EDGE_CASE_1}}
- {{EDGE_CASE_2}}

### Assessed type

{{C4_ASSESSED_TYPE}} (e.g., Reentrancy, Access Control, Oracle, Math, Other)
