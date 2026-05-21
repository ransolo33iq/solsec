<p align="center">
  <h1 align="center">SOLSEC</h1>
  <p align="center">Solidity Smart Contract Security Auditor</p>
</p>

<p align="center">
  <a href="https://github.com/ransolo33iq/solsec"><img alt="GitHub" src="https://img.shields.io/github/stars/ransolo33iq/solsec?style=flat-square" /></a>
</p>

---

## What is Solsec?

Solsec is an AI-powered Solidity security auditor built on top of [opencode](https://github.com/anomalyco/opencode). It specializes in finding vulnerabilities in smart contracts using:

- **Slither** — Static analysis (100+ detectors)
- **Mythril** — Symbolic execution
- **Forge** — Compilation, testing, fuzzing
- **Echidna** — Property-based fuzzing
- **Solhint** — Linting

## Installation

```bash
# From GitHub releases
gh release download --repo ransolo33iq/solsec --pattern 'solsec-linux-x64' --dir /usr/local/bin/solsec
chmod +x /usr/local/bin/solsec

# Or build from source
git clone https://github.com/ransolo33iq/solsec.git
cd solsec
bun install
bun run --cwd packages/opencode build -- --single --baseline --skip-embed-web-ui
```

## Usage

```bash
# Audit a contract
solsec run "Audit this contract for vulnerabilities" 

# With specific model
solsec run -m gitlawb/mimo-v2.5-pro "Audit Vault.sol"

# Interactive mode
solsec
```

## Features

- **AGENTS.md** — Auto-loaded system prompt with 15-category vulnerability taxonomy
- **Anti-Hallucination** — Every finding requires exact line numbers, code snippets, and PoC
- **Thinking Display** — Shows model reasoning in real-time
- **Context Saver** — Tracks findings across sessions via `.solsec/audit-state.json`
- **Security Tools** — Integrated slither, mythril, forge, echidna, solhint

## Vulnerability Taxonomy

Solsec checks for:
1. Reentrancy (single-function, cross-function, read-only)
2. Access Control
3. Integer Overflow/Underflow
4. Unchecked External Calls
5. Front-Running / MEV
6. Oracle Manipulation
7. Flash Loan Attacks
8. Denial of Service
9. Logic Errors
10. Merkle Proof Verification
11. Arbitrary Function Selectors
12. Code Quality & Hidden Risks
13. Missing Events
14. False Positive Prevention

## Configuration

Config file: `~/.config/solsec/solsec.json`

```json
{
  "model": "gitlawb/mimo-v2.5-pro",
  "provider": {
    "gitlawb": {
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://opengateway.gitlawb.com/v1"
      },
      "models": {
        "mimo-v2.5-pro": {
          "name": "MiMo V2.5 Pro",
          "limit": { "context": 131072, "output": 16384 }
        }
      }
    }
  }
}
```

## CI/CD

Every push to `master` builds binaries for:
- Linux x64 / arm64
- macOS x64 / arm64
- Windows x64

## Credits

Built on [opencode](https://github.com/anomalyco/opencode) by the opencode team.
