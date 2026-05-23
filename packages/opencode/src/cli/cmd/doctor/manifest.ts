/**
 * Tool manifest for `solsec doctor`. Each entry describes how to detect, install,
 * and verify a security tool used by the audit pipeline. Versions are pinned for
 * reproducibility — bump deliberately, not by drift.
 *
 * Categories:
 *   - core:  hard-required for any audit (slither, forge, foundry suite, solc)
 *   - sast:  static analysis (aderyn, semgrep, wake, slither-mutate)
 *   - sym:   symbolic / formal (halmos, kontrol, mythril, manticore)
 *   - fuzz:  property fuzzers (echidna, medusa, ityfuzz)
 *   - chain: on-chain helpers (heimdall, 4byte, crytic-compile)
 *   - smt:   SMT solvers (z3 via halmos, cvc5, bitwuzla)
 *   - lint:  style/lint (solhint)
 */

export type ToolCategory = "core" | "sast" | "sym" | "fuzz" | "chain" | "smt" | "lint"

export type ToolInstaller =
  | { kind: "pip"; pkg: string; version?: string }
  | { kind: "pipx"; pkg: string; version?: string }
  | { kind: "cargo"; pkg: string; version?: string; bin?: string }
  | { kind: "npm"; pkg: string; version?: string }
  | { kind: "curl-bash"; url: string }
  | { kind: "github-release"; repo: string; asset: string; version?: string; binIn?: string }
  | { kind: "foundryup"; tool?: string }
  | { kind: "manual"; instructions: string }

export interface ToolSpec {
  name: string
  bin: string
  category: ToolCategory
  description: string
  versionFlag: string
  versionRegex?: RegExp
  pinned?: string
  installers: ToolInstaller[]
  required: boolean
  homepage: string
}

const semver = /\b(\d+\.\d+\.\d+(?:[-+][\w.]+)?)\b/

export const TOOLS: ToolSpec[] = [
  // ── core ──────────────────────────────────────────────────────────────────
  {
    name: "slither",
    bin: "slither",
    category: "core",
    description: "Static analyzer with 100+ Solidity detectors",
    versionFlag: "--version",
    versionRegex: semver,
    pinned: "0.11.5",
    installers: [{ kind: "pipx", pkg: "slither-analyzer", version: "0.11.5" }],
    required: true,
    homepage: "https://github.com/crytic/slither",
  },
  {
    name: "solc-select",
    bin: "solc-select",
    category: "core",
    description: "Multi-version solc manager (used by slither)",
    versionFlag: "versions",
    versionRegex: /^(.*)$/m,
    installers: [{ kind: "pipx", pkg: "solc-select" }],
    required: true,
    homepage: "https://github.com/crytic/solc-select",
  },
  {
    name: "forge",
    bin: "forge",
    category: "core",
    description: "Foundry compiler / test runner",
    versionFlag: "--version",
    versionRegex: /(\d+\.\d+\.\d+(?:-\w+)?)/,
    installers: [{ kind: "foundryup", tool: "forge" }],
    required: true,
    homepage: "https://book.getfoundry.sh",
  },
  {
    name: "cast",
    bin: "cast",
    category: "core",
    description: "Foundry chain interaction CLI",
    versionFlag: "--version",
    versionRegex: /(\d+\.\d+\.\d+(?:-\w+)?)/,
    installers: [{ kind: "foundryup", tool: "cast" }],
    required: true,
    homepage: "https://book.getfoundry.sh",
  },
  {
    name: "anvil",
    bin: "anvil",
    category: "core",
    description: "Foundry local fork / mainnet replay",
    versionFlag: "--version",
    versionRegex: /(\d+\.\d+\.\d+(?:-\w+)?)/,
    installers: [{ kind: "foundryup", tool: "anvil" }],
    required: true,
    homepage: "https://book.getfoundry.sh",
  },
  {
    name: "chisel",
    bin: "chisel",
    category: "core",
    description: "Foundry Solidity REPL",
    versionFlag: "--version",
    versionRegex: /(\d+\.\d+\.\d+(?:-\w+)?)/,
    installers: [{ kind: "foundryup", tool: "chisel" }],
    required: false,
    homepage: "https://book.getfoundry.sh",
  },

  // ── sast ──────────────────────────────────────────────────────────────────
  {
    name: "aderyn",
    bin: "aderyn",
    category: "sast",
    description: "Fast Rust-based Solidity static analyzer (Cyfrin)",
    versionFlag: "--version",
    versionRegex: semver,
    pinned: "0.5.5",
    installers: [
      { kind: "cargo", pkg: "aderyn", version: "0.5.5" },
      {
        kind: "curl-bash",
        url: "https://raw.githubusercontent.com/Cyfrin/up/main/install",
      },
    ],
    required: false,
    homepage: "https://github.com/Cyfrin/aderyn",
  },
  {
    name: "semgrep",
    bin: "semgrep",
    category: "sast",
    description: "Pattern-based static analyzer (with Solidity ruleset)",
    versionFlag: "--version",
    versionRegex: semver,
    pinned: "1.96.0",
    installers: [{ kind: "pipx", pkg: "semgrep", version: "1.96.0" }],
    required: false,
    homepage: "https://semgrep.dev",
  },
  {
    name: "wake",
    bin: "wake",
    category: "sast",
    description: "Ackee Wake — Solidity dev framework with detectors",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [{ kind: "pipx", pkg: "eth-wake" }],
    required: false,
    homepage: "https://github.com/Ackee-Blockchain/wake",
  },
  {
    name: "slither-mutate",
    bin: "slither-mutate",
    category: "sast",
    description: "Mutation testing for Solidity (ships with slither-analyzer)",
    versionFlag: "--help",
    installers: [{ kind: "pipx", pkg: "slither-analyzer", version: "0.11.5" }],
    required: false,
    homepage: "https://github.com/crytic/slither",
  },
  {
    name: "solhint",
    bin: "solhint",
    category: "lint",
    description: "Solidity linter for style + best practices",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [{ kind: "npm", pkg: "solhint" }],
    required: false,
    homepage: "https://protofire.github.io/solhint/",
  },

  // ── sym ───────────────────────────────────────────────────────────────────
  {
    name: "halmos",
    bin: "halmos",
    category: "sym",
    description: "Symbolic execution for Foundry tests (a16z)",
    versionFlag: "--version",
    versionRegex: semver,
    pinned: "0.3.3",
    installers: [{ kind: "pipx", pkg: "halmos", version: "0.3.3" }],
    required: false,
    homepage: "https://github.com/a16z/halmos",
  },
  {
    name: "kontrol",
    bin: "kontrol",
    category: "sym",
    description: "K-framework symbolic prover for Foundry (Runtime Verification)",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [
      {
        kind: "manual",
        instructions:
          "curl --proto '=https' --tlsv1.2 -sSf https://kframework.org/install | bash; kup install kontrol",
      },
    ],
    required: false,
    homepage: "https://github.com/runtimeverification/kontrol",
  },
  {
    name: "myth",
    bin: "myth",
    category: "sym",
    description: "Mythril symbolic execution",
    versionFlag: "version",
    versionRegex: semver,
    installers: [{ kind: "pipx", pkg: "mythril" }],
    required: false,
    homepage: "https://github.com/Consensys/mythril",
  },
  {
    name: "heimdall",
    bin: "heimdall",
    category: "chain",
    description: "EVM bytecode decompiler / disassembler",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [
      {
        kind: "curl-bash",
        url: "https://raw.githubusercontent.com/Jon-Becker/heimdall-rs/main/bifrost/install",
      },
    ],
    required: false,
    homepage: "https://github.com/Jon-Becker/heimdall-rs",
  },

  // ── fuzz ──────────────────────────────────────────────────────────────────
  {
    name: "echidna",
    bin: "echidna",
    category: "fuzz",
    description: "Property-based fuzzer for EVM smart contracts",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [
      {
        kind: "github-release",
        repo: "crytic/echidna",
        asset: "echidna-{version}-x86_64-linux.tar.gz",
        binIn: "echidna",
      },
    ],
    required: false,
    homepage: "https://github.com/crytic/echidna",
  },
  {
    name: "medusa",
    bin: "medusa",
    category: "fuzz",
    description: "Coverage-guided fuzzer for EVM (crytic)",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [
      {
        kind: "github-release",
        repo: "crytic/medusa",
        asset: "medusa-linux-x64.tar.gz",
        binIn: "medusa",
      },
    ],
    required: false,
    homepage: "https://github.com/crytic/medusa",
  },

  // ── smt ───────────────────────────────────────────────────────────────────
  {
    name: "z3",
    bin: "z3",
    category: "smt",
    description: "Z3 SMT solver (auto-installed via halmos pip dep)",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [{ kind: "pip", pkg: "z3-solver" }],
    required: false,
    homepage: "https://github.com/Z3Prover/z3",
  },
  {
    name: "cvc5",
    bin: "cvc5",
    category: "smt",
    description: "cvc5 SMT solver — backup for halmos hard cases",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [
      { kind: "pip", pkg: "cvc5" },
      {
        kind: "github-release",
        repo: "cvc5/cvc5",
        asset: "cvc5-Linux-x86_64-static.zip",
        binIn: "bin/cvc5",
      },
    ],
    required: false,
    homepage: "https://github.com/cvc5/cvc5",
  },
  {
    name: "bitwuzla",
    bin: "bitwuzla",
    category: "smt",
    description: "Bitwuzla SMT solver — fastest on bitvector arithmetic",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [{ kind: "pip", pkg: "bitwuzla" }],
    required: false,
    homepage: "https://github.com/bitwuzla/bitwuzla",
  },

  // ── chain helpers ─────────────────────────────────────────────────────────
  {
    name: "crytic-compile",
    bin: "crytic-compile",
    category: "chain",
    description: "Multi-framework Solidity compile (slither/echidna dep)",
    versionFlag: "--version",
    versionRegex: semver,
    installers: [{ kind: "pipx", pkg: "crytic-compile" }],
    required: false,
    homepage: "https://github.com/crytic/crytic-compile",
  },
]

export function findTool(name: string): ToolSpec | undefined {
  return TOOLS.find((t) => t.name === name || t.bin === name)
}

export function toolsByCategory(category: ToolCategory): ToolSpec[] {
  return TOOLS.filter((t) => t.category === category)
}
