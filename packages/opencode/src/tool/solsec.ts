import { Effect, Schema } from "effect"
import * as Tool from "./tool"
import { ChildProcess } from "effect/unstable/process"
import { ChildProcessSpawner } from "effect/unstable/process/ChildProcessSpawner"
import { InstanceState } from "@/effect/instance-state"
import path from "path"

// ============================================================================
// SLITHER — Static Analysis
// ============================================================================

export const SlitherParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Path to Solidity file or project directory" }),
  solc_version: Schema.optional(Schema.String).annotate({ description: "Solidity compiler version (e.g., '0.8.20')" }),
  filter_paths: Schema.optional(Schema.String).annotate({ description: "Comma-separated paths to exclude from analysis" }),
  detectors: Schema.optional(Schema.String).annotate({ description: "Comma-separated detector names to run (e.g., 'reentrancy-eth,arbitrary-send')" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw arguments to pass to slither" }),
})

export const SlitherTool = Tool.define(
  "slither",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner

    return {
      get description() {
        return "Run Slither static analysis on Solidity contracts. Detects reentrancy, unchecked calls, access control issues, and 100+ vulnerability patterns. Returns structured findings with severity, SWC-ID, and line numbers."
      },
      parameters: SlitherParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const target = path.resolve(instance.directory, params.target)
          yield* ctx.metadata({ title: `Slither: ${path.basename(target)}`, metadata: {} })

          const args = [target]
          if (params.solc_version) args.push("--solc-solcs-select", params.solc_version)
          if (params.filter_paths) args.push("--filter-paths", params.filter_paths)
          if (params.detectors) args.push("--detect", params.detectors)
          if (params.args) args.push(...params.args.split(/\s+/))
          args.push("--json", "-")

          const proc = ChildProcess.make("slither", args, {
            cwd: instance.directory,
            env: { ...process.env, PATH: process.env.PATH },
            stdin: "ignore",
          })

          const handle = yield* spawner.spawn(proc).pipe(Effect.orDie)
          const output = yield* handle.stdout.pipe(Effect.orDie)
          const stderr = yield* handle.stderr.pipe(Effect.catch(() => Effect.succeed("")))
          yield* handle.exitCode.pipe(Effect.orDie)

          let result: string
          try {
            const json = JSON.parse(output)
            const detectors = json.detectors || []
            if (detectors.length === 0) {
              result = "Slither found no vulnerabilities."
            } else {
              const lines = [`Slither found ${detectors.length} issue(s):\n`]
              for (const d of detectors) {
                const impact = d.impact || "unknown"
                const confidence = d.confidence || "unknown"
                const check = d.check || "unknown"
                const desc = d.description || d.markdown || ""
                lines.push(`### [${impact.toUpperCase()}] ${check} (confidence: ${confidence})`)
                lines.push(desc)
                if (d.elements) {
                  for (const el of d.elements) {
                    if (el.source_mapping?.lines) {
                      lines.push(`  → ${el.name || "unknown"} at line ${el.source_mapping.lines.join("-")}`)
                    }
                  }
                }
                lines.push("")
              }
              result = lines.join("\n")
            }
          } catch {
            result = output || stderr || "(no output)"
          }

          return {
            title: `Slither: ${path.basename(target)}`,
            metadata: { target, exit: 0 },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// MYTHRIL — Symbolic Execution
// ============================================================================

export const MythrilParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Path to Solidity file" }),
  solc_version: Schema.optional(Schema.String).annotate({ description: "Solidity compiler version" }),
  execution_timeout: Schema.optional(Schema.Number).annotate({ description: "Max execution time in seconds (default: 60)" }),
  max_depth: Schema.optional(Schema.Number).annotate({ description: "Max search depth (default: 22)" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw arguments" }),
})

export const MythrilTool = Tool.define(
  "mythril",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner

    return {
      get description() {
        return "Run Mythril symbolic execution analysis on Solidity contracts. Deep analysis for integer overflow, reentrancy, unchecked calls, and logic errors. Slower but finds vulnerabilities static analyzers miss."
      },
      parameters: MythrilParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const target = path.resolve(instance.directory, params.target)
          yield* ctx.metadata({ title: `Mythril: ${path.basename(target)}`, metadata: {} })

          const args = ["analyze", target]
          if (params.solc_version) args.push("--solv", params.solc_version)
          if (params.execution_timeout) args.push("--execution-timeout", params.execution_timeout.toString())
          if (params.max_depth) args.push("--max-depth", params.max_depth.toString())
          if (params.args) args.push(...params.args.split(/\s+/))
          args.push("-o", "json")

          const proc = ChildProcess.make("myth", args, {
            cwd: instance.directory,
            env: { ...process.env, PATH: process.env.PATH },
            stdin: "ignore",
          })

          const handle = yield* spawner.spawn(proc).pipe(Effect.orDie)
          const output = yield* handle.stdout.pipe(Effect.orDie)
          const stderr = yield* handle.stderr.pipe(Effect.catch(() => Effect.succeed("")))
          yield* handle.exitCode.pipe(Effect.orDie)

          let result: string
          try {
            const json = JSON.parse(output)
            const issues = json.issues || []
            if (issues.length === 0) {
              result = "Mythril found no vulnerabilities."
            } else {
              const lines = [`Mythril found ${issues.length} issue(s):\n`]
              for (const issue of issues) {
                const severity = issue.severity || "unknown"
                const swc = issue.swc_id || "unknown"
                const title = issue.title || "unknown"
                const desc = issue.description || ""
                lines.push(`### [${severity.toUpperCase()}] ${title} — ${swc}`)
                lines.push(desc)
                if (issue.extra?.contracts) {
                  for (const c of issue.extra.contracts) {
                    lines.push(`  → Contract: ${c.address || "unknown"}`)
                  }
                }
                lines.push("")
              }
              result = lines.join("\n")
            }
          } catch {
            result = output || stderr || "(no output)"
          }

          return {
            title: `Mythril: ${path.basename(target)}`,
            metadata: { target, exit: 0 },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// FORGE — Build, Test, Fuzz
// ============================================================================

export const ForgeParameters = Schema.Struct({
  command: Schema.Literals(["build", "test", "snapshot", "inspect", "verify-contract"]).annotate({
    description: "Forge command to run",
  }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional arguments (e.g., '--match-test testReentrancy -vvv')" }),
  root: Schema.optional(Schema.String).annotate({ description: "Project root directory (defaults to current)" }),
})

export const ForgeTool = Tool.define(
  "forge",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner

    return {
      get description() {
        return "Run Foundry forge commands: build (compile contracts), test (run tests with gas reports), snapshot (save gas snapshots), inspect (ABI/bytecode). Use for compilation checks, unit tests, and fuzz testing."
      },
      parameters: ForgeParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          yield* ctx.metadata({ title: `forge ${params.command}`, metadata: {} })

          const args = [params.command]
          if (params.args) args.push(...params.args.split(/\s+/))
          if (params.command === "test") {
            args.push("-vvv", "--json")
          }

          const proc = ChildProcess.make("forge", args, {
            cwd,
            env: { ...process.env, PATH: process.env.PATH },
            stdin: "ignore",
          })

          const handle = yield* spawner.spawn(proc).pipe(Effect.orDie)
          const output = yield* handle.stdout.pipe(Effect.orDie)
          const stderr = yield* handle.stderr.pipe(Effect.catch(() => Effect.succeed("")))
          const exitCode = yield* handle.exitCode.pipe(Effect.orDie)

          let result = output || stderr || "(no output)"
          if (exitCode !== 0) {
            result = `[exit code: ${exitCode}]\n${result}`
          }

          return {
            title: `forge ${params.command}`,
            metadata: { exit: exitCode },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// SOLC — Compiler Checks
// ============================================================================

export const SolcParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Path to Solidity file" }),
  version: Schema.optional(Schema.String).annotate({ description: "Compiler version (e.g., '0.8.20')" }),
  abi: Schema.optional(Schema.Boolean).annotate({ description: "Output ABI" }),
  bin: Schema.optional(Schema.Boolean).annotate({ description: "Output bytecode" }),
  asm: Schema.optional(Schema.Boolean).annotate({ description: "Output assembly" }),
  gas: Schema.optional(Schema.Boolean).annotate({ description: "Output gas estimates" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw arguments" }),
})

export const SolcTool = Tool.define(
  "solc",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner

    return {
      get description() {
        return "Run the Solidity compiler (solc) for syntax checking, ABI extraction, bytecode generation, assembly output, and gas estimates. Use to verify contracts compile and inspect compiler output."
      },
      parameters: SolcParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const target = path.resolve(instance.directory, params.target)
          yield* ctx.metadata({ title: `solc: ${path.basename(target)}`, metadata: {} })

          const bin = params.version ? `solc-${params.version}` : "solc"
          const args = [target]
          if (params.abi) args.push("--abi")
          if (params.bin) args.push("--bin")
          if (params.asm) args.push("--asm")
          if (params.gas) args.push("--gas")
          if (!params.abi && !params.bin && !params.asm && !params.gas) {
            args.push("--abi", "--bin")
          }
          if (params.args) args.push(...params.args.split(/\s+/))

          const proc = ChildProcess.make(bin, args, {
            cwd: instance.directory,
            env: { ...process.env, PATH: process.env.PATH },
            stdin: "ignore",
          })

          const handle = yield* spawner.spawn(proc).pipe(Effect.orDie)
          const output = yield* handle.stdout.pipe(Effect.orDie)
          const stderr = yield* handle.stderr.pipe(Effect.catch(() => Effect.succeed("")))
          const exitCode = yield* handle.exitCode.pipe(Effect.orDie)

          let result = output || stderr || "(no output)"
          if (exitCode !== 0) {
            result = `[compilation failed, exit code: ${exitCode}]\n${stderr || output}`
          }

          return {
            title: `solc: ${path.basename(target)}`,
            metadata: { target, exit: exitCode },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// ECHIDNA — Property-Based Fuzzing
// ============================================================================

export const EchidnaParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Path to Solidity file" }),
  contract: Schema.String.annotate({ description: "Contract name to test" }),
  config: Schema.optional(Schema.String).annotate({ description: "Path to echidna config file" }),
  test_limit: Schema.optional(Schema.Number).annotate({ description: "Number of test sequences to run (default: 50000)" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw arguments" }),
})

export const EchidnaTool = Tool.define(
  "echidna",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner

    return {
      get description() {
        return "Run Echidna property-based fuzzer on Solidity contracts. Tests invariant violations by generating random transaction sequences. Finds edge-case bugs that static analysis and manual review miss."
      },
      parameters: EchidnaParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const target = path.resolve(instance.directory, params.target)
          yield* ctx.metadata({ title: `Echidna: ${params.contract}`, metadata: {} })

          const args = [target, "--contract", params.contract]
          if (params.config) args.push("--config", params.config)
          if (params.test_limit) args.push("--test-limit", params.test_limit.toString())
          if (params.args) args.push(...params.args.split(/\s+/))

          const proc = ChildProcess.make("echidna", args, {
            cwd: instance.directory,
            env: { ...process.env, PATH: process.env.PATH },
            stdin: "ignore",
          })

          const handle = yield* spawner.spawn(proc).pipe(Effect.orDie)
          const output = yield* handle.stdout.pipe(Effect.orDie)
          const stderr = yield* handle.stderr.pipe(Effect.catch(() => Effect.succeed("")))
          const exitCode = yield* handle.exitCode.pipe(Effect.orDie)

          let result = output || stderr || "(no output)"
          if (exitCode !== 0) {
            result = `[exit code: ${exitCode}]\n${result}`
          }

          return {
            title: `Echidna: ${params.contract}`,
            metadata: { target, exit: exitCode },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// MANTICORE — Symbolic Execution (EVM)
// ============================================================================

export const ManticoreParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Path to Solidity file" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional arguments" }),
})

export const ManticoreTool = Tool.define(
  "manticore",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner

    return {
      get description() {
        return "Run Manticore symbolic execution on Solidity contracts. Explores all execution paths to find vulnerabilities. Generates concrete test cases for each bug found."
      },
      parameters: ManticoreParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const target = path.resolve(instance.directory, params.target)
          yield* ctx.metadata({ title: `Manticore: ${path.basename(target)}`, metadata: {} })

          const args = [target]
          if (params.args) args.push(...params.args.split(/\s+/))

          const proc = ChildProcess.make("manticore", args, {
            cwd: instance.directory,
            env: { ...process.env, PATH: process.env.PATH },
            stdin: "ignore",
          })

          const handle = yield* spawner.spawn(proc).pipe(Effect.orDie)
          const output = yield* handle.stdout.pipe(Effect.orDie)
          const stderr = yield* handle.stderr.pipe(Effect.catch(() => Effect.succeed("")))
          const exitCode = yield* handle.exitCode.pipe(Effect.orDie)

          let result = output || stderr || "(no output)"
          if (exitCode !== 0) {
            result = `[exit code: ${exitCode}]\n${result}`
          }

          return {
            title: `Manticore: ${path.basename(target)}`,
            metadata: { target, exit: exitCode },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// Helpers shared by the new wrappers
// ============================================================================

function spawnCollect(opts: {
  cmd: string
  args: string[]
  cwd: string
  spawner: any
  timeoutMs?: number
}) {
  return Effect.gen(function* () {
    const proc = ChildProcess.make(opts.cmd, opts.args, {
      cwd: opts.cwd,
      env: { ...process.env, PATH: process.env.PATH },
      stdin: "ignore",
    })
    const handle = yield* opts.spawner.spawn(proc).pipe(Effect.orDie)
    const stdout = yield* handle.stdout.pipe(Effect.orDie)
    const stderr = yield* handle.stderr.pipe(Effect.catch(() => Effect.succeed("")))
    const exit = yield* handle.exitCode.pipe(Effect.orDie)
    return { stdout, stderr, exit }
  })
}

// ============================================================================
// HALMOS — Symbolic execution for Foundry tests
// ============================================================================

export const HalmosParameters = Schema.Struct({
  contract: Schema.optional(Schema.String).annotate({ description: "Contract name to symbolically execute" }),
  function: Schema.optional(Schema.String).annotate({ description: "Function name (or pattern) to prove (e.g., 'check_*', 'invariant_*')" }),
  solver_timeout_assertion: Schema.optional(Schema.Number).annotate({ description: "Per-assertion solver timeout in ms (default: 1000)" }),
  loop: Schema.optional(Schema.Number).annotate({ description: "Loop unroll bound (default: 2)" }),
  root: Schema.optional(Schema.String).annotate({ description: "Foundry project root (defaults to instance directory)" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const HalmosTool = Tool.define(
  "halmos",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run halmos (a16z) symbolic execution on Foundry tests. Proves invariants, finds counterexamples, supports check_* and invariant_* test functions. Uses Z3 (with cvc5/bitwuzla as backups). Use for formal verification of high-value functions."
      },
      parameters: HalmosParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          yield* ctx.metadata({ title: `halmos${params.contract ? ` ${params.contract}` : ""}`, metadata: {} })
          const args: string[] = []
          if (params.contract) args.push("--contract", params.contract)
          if (params.function) args.push("--function", params.function)
          if (params.solver_timeout_assertion !== undefined)
            args.push("--solver-timeout-assertion", params.solver_timeout_assertion.toString())
          if (params.loop !== undefined) args.push("--loop", params.loop.toString())
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "halmos", args, cwd, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `halmos${params.contract ? ` ${params.contract}` : ""}`,
            metadata: { exit: r.exit, contract: params.contract, function: params.function },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// KONTROL — K-framework symbolic prover (Runtime Verification)
// ============================================================================

export const KontrolParameters = Schema.Struct({
  command: Schema.Literals(["build", "prove", "show", "summary", "view-kcfg"]).annotate({
    description: "Kontrol subcommand to run",
  }),
  match_test: Schema.optional(Schema.String).annotate({ description: "Test pattern for `prove` (e.g., 'TestMyContract.testInvariant_*')" }),
  root: Schema.optional(Schema.String).annotate({ description: "Foundry project root" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const KontrolTool = Tool.define(
  "kontrol",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run Kontrol (Runtime Verification) K-framework symbolic prover on Foundry tests. Stronger than halmos for complex arithmetic / loop reasoning. Use for high-stakes invariants where halmos times out."
      },
      parameters: KontrolParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          yield* ctx.metadata({ title: `kontrol ${params.command}`, metadata: {} })
          const args = [params.command]
          if (params.match_test) args.push("--match-test", params.match_test)
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "kontrol", args, cwd, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `kontrol ${params.command}`,
            metadata: { exit: r.exit, command: params.command },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// MEDUSA — Coverage-guided fuzzer (crytic)
// ============================================================================

export const MedusaParameters = Schema.Struct({
  command: Schema.Literals(["fuzz", "init", "completion"]).annotate({ description: "Medusa subcommand" }),
  config: Schema.optional(Schema.String).annotate({ description: "Path to medusa.json config" }),
  test_limit: Schema.optional(Schema.Number).annotate({ description: "Max number of test sequences" }),
  workers: Schema.optional(Schema.Number).annotate({ description: "Worker count" }),
  root: Schema.optional(Schema.String).annotate({ description: "Project root" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const MedusaTool = Tool.define(
  "medusa",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run Medusa (crytic) coverage-guided EVM fuzzer. Better corpus management than echidna; finds invariant violations through guided random sequences. Pair with `assertion()` properties or invariant_*."
      },
      parameters: MedusaParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          yield* ctx.metadata({ title: `medusa ${params.command}`, metadata: {} })
          const args = [params.command]
          if (params.config) args.push("--config", params.config)
          if (params.test_limit !== undefined) args.push("--test-limit", params.test_limit.toString())
          if (params.workers !== undefined) args.push("--workers", params.workers.toString())
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "medusa", args, cwd, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `medusa ${params.command}`,
            metadata: { exit: r.exit },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// ADERYN — Cyfrin Rust-based static analyzer
// ============================================================================

export const AderynParameters = Schema.Struct({
  root: Schema.optional(Schema.String).annotate({ description: "Project root (defaults to instance directory)" }),
  exclude: Schema.optional(Schema.String).annotate({ description: "Comma-separated paths to exclude" }),
  scope: Schema.optional(Schema.String).annotate({ description: "Comma-separated scope paths to include" }),
  output_format: Schema.optional(Schema.Literals(["markdown", "json", "sarif"])).annotate({
    description: "Report format (default: json for parsing)",
  }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const AderynTool = Tool.define(
  "aderyn",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run Aderyn (Cyfrin) Rust-based static analyzer. Faster than slither, complementary detector set, supports SARIF for CI. Reports issues by severity with file:line evidence."
      },
      parameters: AderynParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          yield* ctx.metadata({ title: `aderyn`, metadata: {} })
          const fmt = params.output_format ?? "json"
          const args = ["."]
          if (params.exclude) args.push("--exclude", params.exclude)
          if (params.scope) args.push("--scope", params.scope)
          args.push("--output", `report.${fmt === "markdown" ? "md" : fmt === "sarif" ? "sarif" : "json"}`)
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "aderyn", args, cwd, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `aderyn`,
            metadata: { exit: r.exit, format: fmt, root: cwd },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// SEMGREP — Pattern matcher (with Solidity ruleset)
// ============================================================================

export const SemgrepParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "File or directory to scan" }),
  config: Schema.optional(Schema.String).annotate({
    description: "Ruleset path or registry id (default: .solsec/semgrep/solidity)",
  }),
  severity: Schema.optional(Schema.Literals(["INFO", "WARNING", "ERROR"])).annotate({
    description: "Minimum severity",
  }),
  json: Schema.optional(Schema.Boolean).annotate({ description: "Emit JSON (default: true for parsing)" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const SemgrepTool = Tool.define(
  "semgrep",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run Semgrep with the Solidity vulnerability ruleset. Pattern-matches known unsafe idioms (arbitrary delegatecall, missing zero-address check, EIP-2612 chainID errors, etc.). Solsec ships rules under .solsec/semgrep/solidity."
      },
      parameters: SemgrepParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const target = path.resolve(instance.directory, params.target)
          const cfgPath = params.config ?? path.join(instance.directory, ".solsec", "semgrep", "solidity")
          yield* ctx.metadata({ title: `semgrep ${path.basename(target)}`, metadata: {} })
          const args = ["--config", cfgPath, target]
          if (params.severity) args.push("--severity", params.severity)
          if (params.json !== false) args.push("--json")
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "semgrep", args, cwd: instance.directory, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `semgrep ${path.basename(target)}`,
            metadata: { exit: r.exit, target, config: cfgPath },
            output: r.exit !== 0 && r.exit !== 1 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// HEIMDALL — EVM bytecode decompiler
// ============================================================================

export const HeimdallParameters = Schema.Struct({
  command: Schema.Literals(["decompile", "disassemble", "cfg", "snapshot", "decode"]).annotate({
    description: "Heimdall subcommand",
  }),
  target: Schema.String.annotate({
    description: "0x... address, raw bytecode (0x...), or path to bytecode file",
  }),
  rpc: Schema.optional(Schema.String).annotate({ description: "RPC URL for on-chain targets" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const HeimdallTool = Tool.define(
  "heimdall",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run Heimdall on raw EVM bytecode or on-chain addresses. `decompile` produces solidity-like pseudocode; `cfg` produces a control-flow graph; `snapshot` summarizes selectors + behaviors. Use on unverified contracts."
      },
      parameters: HeimdallParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          yield* ctx.metadata({ title: `heimdall ${params.command}`, metadata: {} })
          const args = [params.command, params.target]
          if (params.rpc) args.push("--rpc-url", params.rpc)
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "heimdall", args, cwd: instance.directory, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `heimdall ${params.command}`,
            metadata: { exit: r.exit, target: params.target },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// WAKE — Ackee Wake detectors
// ============================================================================

export const WakeParameters = Schema.Struct({
  command: Schema.Literals(["detect", "compile", "init"]).annotate({ description: "Wake subcommand" }),
  detector: Schema.optional(Schema.String).annotate({ description: "Detector name (default: 'all')" }),
  root: Schema.optional(Schema.String).annotate({ description: "Project root" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const WakeTool = Tool.define(
  "wake",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run Ackee Wake detectors (`wake detect all`). Complementary to slither/aderyn, with strong DeFi-pattern detectors (oracle, governance, ERC standard deviations). Pair with the other static analyzers — false positives drop with the intersection."
      },
      parameters: WakeParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          yield* ctx.metadata({ title: `wake ${params.command}`, metadata: {} })
          const args = [params.command]
          if (params.command === "detect") args.push(params.detector ?? "all")
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "wake", args, cwd, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `wake ${params.command}`,
            metadata: { exit: r.exit, command: params.command },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// CAST — typed wrapper over Foundry cast (call, sig, 4byte, abi-decode, ...)
// ============================================================================

export const CastParameters = Schema.Struct({
  subcommand: Schema.String.annotate({
    description:
      "cast subcommand (e.g., 'call', 'storage', 'sig', '4byte', 'abi-decode', 'receipt', 'run', 'trace', 'logs', 'block-number', 'chain-id', 'balance', 'nonce', 'code')",
  }),
  args: Schema.optional(Schema.String).annotate({
    description: "Positional + flag arguments forwarded to cast (e.g., '0xabc... balanceOf(address) 0xdef... --rpc-url https://eth.llamarpc.com')",
  }),
  rpc: Schema.optional(Schema.String).annotate({ description: "RPC URL (alias for --rpc-url)" }),
})

export const CastTool = Tool.define(
  "cast",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run Foundry `cast` for chain interaction: `call`/`storage` to read state, `sig` to compute selectors, `4byte` to look them up, `abi-decode` to decode calldata/returns, `receipt`/`trace`/`run` for tx forensics, `logs` for event scanning. Use against arbitrary RPC endpoints."
      },
      parameters: CastParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          yield* ctx.metadata({ title: `cast ${params.subcommand}`, metadata: {} })
          const args = [params.subcommand]
          if (params.args) args.push(...params.args.split(/\s+/))
          if (params.rpc) args.push("--rpc-url", params.rpc)
          const r = yield* spawnCollect({ cmd: "cast", args, cwd: instance.directory, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `cast ${params.subcommand}`,
            metadata: { exit: r.exit, subcommand: params.subcommand },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// SOLHINT — Solidity linter
// ============================================================================

export const SolhintParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Glob or file to lint (e.g., 'contracts/**/*.sol')" }),
  config: Schema.optional(Schema.String).annotate({ description: "Config file path (default: .solhint.json)" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const SolhintTool = Tool.define(
  "solhint",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run solhint to enforce Solidity style + security best practices (no-tx-origin, avoid-low-level-calls, reentrancy, etc.). Lightweight check before slither/aderyn."
      },
      parameters: SolhintParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          yield* ctx.metadata({ title: `solhint ${params.target}`, metadata: {} })
          const args: string[] = []
          if (params.config) args.push("--config", params.config)
          if (params.args) args.push(...params.args.split(/\s+/))
          args.push(params.target)
          const r = yield* spawnCollect({ cmd: "solhint", args, cwd: instance.directory, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `solhint ${params.target}`,
            metadata: { exit: r.exit, target: params.target },
            output: r.exit !== 0 && r.exit !== 1 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// ANVIL — local mainnet fork management
// ============================================================================

export const AnvilParameters = Schema.Struct({
  fork_url: Schema.optional(Schema.String).annotate({ description: "Upstream RPC to fork (e.g., 'https://eth.llamarpc.com')" }),
  fork_block: Schema.optional(Schema.Number).annotate({ description: "Pin fork to specific block number" }),
  port: Schema.optional(Schema.Number).annotate({ description: "Local port (default: 8545)" }),
  chain_id: Schema.optional(Schema.Number).annotate({ description: "Override chain id" }),
  detach: Schema.optional(Schema.Boolean).annotate({
    description: "Spawn in background and return RPC URL + pid (default: false)",
  }),
  duration_seconds: Schema.optional(Schema.Number).annotate({
    description: "When non-detached, run for at most N seconds and capture output",
  }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional raw flags" }),
})

export const AnvilTool = Tool.define(
  "anvil",
  Effect.gen(function* () {
    return {
      get description() {
        return "Start a local anvil fork (Foundry). Detached mode returns an RPC URL + pid that subsequent forge/cast tools can use with --fork-url. Use to replay attacks against mainnet state without sending real txs."
      },
      parameters: AnvilParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          yield* ctx.metadata({ title: `anvil`, metadata: {} })
          const args: string[] = []
          if (params.fork_url) args.push("--fork-url", params.fork_url)
          if (params.fork_block !== undefined) args.push("--fork-block-number", params.fork_block.toString())
          if (params.port !== undefined) args.push("--port", params.port.toString())
          if (params.chain_id !== undefined) args.push("--chain-id", params.chain_id.toString())
          if (params.args) args.push(...params.args.split(/\s+/))
          if (params.detach) {
            const ret = yield* Effect.promise(async () => {
              const { spawn } = await import("child_process")
              const child = spawn("anvil", args, {
                cwd: instance.directory,
                env: process.env,
                detached: true,
                stdio: ["ignore", "pipe", "pipe"],
              })
              child.unref()
              let banner = ""
              const t = new Promise<void>((resolve) => setTimeout(resolve, 1500))
              child.stdout?.on("data", (d) => (banner += d.toString()))
              child.stderr?.on("data", (d) => (banner += d.toString()))
              await t
              return { pid: child.pid, banner: banner.slice(0, 4000) }
            })
            const port = params.port ?? 8545
            return {
              title: `anvil (detached pid ${ret.pid})`,
              metadata: { detached: true, pid: ret.pid, rpcUrl: `http://127.0.0.1:${port}` },
              output: `anvil started in background\npid: ${ret.pid}\nrpc: http://127.0.0.1:${port}\n\n${ret.banner}`,
            }
          }
          const ret = yield* Effect.promise(async () => {
            const { spawn } = await import("child_process")
            return new Promise<{ stdout: string; stderr: string; exit: number }>((resolve) => {
              const child = spawn("anvil", args, {
                cwd: instance.directory,
                env: process.env,
                stdio: ["ignore", "pipe", "pipe"],
              })
              let stdout = ""
              let stderr = ""
              const timer = params.duration_seconds
                ? setTimeout(() => child.kill("SIGTERM"), params.duration_seconds * 1000)
                : undefined
              child.stdout?.on("data", (d) => (stdout += d.toString()))
              child.stderr?.on("data", (d) => (stderr += d.toString()))
              child.on("close", (code) => {
                if (timer) clearTimeout(timer)
                resolve({ stdout, stderr, exit: code ?? 0 })
              })
            })
          })
          const result = (ret.stdout || ret.stderr || "(no output)").slice(0, 60_000)
          return {
            title: `anvil`,
            metadata: { exit: ret.exit, fork_url: params.fork_url, fork_block: params.fork_block },
            output: result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// FORGE-FORK-TEST — opinionated fork-pinned PoC harness
// ============================================================================

export const ForgeForkTestParameters = Schema.Struct({
  test_path: Schema.String.annotate({ description: "Foundry test file path (e.g., 'test/Exploit.t.sol')" }),
  match_test: Schema.optional(Schema.String).annotate({ description: "Test function pattern (e.g., 'testExploit*')" }),
  fork_url: Schema.String.annotate({ description: "Upstream RPC URL for fork" }),
  fork_block: Schema.Number.annotate({ description: "Pinned block number for reproducibility" }),
  verbosity: Schema.optional(Schema.Number).annotate({ description: "vvv-level (default: 4)" }),
  args: Schema.optional(Schema.String).annotate({ description: "Additional forge test flags" }),
  root: Schema.optional(Schema.String).annotate({ description: "Project root" }),
})

export const ForgeForkTestTool = Tool.define(
  "forge_fork_test",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run a Foundry test against a fork pinned to a specific block. Reproducible, profit-asserting PoC harness for 1day exploits and bounty submissions. Captures gas, profit deltas, and traces. NEVER `vm.store` directly into protocol storage — use legitimate state transitions."
      },
      parameters: ForgeForkTestParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          yield* ctx.metadata({ title: `forge fork-test ${params.test_path}@${params.fork_block}`, metadata: {} })
          const v = "v".repeat(params.verbosity ?? 4)
          const args = [
            "test",
            "--match-path",
            params.test_path,
            "--fork-url",
            params.fork_url,
            "--fork-block-number",
            params.fork_block.toString(),
            `-${v}`,
          ]
          if (params.match_test) args.push("--match-test", params.match_test)
          if (params.args) args.push(...params.args.split(/\s+/))
          const r = yield* spawnCollect({ cmd: "forge", args, cwd, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 80_000)
          return {
            title: `forge fork-test ${path.basename(params.test_path)}`,
            metadata: {
              exit: r.exit,
              fork_url: params.fork_url,
              fork_block: params.fork_block,
              test_path: params.test_path,
            },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)

// ============================================================================
// ECHIDNA-INVARIANT — generates a config + runs echidna for invariant suite
// ============================================================================

export const EchidnaInvariantParameters = Schema.Struct({
  target: Schema.String.annotate({ description: "Solidity file containing the invariant contract" }),
  contract: Schema.String.annotate({ description: "Contract name (must define echidna_* / invariant_* / assert(...) properties)" }),
  test_limit: Schema.optional(Schema.Number).annotate({ description: "Sequence test limit (default: 50000)" }),
  seq_len: Schema.optional(Schema.Number).annotate({ description: "Max calls per sequence (default: 100)" }),
  shrink_limit: Schema.optional(Schema.Number).annotate({ description: "Counterexample shrinker iterations (default: 5000)" }),
  corpus_dir: Schema.optional(Schema.String).annotate({ description: "Coverage corpus directory" }),
  config: Schema.optional(Schema.String).annotate({ description: "Pre-existing config file (overrides auto-generated)" }),
  root: Schema.optional(Schema.String).annotate({ description: "Project root" }),
})

export const EchidnaInvariantTool = Tool.define(
  "echidna_invariant",
  Effect.gen(function* () {
    const spawner = yield* ChildProcessSpawner
    return {
      get description() {
        return "Run echidna with an auto-generated YAML config tuned for invariant fuzzing (longer sequences, larger shrink budget, optional corpus dir). Use after writing echidna_* / invariant_* properties for the contract under audit."
      },
      parameters: EchidnaInvariantParameters,
      execute: (params, ctx) =>
        Effect.gen(function* () {
          const instance = yield* InstanceState.context
          const cwd = params.root ? path.resolve(instance.directory, params.root) : instance.directory
          const target = path.resolve(cwd, params.target)
          yield* ctx.metadata({ title: `echidna-invariant ${params.contract}`, metadata: {} })
          let configPath = params.config
          if (!configPath) {
            const yaml =
              [
                `testMode: assertion`,
                `testLimit: ${params.test_limit ?? 50000}`,
                `seqLen: ${params.seq_len ?? 100}`,
                `shrinkLimit: ${params.shrink_limit ?? 5000}`,
                params.corpus_dir ? `corpusDir: ${params.corpus_dir}` : null,
                `coverage: true`,
              ]
                .filter(Boolean)
                .join("\n") + "\n"
            const tmp = path.join(cwd, ".solsec-echidna.yml")
            yield* Effect.promise(async () => {
              const fs = await import("fs/promises")
              await fs.writeFile(tmp, yaml, "utf8")
            })
            configPath = tmp
          }
          const args = [target, "--contract", params.contract, "--config", configPath]
          const r = yield* spawnCollect({ cmd: "echidna", args, cwd, spawner })
          const result = (r.stdout || r.stderr || "(no output)").slice(0, 80_000)
          return {
            title: `echidna-invariant ${params.contract}`,
            metadata: { exit: r.exit, target, contract: params.contract, config: configPath },
            output: r.exit !== 0 ? `[exit ${r.exit}]\n${result}` : result,
          }
        }).pipe(Effect.orDie),
    }
  }),
)
