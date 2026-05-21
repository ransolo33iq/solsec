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
