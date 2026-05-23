import { Effect } from "effect"
import { spawn } from "child_process"
import * as os from "os"
import * as path from "path"
import * as fs from "fs/promises"
import { UI } from "../../ui"
import { effectCmd, fail } from "../../effect-cmd"
import { TOOLS, type ToolSpec, type ToolInstaller, findTool, type ToolCategory } from "./manifest"

interface ToolStatus {
  spec: ToolSpec
  installed: boolean
  path?: string
  version?: string
  error?: string
}

function run(cmd: string, args: string[], opts?: { timeout?: number }): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { env: process.env })
    let stdout = ""
    let stderr = ""
    let killed = false
    const timer = opts?.timeout
      ? setTimeout(() => {
          killed = true
          proc.kill("SIGTERM")
        }, opts.timeout)
      : undefined
    proc.stdout?.on("data", (d) => (stdout += d.toString()))
    proc.stderr?.on("data", (d) => (stderr += d.toString()))
    proc.on("error", (e) => {
      if (timer) clearTimeout(timer)
      resolve({ code: 127, stdout, stderr: stderr + e.message })
    })
    proc.on("close", (code) => {
      if (timer) clearTimeout(timer)
      resolve({ code: killed ? 124 : (code ?? 1), stdout, stderr })
    })
  })
}

async function which(bin: string): Promise<string | undefined> {
  const r = await run(process.platform === "win32" ? "where" : "which", [bin], { timeout: 3000 })
  if (r.code !== 0) return undefined
  return r.stdout.split(/\r?\n/).find((l) => l.trim().length > 0)?.trim()
}

async function checkOne(spec: ToolSpec): Promise<ToolStatus> {
  const p = await which(spec.bin)
  if (!p) return { spec, installed: false }
  const args = spec.versionFlag.split(/\s+/).filter(Boolean)
  const r = await run(spec.bin, args, { timeout: 5000 })
  const out = (r.stdout + "\n" + r.stderr).trim()
  const m = spec.versionRegex ? out.match(spec.versionRegex) : null
  return {
    spec,
    installed: true,
    path: p,
    version: m ? m[1] : out.split(/\r?\n/)[0]?.slice(0, 80),
  }
}

function colorStatus(s: ToolStatus) {
  if (s.installed) return UI.Style.TEXT_SUCCESS_BOLD + "✓" + UI.Style.TEXT_NORMAL
  if (s.spec.required) return UI.Style.TEXT_DANGER_BOLD + "✗" + UI.Style.TEXT_NORMAL
  return UI.Style.TEXT_WARNING_BOLD + "○" + UI.Style.TEXT_NORMAL
}

function describeInstaller(i: ToolInstaller): string {
  switch (i.kind) {
    case "pip":
      return `pip install ${i.pkg}${i.version ? `==${i.version}` : ""}`
    case "pipx":
      return `pipx install ${i.pkg}${i.version ? `==${i.version}` : ""}`
    case "cargo":
      return `cargo install ${i.pkg}${i.version ? ` --version ${i.version}` : ""}`
    case "npm":
      return `npm install -g ${i.pkg}${i.version ? `@${i.version}` : ""}`
    case "curl-bash":
      return `curl -sSL ${i.url} | bash`
    case "github-release":
      return `download ${i.repo} release${i.version ? ` ${i.version}` : ""} (asset: ${i.asset})`
    case "foundryup":
      return `foundryup${i.tool ? ` --use ${i.tool}` : ""}`
    case "manual":
      return i.instructions
  }
}

async function ensureFoundryup(): Promise<boolean> {
  if (await which("foundryup")) return true
  // Install foundryup itself if missing
  const r = await run("bash", ["-c", "curl -L https://foundry.paradigm.xyz | bash"], { timeout: 60_000 })
  if (r.code !== 0) return false
  // foundryup installs to ~/.foundry/bin
  const fbin = path.join(os.homedir(), ".foundry", "bin")
  if (!process.env.PATH?.includes(fbin)) {
    process.env.PATH = `${fbin}${path.delimiter}${process.env.PATH ?? ""}`
  }
  return !!(await which("foundryup"))
}

async function ensurePipx(): Promise<boolean> {
  if (await which("pipx")) return true
  // try pip install
  const r = await run("bash", ["-c", "python3 -m pip install --user pipx && python3 -m pipx ensurepath"], {
    timeout: 60_000,
  })
  if (r.code === 0) {
    const pbin = path.join(os.homedir(), ".local", "bin")
    if (!process.env.PATH?.includes(pbin)) {
      process.env.PATH = `${pbin}${path.delimiter}${process.env.PATH ?? ""}`
    }
  }
  return !!(await which("pipx"))
}

async function tryInstaller(i: ToolInstaller, spec: ToolSpec): Promise<{ ok: boolean; msg: string }> {
  switch (i.kind) {
    case "pip": {
      const ver = i.version ? `${i.pkg}==${i.version}` : i.pkg
      const r = await run("bash", ["-c", `python3 -m pip install --user --quiet "${ver}"`], { timeout: 300_000 })
      return { ok: r.code === 0, msg: r.code === 0 ? "" : r.stderr.slice(-400) }
    }
    case "pipx": {
      if (!(await ensurePipx())) return { ok: false, msg: "pipx not available and could not be installed" }
      const ver = i.version ? `${i.pkg}==${i.version}` : i.pkg
      const r = await run("bash", ["-c", `pipx install --force "${ver}"`], { timeout: 300_000 })
      return { ok: r.code === 0, msg: r.code === 0 ? "" : r.stderr.slice(-400) }
    }
    case "cargo": {
      if (!(await which("cargo"))) return { ok: false, msg: "cargo (Rust) not installed; run: curl https://sh.rustup.rs -sSf | sh" }
      const ver = i.version ? ` --version ${i.version}` : ""
      const r = await run("bash", ["-c", `cargo install --quiet ${i.pkg}${ver}`], { timeout: 600_000 })
      return { ok: r.code === 0, msg: r.code === 0 ? "" : r.stderr.slice(-400) }
    }
    case "npm": {
      if (!(await which("npm"))) return { ok: false, msg: "npm not installed" }
      const ver = i.version ? `${i.pkg}@${i.version}` : i.pkg
      const r = await run("bash", ["-c", `npm install -g --silent ${ver}`], { timeout: 300_000 })
      return { ok: r.code === 0, msg: r.code === 0 ? "" : r.stderr.slice(-400) }
    }
    case "curl-bash": {
      const r = await run("bash", ["-c", `curl -sSL "${i.url}" | bash`], { timeout: 300_000 })
      return { ok: r.code === 0, msg: r.code === 0 ? "" : r.stderr.slice(-400) }
    }
    case "foundryup": {
      if (!(await ensureFoundryup())) return { ok: false, msg: "foundryup install failed" }
      const r = await run("bash", ["-c", `foundryup`], { timeout: 600_000 })
      return { ok: r.code === 0, msg: r.code === 0 ? "" : r.stderr.slice(-400) }
    }
    case "github-release": {
      // Best-effort: latest release, asset by name template, drop bin in ~/.local/bin
      const dest = path.join(os.homedir(), ".local", "bin")
      await fs.mkdir(dest, { recursive: true })
      const tmp = await fs.mkdtemp(path.join(os.tmpdir(), `solsec-doctor-${spec.name}-`))
      const ver = i.version ?? "latest"
      const tag = ver === "latest" ? "latest" : ver.startsWith("v") ? ver : `v${ver}`
      const asset = i.asset.replace("{version}", ver)
      const url =
        ver === "latest"
          ? `https://github.com/${i.repo}/releases/latest/download/${asset}`
          : `https://github.com/${i.repo}/releases/download/${tag}/${asset}`
      const dl = path.join(tmp, asset)
      const r1 = await run("bash", ["-c", `curl -sSL -o "${dl}" "${url}"`], { timeout: 300_000 })
      if (r1.code !== 0) return { ok: false, msg: `download failed: ${r1.stderr.slice(-200)}` }
      const cmd =
        asset.endsWith(".tar.gz") || asset.endsWith(".tgz")
          ? `tar -xzf "${dl}" -C "${tmp}"`
          : asset.endsWith(".zip")
            ? `unzip -q -o "${dl}" -d "${tmp}"`
            : ""
      if (cmd) {
        const r2 = await run("bash", ["-c", cmd], { timeout: 60_000 })
        if (r2.code !== 0) return { ok: false, msg: `extract failed: ${r2.stderr.slice(-200)}` }
      } else {
        // single binary download
        await fs.copyFile(dl, path.join(dest, spec.bin))
      }
      const inner = i.binIn ?? spec.bin
      const innerPath = path.join(tmp, inner)
      const exists = await fs
        .stat(innerPath)
        .then(() => true)
        .catch(() => false)
      if (exists) {
        const r3 = await run("bash", ["-c", `cp "${innerPath}" "${path.join(dest, spec.bin)}" && chmod +x "${path.join(dest, spec.bin)}"`], { timeout: 10_000 })
        if (r3.code !== 0) return { ok: false, msg: `copy failed: ${r3.stderr.slice(-200)}` }
      }
      if (!process.env.PATH?.includes(dest)) {
        process.env.PATH = `${dest}${path.delimiter}${process.env.PATH ?? ""}`
      }
      return { ok: true, msg: `installed to ${dest}` }
    }
    case "manual":
      return { ok: false, msg: `manual install required: ${i.instructions}` }
  }
}

async function installOne(spec: ToolSpec, force = false): Promise<{ ok: boolean; msg: string }> {
  if (!force) {
    const status = await checkOne(spec)
    if (status.installed)
      return { ok: true, msg: `already installed (${status.version ?? "unknown version"}) at ${status.path}` }
  }
  for (const installer of spec.installers) {
    const r = await tryInstaller(installer, spec)
    if (r.ok) {
      // verify
      const v = await checkOne(spec)
      if (v.installed) return { ok: true, msg: `installed via ${installer.kind} (${v.version ?? "ok"})` }
      return { ok: false, msg: `installer ${installer.kind} reported success but binary not found on PATH` }
    }
  }
  return { ok: false, msg: spec.installers.map((i) => `× ${describeInstaller(i)}`).join("\n      ") }
}

const CATEGORY_LABEL: Record<ToolCategory, string> = {
  core: "core (required)",
  sast: "static analysis",
  sym: "symbolic / formal",
  fuzz: "fuzzers",
  chain: "chain helpers",
  smt: "smt solvers",
  lint: "lint",
}

function printStatus(statuses: ToolStatus[]) {
  const groups = new Map<ToolCategory, ToolStatus[]>()
  for (const s of statuses) {
    const arr = groups.get(s.spec.category) ?? []
    arr.push(s)
    groups.set(s.spec.category, arr)
  }
  const order: ToolCategory[] = ["core", "sast", "sym", "fuzz", "chain", "smt", "lint"]
  for (const cat of order) {
    const arr = groups.get(cat)
    if (!arr) continue
    UI.println("")
    UI.println(UI.Style.TEXT_HIGHLIGHT_BOLD + CATEGORY_LABEL[cat] + UI.Style.TEXT_NORMAL)
    for (const s of arr) {
      const sym = colorStatus(s)
      const name = s.spec.name.padEnd(18)
      const ver = s.version ? UI.Style.TEXT_DIM + s.version + UI.Style.TEXT_NORMAL : ""
      const desc = UI.Style.TEXT_DIM + s.spec.description + UI.Style.TEXT_NORMAL
      UI.println(`  ${sym}  ${name} ${ver}`)
      if (!s.installed) UI.println(`       ${desc}`)
    }
  }
}

export const DoctorCommand = effectCmd({
  command: "doctor [action] [tool]",
  describe: "check, install, or update audit tooling (slither, halmos, semgrep, ...)",
  instance: false,
  builder: (yargs) =>
    yargs
      .positional("action", {
        describe: "check | install | update | which",
        type: "string",
        choices: ["check", "install", "update", "which"] as const,
        default: "check",
      })
      .positional("tool", {
        describe: "tool name (omit to act on all)",
        type: "string",
      })
      .option("category", {
        describe: "filter by category (core, sast, sym, fuzz, chain, smt, lint)",
        type: "string",
      })
      .option("force", {
        describe: "force reinstall",
        type: "boolean",
        default: false,
      })
      .option("required-only", {
        describe: "only operate on required tools",
        type: "boolean",
        default: false,
      }),
  handler: Effect.fn("Cli.doctor")(function* (args) {
    const action = (args.action as string) ?? "check"
    const targets = (() => {
      if (args.tool) {
        const t = findTool(args.tool)
        if (!t) return []
        return [t]
      }
      let pool = TOOLS
      if (args.category) pool = pool.filter((t) => t.category === args.category)
      if (args["required-only"]) pool = pool.filter((t) => t.required)
      return pool
    })()
    if (args.tool && targets.length === 0) return yield* fail(`unknown tool: ${args.tool}`)

    if (action === "which") {
      for (const t of targets) {
        const p = yield* Effect.promise(() => which(t.bin))
        UI.println(`${t.name.padEnd(18)} ${p ?? "(not found)"}`)
      }
      return
    }

    if (action === "check") {
      const statuses = yield* Effect.promise(() => Promise.all(targets.map(checkOne)))
      printStatus(statuses)
      const missing = statuses.filter((s) => s.spec.required && !s.installed)
      UI.println("")
      if (missing.length > 0) {
        UI.println(
          UI.Style.TEXT_DANGER_BOLD +
            `${missing.length} required tool(s) missing: ${missing.map((s) => s.spec.name).join(", ")}` +
            UI.Style.TEXT_NORMAL,
        )
        UI.println(`Run: ${UI.Style.TEXT_HIGHLIGHT_BOLD}solsec doctor install${UI.Style.TEXT_NORMAL}`)
        return yield* fail("required tools missing", 2)
      }
      UI.println(UI.Style.TEXT_SUCCESS_BOLD + "All required tools present." + UI.Style.TEXT_NORMAL)
      return
    }

    if (action === "install" || action === "update") {
      const force = action === "update" || args.force
      UI.println(`Installing ${targets.length} tool(s) (force=${force})...`)
      let okCount = 0
      let failCount = 0
      for (const t of targets) {
        process.stderr.write(`  ${t.name.padEnd(18)} ... `)
        const r = yield* Effect.promise(() => installOne(t, force))
        if (r.ok) {
          okCount++
          UI.println(UI.Style.TEXT_SUCCESS_BOLD + r.msg + UI.Style.TEXT_NORMAL)
        } else {
          failCount++
          UI.println(UI.Style.TEXT_DANGER_BOLD + "failed" + UI.Style.TEXT_NORMAL)
          for (const line of r.msg.split("\n")) UI.println(`      ${line}`)
        }
      }
      UI.println("")
      UI.println(`${okCount} ok, ${failCount} failed`)
      if (failCount > 0) return yield* fail(`${failCount} tool(s) failed to install`, 3)
      return
    }

    return yield* fail(`unknown action: ${action}`)
  }),
})
