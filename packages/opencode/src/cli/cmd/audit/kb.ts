import { Effect } from "effect"
import * as fs from "fs/promises"
import * as path from "path"
import * as os from "os"
import { spawn } from "child_process"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec kb
 *
 * Live knowledge base of historical exploits + sibling-fork patterns. The
 * `solsec exploits` CLI and audit subagents (sibling-hunter, oracle-triage,
 * composability-prober, economic-flaw-checker, auditor) all read from this KB.
 *
 *   solsec kb update            — refresh all sources (network)
 *   solsec kb status            — print local KB freshness
 *   solsec kb path              — print the KB path
 *   solsec kb search <query>    — alias for `solsec exploits` against KB-only
 */

const KB_ROOT = path.join(os.homedir(), ".cache", "solsec", "kb")
const KB_FILE = path.join(KB_ROOT, "exploits.json")
const STATE_FILE = path.join(KB_ROOT, "state.json")
const STALE_AFTER_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

interface ExploitEntry {
  id: string
  date?: string
  target?: string
  chain?: string
  attack_class: string
  swc?: string
  loss_usd?: number
  root_cause: string
  pattern?: string
  detector_hint?: string
  references?: string[]
  poc_link?: string
  source: string
}

interface KbState {
  version: 1
  updated_at: string
  sources: Record<string, { ok: boolean; count: number; error?: string; updated_at: string }>
}

async function ensureRoot() {
  await fs.mkdir(KB_ROOT, { recursive: true })
}

async function readKb(): Promise<ExploitEntry[]> {
  try {
    const raw = await fs.readFile(KB_FILE, "utf8")
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : (parsed.entries ?? [])
  } catch {
    return []
  }
}

async function writeKb(entries: ExploitEntry[]) {
  await ensureRoot()
  // Stable order by date desc then id
  const sorted = entries.slice().sort((a, b) => {
    const da = a.date ?? ""
    const db = b.date ?? ""
    if (da !== db) return da < db ? 1 : -1
    return a.id < b.id ? -1 : 1
  })
  await fs.writeFile(KB_FILE, JSON.stringify(sorted, null, 2))
}

async function readState(): Promise<KbState | undefined> {
  try {
    return JSON.parse(await fs.readFile(STATE_FILE, "utf8")) as KbState
  } catch {
    return undefined
  }
}

async function writeState(state: KbState) {
  await ensureRoot()
  await fs.writeFile(STATE_FILE, JSON.stringify(state, null, 2))
}

function runCmd(cmd: string, args: string[], opts?: { cwd?: string; timeoutMs?: number }) {
  return new Promise<{ ok: boolean; stdout: string; stderr: string }>((resolve) => {
    const proc = spawn(cmd, args, { cwd: opts?.cwd, env: process.env })
    let stdout = ""
    let stderr = ""
    const t = opts?.timeoutMs ? setTimeout(() => proc.kill("SIGTERM"), opts.timeoutMs) : undefined
    proc.stdout?.on("data", (d) => (stdout += d.toString()))
    proc.stderr?.on("data", (d) => (stderr += d.toString()))
    proc.on("error", (e) => {
      if (t) clearTimeout(t)
      resolve({ ok: false, stdout, stderr: stderr + e.message })
    })
    proc.on("close", (code) => {
      if (t) clearTimeout(t)
      resolve({ ok: code === 0, stdout, stderr })
    })
  })
}

// ── Fetchers ────────────────────────────────────────────────────────────────

async function fetchDefiHackLabs(): Promise<ExploitEntry[]> {
  const repo = path.join(KB_ROOT, "defihacklabs")
  const exists = await fs
    .stat(repo)
    .then(() => true)
    .catch(() => false)
  if (!exists) {
    const r = await runCmd(
      "git",
      ["clone", "--depth", "1", "https://github.com/SunWeb3Sec/DeFiHackLabs.git", repo],
      { timeoutMs: 300_000 },
    )
    if (!r.ok) throw new Error(`git clone failed: ${r.stderr.slice(-200)}`)
  } else {
    const r = await runCmd("git", ["pull", "--ff-only"], { cwd: repo, timeoutMs: 60_000 })
    if (!r.ok) throw new Error(`git pull failed: ${r.stderr.slice(-200)}`)
  }

  // DeFiHackLabs structure: src/test/<DATE>-<Project>_exp/<Project>_exp.t.sol
  // and a README index. Index is the easiest source of structured data.
  const readme = path.join(repo, "README.md")
  let raw = ""
  try {
    raw = await fs.readFile(readme, "utf8")
  } catch {
    return []
  }

  const entries: ExploitEntry[] = []
  // Match table rows: | YYYY-MM-DD | [Project](link) | <classes> | <loss> | ...
  const rowRe = /^\|\s*(\d{4}-\d{2}-\d{2})\s*\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|([^|]*)\|([^|]*)\|/gm
  let m: RegExpExecArray | null
  while ((m = rowRe.exec(raw)) !== null) {
    const date = m[1]!
    const project = m[2]!.trim()
    const link = m[3]!.trim()
    const classes = m[4]!.trim()
    const loss = m[5]!.trim()
    const lossNum = (() => {
      const mm = loss.replace(/[, $]/g, "").match(/(\d+(?:\.\d+)?)([KMB])?/)
      if (!mm) return undefined
      const n = parseFloat(mm[1]!)
      const mult = mm[2] === "K" ? 1e3 : mm[2] === "M" ? 1e6 : mm[2] === "B" ? 1e9 : 1
      return Math.round(n * mult)
    })()
    entries.push({
      id: `defihacklabs:${date}:${project.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
      date,
      target: project,
      attack_class: classes.toLowerCase().replace(/\s+/g, "-") || "unknown",
      loss_usd: lossNum,
      root_cause: classes || "see writeup",
      references: [link],
      source: "defihacklabs",
    })
  }
  return entries
}

async function fetchRekt(): Promise<ExploitEntry[]> {
  // rekt.news doesn't expose a clean RSS for incident data, but their
  // /leaderboard JSON is publicly fetchable.
  const url = "https://rekt.news/leaderboard/"
  try {
    const r = await fetch(url, { headers: { "user-agent": "solsec/kb" } })
    if (!r.ok) throw new Error(`HTTP ${r.status}`)
    const html = await r.text()
    // The leaderboard renders entries in __NEXT_DATA__ JSON; extract.
    const m = html.match(/<script id="__NEXT_DATA__"[^>]*>([\s\S]*?)<\/script>/)
    if (!m) return []
    const data = JSON.parse(m[1]!)
    const items: any[] = data?.props?.pageProps?.posts ?? []
    return items
      .filter((it) => it?.title && it?.frontmatter)
      .map((it) => {
        const fm = it.frontmatter ?? {}
        return {
          id: `rekt:${(it.slug ?? it.title).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
          date: fm.date ?? it.date,
          target: fm.protocol ?? it.title,
          chain: fm.chain,
          attack_class: (fm.category ?? "unknown").toLowerCase(),
          loss_usd:
            typeof fm.loss === "number"
              ? fm.loss
              : typeof fm.loss === "string"
                ? Number(fm.loss.replace(/[^0-9.]/g, "")) || undefined
                : undefined,
          root_cause: fm.summary ?? it.excerpt ?? "see writeup",
          references: [`https://rekt.news/${it.slug ?? ""}`],
          source: "rekt.news",
        } as ExploitEntry
      })
  } catch {
    return []
  }
}

async function fetchImmunefiDisclosed(): Promise<ExploitEntry[]> {
  const urls = [
    "https://immunefi.com/explore/disclosed/",
    "https://immunefi.com/api/v1/disclosed",
  ]
  for (const url of urls) {
    try {
      const r = await fetch(url, { headers: { "user-agent": "solsec/kb", accept: "application/json,text/html" } })
      if (!r.ok) continue
      const ct = r.headers.get("content-type") ?? ""
      if (ct.includes("application/json")) {
        const json = (await r.json()) as any
        const items: any[] = Array.isArray(json) ? json : json?.data ?? json?.disclosed ?? []
        return items.map((it) => ({
          id: `immunefi:${(it.id ?? it.title ?? "").toString().toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
          date: it.date ?? it.disclosedAt,
          target: it.project ?? it.title,
          attack_class: (it.severity ?? it.category ?? "unknown").toString().toLowerCase(),
          loss_usd: typeof it.bountyAmount === "number" ? it.bountyAmount : undefined,
          root_cause: it.summary ?? "see writeup",
          references: [it.url ?? `https://immunefi.com/explore/disclosed/${it.id ?? ""}`],
          source: "immunefi-disclosed",
        }))
      }
    } catch {}
  }
  return []
}

async function fetchSolidityScan(): Promise<ExploitEntry[]> {
  // SolidityScan blog has a JSON feed at /blog/wp-json/wp/v2/posts (Wordpress)
  const candidates = [
    "https://solidityscan.com/blog/wp-json/wp/v2/posts?per_page=50",
    "https://blog.solidityscan.com/feed.json",
  ]
  for (const url of candidates) {
    try {
      const r = await fetch(url, { headers: { "user-agent": "solsec/kb" } })
      if (!r.ok) continue
      const json = (await r.json()) as any[]
      if (!Array.isArray(json)) continue
      return json.map((p: any) => ({
        id: `solidityscan:${(p.slug ?? p.id).toString()}`,
        date: p.date ?? p.published,
        target: p.title?.rendered ?? p.title,
        attack_class: (p.categories?.[0] ?? "blog").toString(),
        root_cause: (p.excerpt?.rendered ?? p.excerpt ?? "")
          .replace(/<[^>]+>/g, "")
          .slice(0, 400),
        references: [p.link ?? p.url ?? ""],
        source: "solidityscan",
      }))
    } catch {}
  }
  return []
}

async function fetchCode4rena(): Promise<ExploitEntry[]> {
  // Public C4 findings: github.com/code-423n4/<contest>-findings
  // Not feasible to enumerate every contest at update time. Pull the
  // aggregated reports index from the org if available.
  const url = "https://api.github.com/orgs/code-423n4/repos?per_page=100&sort=updated&type=public"
  try {
    const r = await fetch(url, { headers: { "user-agent": "solsec/kb", accept: "application/json" } })
    if (!r.ok) return []
    const repos: any[] = await r.json()
    return repos
      .filter((r) => /findings?$/.test(r.name) || /-findings/.test(r.name))
      .slice(0, 40)
      .map((r) => ({
        id: `c4:${r.name}`,
        date: (r.updated_at ?? "").slice(0, 10),
        target: r.name.replace(/-findings?$/, ""),
        attack_class: "audit-contest",
        root_cause: r.description ?? "see findings repo",
        references: [r.html_url],
        source: "code4rena",
      }))
  } catch {
    return []
  }
}

// ── Update orchestrator ─────────────────────────────────────────────────────

async function update(only?: string[]) {
  await ensureRoot()
  const sources: Record<string, () => Promise<ExploitEntry[]>> = {
    defihacklabs: fetchDefiHackLabs,
    rekt: fetchRekt,
    immunefi: fetchImmunefiDisclosed,
    solidityscan: fetchSolidityScan,
    code4rena: fetchCode4rena,
  }
  const filtered = only?.length ? only.filter((k) => k in sources) : Object.keys(sources)
  const state: KbState = {
    version: 1,
    updated_at: new Date().toISOString(),
    sources: {},
  }
  const all: ExploitEntry[] = []

  // Preserve pre-existing entries from sources we didn't refresh this run
  const existing = await readKb()
  if (only?.length) {
    for (const e of existing) if (!filtered.includes(e.source)) all.push(e)
  }

  for (const name of filtered) {
    process.stderr.write(`  fetching ${name}... `)
    try {
      const entries = await sources[name]!()
      all.push(...entries)
      state.sources[name] = { ok: true, count: entries.length, updated_at: new Date().toISOString() }
      UI.println(`ok (${entries.length})`)
    } catch (e) {
      state.sources[name] = {
        ok: false,
        count: 0,
        error: (e as Error).message.slice(0, 200),
        updated_at: new Date().toISOString(),
      }
      UI.println(`failed: ${(e as Error).message.slice(0, 80)}`)
    }
  }

  // Dedupe by id
  const byId = new Map<string, ExploitEntry>()
  for (const e of all) {
    const prior = byId.get(e.id)
    if (!prior) byId.set(e.id, e)
    else {
      // prefer entries with more fields filled in
      const score = (x: ExploitEntry) =>
        Object.values(x).filter((v) => v !== undefined && v !== "" && v !== null).length
      if (score(e) > score(prior)) byId.set(e.id, e)
    }
  }

  await writeKb([...byId.values()])
  await writeState(state)
  return state
}

export const KbCommand = effectCmd({
  command: "kb <action> [args..]",
  describe: "live exploit knowledge base (DeFiHackLabs, rekt, Immunefi, SolidityScan, C4)",
  instance: false,
  builder: (yargs) =>
    yargs
      .positional("action", {
        describe: "update | status | path | search",
        choices: ["update", "status", "path", "search"] as const,
        type: "string",
        demandOption: true,
      })
      .positional("args", { describe: "(search) query keywords", array: true, type: "string" })
      .option("sources", { describe: "(update) comma-separated source filter", type: "string" }),
  handler: Effect.fn("Cli.kb")(function* (args) {
    const action = args.action as string

    if (action === "path") {
      UI.println(KB_ROOT)
      return
    }

    if (action === "status") {
      const state = yield* Effect.promise(readState)
      const entries = yield* Effect.promise(readKb)
      if (!state) {
        UI.println(`(KB never updated; run: solsec kb update)`)
        return
      }
      const age = Date.now() - new Date(state.updated_at).getTime()
      const stale = age > STALE_AFTER_MS
      UI.println(`KB: ${KB_FILE}`)
      UI.println(`updated: ${state.updated_at}${stale ? "  ⚠ STALE (> 7 days)" : ""}`)
      UI.println(`entries: ${entries.length}`)
      UI.println("")
      UI.println("sources:")
      for (const [name, s] of Object.entries(state.sources)) {
        const status = s.ok ? "ok" : "fail"
        UI.println(`  ${name.padEnd(16)} ${status.padEnd(4)} count=${s.count} ${s.error ?? ""}`)
      }
      return
    }

    if (action === "update") {
      const only = (args.sources as string | undefined)?.split(",").map((s) => s.trim()).filter(Boolean)
      const state = yield* Effect.promise(() => update(only))
      const total = Object.values(state.sources).reduce((a, s) => a + s.count, 0)
      UI.println("")
      UI.println(`KB updated: ${total} total entries across ${Object.keys(state.sources).length} source(s)`)
      UI.println(`location: ${KB_FILE}`)
      const failed = Object.entries(state.sources).filter(([, s]) => !s.ok)
      if (failed.length > 0) UI.println(`(${failed.length} source(s) failed — see solsec kb status)`)
      return
    }

    if (action === "search") {
      const q = (args.args as string[] | undefined)?.join(" ").toLowerCase() ?? ""
      const entries = yield* Effect.promise(readKb)
      if (entries.length === 0) return yield* fail("KB empty — run: solsec kb update")
      const hits = entries.filter((e) => {
        if (!q) return true
        const hay = [
          e.id,
          e.attack_class,
          e.target ?? "",
          e.chain ?? "",
          e.root_cause,
          (e.references ?? []).join(" "),
        ]
          .join(" ")
          .toLowerCase()
        return q
          .split(/\s+/)
          .filter(Boolean)
          .every((tok) => hay.includes(tok))
      })
      UI.println(`${hits.length}/${entries.length} matching`)
      for (const e of hits.slice(0, 100)) {
        const meta = [e.date, e.target, e.attack_class, e.chain, e.loss_usd ? `$${e.loss_usd.toLocaleString()}` : ""]
          .filter(Boolean)
          .join(" · ")
        UI.println(`  ${e.id}`)
        UI.println(`    ${meta}`)
        if (e.root_cause) UI.println(`    ${e.root_cause.slice(0, 200)}`)
        if (e.references?.[0]) UI.println(`    ${e.references[0]}`)
      }
      return
    }

    return yield* fail(`unknown action: ${action}`)
  }),
})
