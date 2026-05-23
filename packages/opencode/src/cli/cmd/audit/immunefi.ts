import { Effect } from "effect"
import * as fs from "fs/promises"
import * as path from "path"
import * as os from "os"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec immunefi
 *
 * Real implementation of the ghost `solsec-immunefi` CLI. Lists/filters
 * Immunefi bug-bounty programs. Caches the JSON to ~/.cache/solsec/immunefi.json
 * (24h TTL) so we don't re-hit the upstream every invocation.
 *
 * Upstream: https://immunefi.com/public-api/
 */

interface ImmunefiProgram {
  id?: string
  project: string
  launchDate?: string
  maxBounty?: number
  totalRewardsPaid?: number
  programType?: string
  assets?: Array<{ type?: string; chain?: string; url?: string }>
  rewards?: Array<{ severity?: string; assetType?: string; amount?: number }>
  kycRequired?: boolean
  vaultProgram?: boolean
  url?: string
}

const CACHE_DIR = path.join(os.homedir(), ".cache", "solsec")
const CACHE_FILE = path.join(CACHE_DIR, "immunefi.json")
const CACHE_TTL_MS = 24 * 60 * 60 * 1000

async function readCache(): Promise<{ data: ImmunefiProgram[]; cachedAt: number } | undefined> {
  try {
    const raw = await fs.readFile(CACHE_FILE, "utf8")
    const parsed = JSON.parse(raw)
    if (parsed?.data && parsed?.cachedAt) return parsed
  } catch {}
  return undefined
}

async function writeCache(data: ImmunefiProgram[]) {
  await fs.mkdir(CACHE_DIR, { recursive: true })
  await fs.writeFile(CACHE_FILE, JSON.stringify({ data, cachedAt: Date.now() }))
}

async function fetchPrograms(): Promise<ImmunefiProgram[]> {
  // Public Immunefi API endpoints. Try the bounty-summary one first;
  // fall back to the explore page JSON if that ever changes.
  const urls = [
    "https://immunefi.com/public-api/bounty-summary/",
    "https://immunefi.com/api/v1/bounty",
  ]
  for (const url of urls) {
    try {
      const r = await fetch(url, {
        headers: { "user-agent": "solsec/audit-cli", accept: "application/json" },
      })
      if (!r.ok) continue
      const json = (await r.json()) as any
      const arr: ImmunefiProgram[] = Array.isArray(json) ? json : json?.data ?? json?.bounties ?? []
      if (arr.length > 0) return arr
    } catch {}
  }
  throw new Error("could not fetch Immunefi programs (network blocked or upstream changed)")
}

function chainsOf(p: ImmunefiProgram): string[] {
  return Array.from(new Set((p.assets ?? []).map((a) => (a.chain ?? "").toLowerCase()).filter(Boolean)))
}

export const ImmunefiCommand = effectCmd({
  command: "immunefi",
  describe: "list / filter Immunefi bug-bounty programs (caches 24h)",
  instance: false,
  builder: (yargs) =>
    yargs
      .option("min-payout", { describe: "minimum max-bounty in USD", type: "number", default: 0 })
      .option("chain", { describe: "filter by chain (e.g., ethereum, arbitrum, base)", type: "string" })
      .option("no-kyc", { describe: "only programs without KYC", type: "boolean", default: false })
      .option("type", { describe: "asset type filter (smart_contract, websites_and_applications, blockchain_dlt)", type: "string" })
      .option("refresh", { describe: "ignore cache, refetch", type: "boolean", default: false })
      .option("json", { describe: "emit JSON instead of table", type: "boolean", default: false })
      .option("limit", { describe: "max rows to print (table mode)", type: "number", default: 50 }),
  handler: Effect.fn("Cli.immunefi")(function* (args) {
    const programs = yield* Effect.promise(async () => {
      if (!args.refresh) {
        const cached = await readCache()
        if (cached && Date.now() - cached.cachedAt < CACHE_TTL_MS) return cached.data
      }
      const fresh = await fetchPrograms()
      await writeCache(fresh)
      return fresh
    }).pipe(
      Effect.catch((e) => fail(`immunefi fetch failed: ${(e as Error).message}`)),
    )

    let filtered = programs
    if (args["min-payout"] > 0)
      filtered = filtered.filter((p) => (p.maxBounty ?? 0) >= (args["min-payout"] as number))
    if (args.chain) {
      const want = (args.chain as string).toLowerCase()
      filtered = filtered.filter((p) => chainsOf(p).some((c) => c.includes(want)))
    }
    if (args["no-kyc"]) filtered = filtered.filter((p) => !p.kycRequired)
    if (args.type) {
      const want = (args.type as string).toLowerCase()
      filtered = filtered.filter((p) => (p.assets ?? []).some((a) => (a.type ?? "").toLowerCase().includes(want)))
    }
    filtered = filtered.sort((a, b) => (b.maxBounty ?? 0) - (a.maxBounty ?? 0))

    if (args.json) {
      process.stdout.write(JSON.stringify(filtered, null, 2))
      process.stdout.write("\n")
      return
    }
    UI.println(`Found ${filtered.length} matching program(s)`)
    UI.println("")
    UI.println(
      ["project", "max bounty", "chains", "kyc", "url"].join("\t"),
    )
    for (const p of filtered.slice(0, args.limit as number)) {
      const max = p.maxBounty ? `$${p.maxBounty.toLocaleString()}` : "—"
      const chains = chainsOf(p).slice(0, 3).join(",") || "—"
      const kyc = p.kycRequired ? "yes" : "no"
      const url = p.url ?? `https://immunefi.com/bounty/${p.project?.toLowerCase().replace(/\s+/g, "-")}`
      UI.println([p.project ?? "—", max, chains, kyc, url].join("\t"))
    }
  }),
})
