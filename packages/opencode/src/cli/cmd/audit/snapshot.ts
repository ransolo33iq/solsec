import { Effect } from "effect"
import * as fs from "fs/promises"
import * as path from "path"
import * as crypto from "crypto"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec snapshot
 *
 * Local-only project snapshot before destructive operations. Replaces the
 * `solsec-backup` ghost (which pointed at an external Telegram-Drive repo).
 *
 * Snapshots live at `.solsec/snapshots/<timestamp>-<reason-slug>/`. Each
 * snapshot is a recursive copy plus a manifest with file hashes. Restore
 * with `solsec snapshot restore <id>`.
 *
 * Default ignores: node_modules, .git, dist, out, cache, broadcast, .solsec/snapshots.
 */

const DEFAULT_IGNORES = [
  "node_modules",
  ".git",
  "dist",
  "out",
  "cache",
  "broadcast",
  ".forge-cache",
  ".turbo",
  ".solsec/snapshots",
]

interface ManifestFile {
  path: string
  size: number
  sha256: string
  mode: number
}

interface Manifest {
  version: 1
  id: string
  reason: string
  source: string
  createdAt: string
  files: ManifestFile[]
}

function slug(s: string) {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || "snapshot"
}

async function* walk(root: string, ignores: Set<string>): AsyncGenerator<string> {
  const stack = [root]
  while (stack.length) {
    const dir = stack.pop()!
    let entries: import("fs").Dirent[]
    try {
      entries = await fs.readdir(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const e of entries) {
      const full = path.join(dir, e.name)
      const rel = path.relative(root, full)
      if (ignores.has(rel)) continue
      if ([...ignores].some((ig) => rel === ig || rel.startsWith(ig + path.sep))) continue
      if (e.isDirectory()) stack.push(full)
      else if (e.isFile()) yield full
    }
  }
}

async function hashFile(p: string): Promise<string> {
  const h = crypto.createHash("sha256")
  const data = await fs.readFile(p)
  h.update(data)
  return h.digest("hex")
}

async function copyFile(src: string, dst: string) {
  await fs.mkdir(path.dirname(dst), { recursive: true })
  await fs.copyFile(src, dst)
  const st = await fs.stat(src)
  await fs.chmod(dst, st.mode).catch(() => {})
}

async function loadManifest(snapDir: string): Promise<Manifest | undefined> {
  try {
    const raw = await fs.readFile(path.join(snapDir, "manifest.json"), "utf8")
    return JSON.parse(raw) as Manifest
  } catch {
    return undefined
  }
}

export const SnapshotCommand = effectCmd({
  command: "snapshot <action> [args..]",
  describe: "create / list / diff / restore local project snapshots before destructive ops",
  instance: false,
  builder: (yargs) =>
    yargs
      .positional("action", {
        describe: "create | list | show | restore | prune",
        type: "string",
        choices: ["create", "list", "show", "restore", "prune"] as const,
        demandOption: true,
      })
      .positional("args", { describe: "snapshot id (for show/restore)", array: true, type: "string" })
      .option("reason", { describe: "(create) human reason", type: "string", default: "manual snapshot" })
      .option("source", { describe: "directory to snapshot (default: cwd)", type: "string" })
      .option("ignore", { describe: "extra ignore paths (comma-separated)", type: "string" })
      .option("keep", { describe: "(prune) number of newest snapshots to keep", type: "number", default: 10 }),
  handler: Effect.fn("Cli.snapshot")(function* (args) {
    const source = path.resolve((args.source as string | undefined) ?? process.cwd())
    const snapsRoot = path.join(source, ".solsec", "snapshots")
    const action = args.action as string

    if (action === "create") {
      const ignores = new Set([
        ...DEFAULT_IGNORES,
        ...((args.ignore as string | undefined)?.split(",").filter(Boolean) ?? []),
      ])
      const ts = new Date().toISOString().replace(/[:.]/g, "-")
      const reason = (args.reason as string) ?? "manual"
      const id = `${ts}-${slug(reason)}`
      const dest = path.join(snapsRoot, id)
      yield* Effect.promise(async () => {
        await fs.mkdir(dest, { recursive: true })
        const files: ManifestFile[] = []
        for await (const abs of walk(source, ignores)) {
          const rel = path.relative(source, abs)
          const dst = path.join(dest, "files", rel)
          await copyFile(abs, dst)
          const st = await fs.stat(abs)
          files.push({ path: rel, size: st.size, sha256: await hashFile(abs), mode: st.mode })
        }
        const manifest: Manifest = {
          version: 1,
          id,
          reason,
          source,
          createdAt: new Date().toISOString(),
          files,
        }
        await fs.writeFile(path.join(dest, "manifest.json"), JSON.stringify(manifest, null, 2))
        UI.println(`snapshot ${id} created → ${path.relative(source, dest)}`)
        UI.println(`  files: ${files.length}, size: ${files.reduce((a, f) => a + f.size, 0).toLocaleString()} bytes`)
      })
      return
    }

    if (action === "list") {
      const entries = yield* Effect.promise(async () => {
        try {
          return await fs.readdir(snapsRoot)
        } catch {
          return []
        }
      })
      if (entries.length === 0) {
        UI.println("(no snapshots)")
        return
      }
      const rows = yield* Effect.promise(async () => {
        const out: { id: string; createdAt: string; reason: string; files: number }[] = []
        for (const id of entries.sort().reverse()) {
          const m = await loadManifest(path.join(snapsRoot, id))
          if (!m) continue
          out.push({ id: m.id, createdAt: m.createdAt, reason: m.reason, files: m.files.length })
        }
        return out
      })
      UI.println(`${rows.length} snapshot(s)`)
      for (const r of rows) {
        UI.println(`  ${r.id}\t${r.createdAt}\tfiles=${r.files}\t${r.reason}`)
      }
      return
    }

    const target = (args.args as string[] | undefined)?.[0]
    if (action === "show") {
      if (!target) return yield* fail("snapshot id required: solsec snapshot show <id>")
      const m = yield* Effect.promise(() => loadManifest(path.join(snapsRoot, target)))
      if (!m) return yield* fail(`snapshot not found: ${target}`)
      UI.println(JSON.stringify(m, null, 2))
      return
    }

    if (action === "restore") {
      if (!target) return yield* fail("snapshot id required: solsec snapshot restore <id>")
      const dir = path.join(snapsRoot, target)
      const m = yield* Effect.promise(() => loadManifest(dir))
      if (!m) return yield* fail(`snapshot not found: ${target}`)
      yield* Effect.promise(async () => {
        let restored = 0
        for (const f of m.files) {
          const src = path.join(dir, "files", f.path)
          const dst = path.join(source, f.path)
          await copyFile(src, dst)
          restored++
        }
        UI.println(`restored ${restored} file(s) from ${m.id}`)
      })
      return
    }

    if (action === "prune") {
      const keep = args.keep as number
      const entries = yield* Effect.promise(async () => {
        try {
          return (await fs.readdir(snapsRoot)).sort().reverse()
        } catch {
          return []
        }
      })
      const toRemove = entries.slice(keep)
      yield* Effect.promise(async () => {
        for (const id of toRemove) {
          await fs.rm(path.join(snapsRoot, id), { recursive: true, force: true })
        }
        UI.println(`pruned ${toRemove.length} snapshot(s); kept ${Math.min(entries.length, keep)}`)
      })
      return
    }

    return yield* fail(`unknown action: ${action}`)
  }),
})
