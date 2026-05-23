import { Effect } from "effect"
import * as fs from "fs/promises"
import * as path from "path"
import * as os from "os"
import * as crypto from "crypto"
import { spawn } from "child_process"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec backup
 *
 * Replaces the ghost `solsec-backup` command (which referenced an external
 * Telegram-Drive repo). Real implementation:
 *
 *   solsec backup login            — interactive bot-token + chat-id setup
 *   solsec backup config           — show current config
 *   solsec backup push <path>      — encrypt, chunk, upload to Telegram, save manifest
 *   solsec backup list             — list local manifests
 *   solsec backup pull <id> <out>  — download chunks, decrypt, restore
 *   solsec backup test             — verify bot can send to chat
 *
 * Encryption: AES-256-GCM with per-snapshot random IV. Key lives in
 * `~/.config/solsec/backup.json` (mode 0600). Key never leaves the local
 * machine; Telegram only stores ciphertext chunks.
 *
 * Chunks: 45 MiB max (Telegram bot file limit is 50 MiB; leave headroom for
 * AES-GCM auth tag + base64 padding when API replies).
 */

const CHUNK_SIZE = 45 * 1024 * 1024
const CONFIG_DIR = path.join(os.homedir(), ".config", "solsec")
const CONFIG_PATH = path.join(CONFIG_DIR, "backup.json")
const INDEX_PATH = path.join(CONFIG_DIR, "backup-index.json")

interface BackupConfig {
  bot_token: string
  chat_id: string
  encryption_key: string // hex, 32 bytes
}

interface ChunkRef {
  index: number
  file_id: string
  size: number
  iv: string
  tag: string
}

interface SnapshotManifest {
  id: string
  reason: string
  source: string
  created_at: string
  total_size: number
  sha256: string
  chunks: ChunkRef[]
}

interface IndexFile {
  version: 1
  snapshots: SnapshotManifest[]
}

async function loadConfig(): Promise<BackupConfig | undefined> {
  try {
    const raw = await fs.readFile(CONFIG_PATH, "utf8")
    return JSON.parse(raw) as BackupConfig
  } catch {
    return undefined
  }
}

async function saveConfig(cfg: BackupConfig) {
  await fs.mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 })
  await fs.writeFile(CONFIG_PATH, JSON.stringify(cfg, null, 2), { mode: 0o600 })
}

async function loadIndex(): Promise<IndexFile> {
  try {
    const raw = await fs.readFile(INDEX_PATH, "utf8")
    return JSON.parse(raw) as IndexFile
  } catch {
    return { version: 1, snapshots: [] }
  }
}

async function saveIndex(idx: IndexFile) {
  await fs.mkdir(CONFIG_DIR, { recursive: true, mode: 0o700 })
  await fs.writeFile(INDEX_PATH, JSON.stringify(idx, null, 2), { mode: 0o600 })
}

function tarGz(source: string, outFile: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const args = ["-czf", outFile, "-C", path.dirname(source), path.basename(source)]
    const proc = spawn("tar", args, { stdio: ["ignore", "ignore", "pipe"] })
    let stderr = ""
    proc.stderr.on("data", (d) => (stderr += d.toString()))
    proc.on("error", reject)
    proc.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`tar exited ${code}: ${stderr}`)),
    )
  })
}

function untarGz(archive: string, destDir: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn("tar", ["-xzf", archive, "-C", destDir], { stdio: ["ignore", "ignore", "pipe"] })
    let stderr = ""
    proc.stderr.on("data", (d) => (stderr += d.toString()))
    proc.on("error", reject)
    proc.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`tar -x exited ${code}: ${stderr}`)),
    )
  })
}

async function readPrompt(label: string): Promise<string> {
  process.stderr.write(label)
  return await new Promise<string>((resolve) => {
    process.stdin.setEncoding("utf8")
    let buf = ""
    const onData = (chunk: string) => {
      buf += chunk
      const nl = buf.indexOf("\n")
      if (nl >= 0) {
        process.stdin.removeListener("data", onData)
        process.stdin.pause()
        resolve(buf.slice(0, nl).trim())
      }
    }
    process.stdin.resume()
    process.stdin.on("data", onData)
  })
}

async function tgApi(token: string, method: string, body?: any): Promise<any> {
  const url = `https://api.telegram.org/bot${token}/${method}`
  const r = await fetch(url, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  })
  const json = (await r.json()) as any
  if (!json.ok) throw new Error(`telegram ${method} failed: ${json.description ?? r.status}`)
  return json.result
}

async function tgSendDocument(
  token: string,
  chatId: string,
  filename: string,
  data: Uint8Array,
  caption?: string,
): Promise<{ file_id: string }> {
  const form = new FormData()
  form.set("chat_id", chatId)
  if (caption) form.set("caption", caption.slice(0, 1024))
  form.set("document", new Blob([new Uint8Array(data)]), filename)
  const r = await fetch(`https://api.telegram.org/bot${token}/sendDocument`, {
    method: "POST",
    body: form as any,
  })
  const json = (await r.json()) as any
  if (!json.ok) throw new Error(`telegram sendDocument failed: ${json.description ?? r.status}`)
  const doc = json.result?.document
  if (!doc?.file_id) throw new Error(`telegram sendDocument: missing file_id`)
  return { file_id: doc.file_id }
}

async function tgGetFile(token: string, fileId: string): Promise<Uint8Array> {
  const fileMeta = await tgApi(token, "getFile", { file_id: fileId })
  if (!fileMeta?.file_path) throw new Error(`getFile returned no file_path`)
  const url = `https://api.telegram.org/file/bot${token}/${fileMeta.file_path}`
  const r = await fetch(url)
  if (!r.ok) throw new Error(`telegram file download failed: HTTP ${r.status}`)
  const ab = await r.arrayBuffer()
  return new Uint8Array(ab)
}

function encryptChunk(plaintext: Uint8Array, keyHex: string): { ciphertext: Uint8Array; iv: string; tag: string } {
  const key = Buffer.from(keyHex, "hex")
  if (key.length !== 32) throw new Error("encryption_key must be 32 bytes (64 hex chars)")
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv)
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  return { ciphertext: ct, iv: iv.toString("hex"), tag: tag.toString("hex") }
}

function decryptChunk(ciphertext: Uint8Array, keyHex: string, ivHex: string, tagHex: string): Uint8Array {
  const key = Buffer.from(keyHex, "hex")
  const iv = Buffer.from(ivHex, "hex")
  const tag = Buffer.from(tagHex, "hex")
  const dec = crypto.createDecipheriv("aes-256-gcm", key, iv)
  dec.setAuthTag(tag)
  return Buffer.concat([dec.update(ciphertext), dec.final()])
}

function sha256Hex(data: Uint8Array): string {
  return crypto.createHash("sha256").update(data).digest("hex")
}

function slug(s: string) {
  return (
    s
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 50) || "snapshot"
  )
}

export const BackupCommand = effectCmd({
  command: "backup <action> [args..]",
  describe: "encrypted Telegram-backed snapshots (replaces ghost solsec-backup)",
  instance: false,
  builder: (yargs) =>
    yargs
      .positional("action", {
        describe: "login | config | push | pull | list | test",
        choices: ["login", "config", "push", "pull", "list", "test"] as const,
        type: "string",
        demandOption: true,
      })
      .positional("args", {
        describe: "(push) <path> [reason] | (pull) <id> <out-dir>",
        array: true,
        type: "string",
      })
      .option("reason", { describe: "(push) reason / label", type: "string", default: "manual" })
      .option("yes", { describe: "skip confirmation prompts", type: "boolean", default: false }),
  handler: Effect.fn("Cli.backup")(function* (args) {
    const action = args.action as string
    const positional = (args.args as string[] | undefined) ?? []

    if (action === "login") {
      yield* Effect.promise(async () => {
        const existing = await loadConfig()
        UI.println("Telegram bot setup:")
        UI.println("  1. Talk to @BotFather, /newbot, copy the HTTP API token.")
        UI.println("  2. Send any message from your account to the bot.")
        UI.println("  3. Run https://api.telegram.org/bot<TOKEN>/getUpdates and copy the chat.id.")
        UI.println("")
        const token = await readPrompt(`Bot token${existing ? " [keep existing]" : ""}: `)
        const chat = await readPrompt(`Chat ID${existing ? " [keep existing]" : ""}: `)
        const finalToken = token || existing?.bot_token || ""
        const finalChat = chat || existing?.chat_id || ""
        if (!finalToken || !finalChat) throw new Error("bot_token and chat_id are required")
        const key = existing?.encryption_key ?? crypto.randomBytes(32).toString("hex")
        await saveConfig({ bot_token: finalToken, chat_id: finalChat, encryption_key: key })
        UI.println("")
        UI.println(`config saved → ${CONFIG_PATH}`)
        if (!existing) UI.println(`new encryption key generated (32 bytes); back this up — restores fail without it.`)
      })
      return
    }

    const cfg = yield* Effect.promise(loadConfig)
    if (!cfg && action !== "config") return yield* fail("not configured. run: solsec backup login")

    if (action === "config") {
      if (!cfg) {
        UI.println("(not configured — run: solsec backup login)")
        return
      }
      UI.println(`config: ${CONFIG_PATH}`)
      UI.println(`bot_token: ${cfg.bot_token.slice(0, 8)}...${cfg.bot_token.slice(-4)}`)
      UI.println(`chat_id: ${cfg.chat_id}`)
      UI.println(`encryption_key: ${cfg.encryption_key.slice(0, 8)}...${cfg.encryption_key.slice(-4)} (32 bytes)`)
      return
    }

    if (action === "test") {
      yield* Effect.promise(async () => {
        const r = await tgApi(cfg!.bot_token, "sendMessage", {
          chat_id: cfg!.chat_id,
          text: `solsec backup test message — ${new Date().toISOString()}`,
        })
        UI.println(`ok — message_id ${r.message_id}`)
      }).pipe(Effect.catch((e) => fail(`test failed: ${(e as Error).message}`)))
      return
    }

    if (action === "list") {
      const idx = yield* Effect.promise(loadIndex)
      if (idx.snapshots.length === 0) {
        UI.println("(no snapshots)")
        return
      }
      UI.println(`${idx.snapshots.length} snapshot(s)`)
      for (const s of idx.snapshots.slice().sort((a, b) => (a.created_at < b.created_at ? 1 : -1))) {
        UI.println(`  ${s.id}\t${s.created_at}\tchunks=${s.chunks.length}\tsize=${s.total_size}\t${s.reason}`)
      }
      return
    }

    if (action === "push") {
      const target = positional[0]
      const reason = (positional[1] ?? args.reason) as string
      if (!target) return yield* fail("usage: solsec backup push <path> [reason]")
      yield* Effect.promise(async () => {
        const abs = path.resolve(target)
        const stat = await fs.stat(abs).catch(() => undefined)
        if (!stat) throw new Error(`path not found: ${abs}`)

        const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "solsec-backup-"))
        const tarPath = path.join(tmp, "payload.tar.gz")
        UI.println(`tar+gzip ${abs} → ${tarPath}`)
        await tarGz(abs, tarPath)

        const data = await fs.readFile(tarPath)
        const fullSha = sha256Hex(new Uint8Array(data))
        const id = `${new Date().toISOString().replace(/[:.]/g, "-")}-${slug(reason)}`
        UI.println(`uploading ${data.length} bytes in ${Math.ceil(data.length / CHUNK_SIZE)} chunk(s)`)

        const chunks: ChunkRef[] = []
        for (let i = 0, idx = 0; i < data.length; i += CHUNK_SIZE, idx++) {
          const part = data.subarray(i, Math.min(i + CHUNK_SIZE, data.length))
          const enc = encryptChunk(new Uint8Array(part), cfg!.encryption_key)
          const filename = `${id}.${idx.toString().padStart(4, "0")}.enc`
          process.stderr.write(`  chunk ${idx + 1}/${Math.ceil(data.length / CHUNK_SIZE)} (${enc.ciphertext.length}b)... `)
          const r = await tgSendDocument(cfg!.bot_token, cfg!.chat_id, filename, enc.ciphertext, `${id} chunk ${idx}`)
          UI.println(`ok (file_id ${r.file_id.slice(0, 16)}...)`)
          chunks.push({ index: idx, file_id: r.file_id, size: enc.ciphertext.length, iv: enc.iv, tag: enc.tag })
        }

        const manifest: SnapshotManifest = {
          id,
          reason,
          source: abs,
          created_at: new Date().toISOString(),
          total_size: data.length,
          sha256: fullSha,
          chunks,
        }
        const idxFile = await loadIndex()
        idxFile.snapshots.push(manifest)
        await saveIndex(idxFile)

        // Also push the manifest itself to Telegram for portability
        const mblob = new TextEncoder().encode(JSON.stringify(manifest, null, 2))
        await tgSendDocument(cfg!.bot_token, cfg!.chat_id, `${id}.manifest.json`, mblob, `${id} manifest`)

        await fs.rm(tmp, { recursive: true, force: true })
        UI.println("")
        UI.println(`pushed ${id}`)
      }).pipe(Effect.catch((e) => fail(`push failed: ${(e as Error).message}`)))
      return
    }

    if (action === "pull") {
      const id = positional[0]
      const out = positional[1]
      if (!id || !out) return yield* fail("usage: solsec backup pull <id> <out-dir>")
      yield* Effect.promise(async () => {
        const idxFile = await loadIndex()
        const m = idxFile.snapshots.find((s) => s.id === id)
        if (!m) throw new Error(`snapshot not found in local index: ${id}`)
        await fs.mkdir(out, { recursive: true })
        const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "solsec-pull-"))
        const tarPath = path.join(tmp, "payload.tar.gz")

        UI.println(`downloading ${m.chunks.length} chunk(s)`)
        const buffers: Buffer[] = []
        for (const c of m.chunks.sort((a, b) => a.index - b.index)) {
          process.stderr.write(`  chunk ${c.index + 1}/${m.chunks.length}... `)
          const enc = await tgGetFile(cfg!.bot_token, c.file_id)
          const dec = decryptChunk(enc, cfg!.encryption_key, c.iv, c.tag)
          buffers.push(Buffer.from(dec))
          UI.println(`ok (${dec.length}b)`)
        }
        const full = Buffer.concat(buffers)
        const sha = sha256Hex(new Uint8Array(full))
        if (sha !== m.sha256) throw new Error(`sha256 mismatch: expected ${m.sha256} got ${sha}`)
        await fs.writeFile(tarPath, full)
        await untarGz(tarPath, out)
        await fs.rm(tmp, { recursive: true, force: true })
        UI.println("")
        UI.println(`restored ${m.id} → ${out}`)
      }).pipe(Effect.catch((e) => fail(`pull failed: ${(e as Error).message}`)))
      return
    }

    return yield* fail(`unknown action: ${action}`)
  }),
})
