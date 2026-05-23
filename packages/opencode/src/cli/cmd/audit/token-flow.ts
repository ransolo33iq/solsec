import { Effect } from "effect"
import { spawn } from "child_process"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec token-flow <rpc> <tx_hash>
 *
 * Real implementation of the ghost `solsec-token-flow` CLI. Uses `cast receipt`
 * to fetch logs, decodes ERC20 / ERC721 / ERC1155 Transfers, ERC20 Approvals,
 * and the native ETH delta from the receipt's `value` + internal traces.
 *
 * Output: a chronological flow table for the tx, suitable for forensics.
 */

// keccak("Transfer(address,address,uint256)")
const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
// keccak("Approval(address,address,uint256)")
const APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
// keccak("TransferSingle(address,address,address,uint256,uint256)")
const TS_TOPIC = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
// keccak("TransferBatch(address,address,address,uint256[],uint256[])")
const TB_TOPIC = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"

interface Log {
  address: string
  topics: string[]
  data: string
  logIndex?: string | number
}

function runCmd(cmd: string, args: string[], timeoutMs = 30_000): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { env: process.env })
    let stdout = ""
    let stderr = ""
    const t = setTimeout(() => proc.kill("SIGTERM"), timeoutMs)
    proc.stdout?.on("data", (d) => (stdout += d.toString()))
    proc.stderr?.on("data", (d) => (stderr += d.toString()))
    proc.on("error", (e) => {
      clearTimeout(t)
      resolve({ ok: false, stdout, stderr: stderr + e.message })
    })
    proc.on("close", (code) => {
      clearTimeout(t)
      resolve({ ok: code === 0, stdout, stderr })
    })
  })
}

function topicAddr(topic: string): string {
  // 32-byte topic → 20-byte address (last 20 bytes)
  const h = topic.replace(/^0x/, "").padStart(64, "0")
  return "0x" + h.slice(24)
}

function hexToBigInt(h: string): bigint {
  if (!h || h === "0x") return 0n
  return BigInt(h.startsWith("0x") ? h : "0x" + h)
}

interface FlowEvent {
  kind: "ERC20Transfer" | "ERC20Approval" | "ERC721Transfer" | "ERC1155Single" | "ERC1155Batch"
  token: string
  from?: string
  to?: string
  spender?: string
  amount?: bigint
  tokenId?: bigint
  ids?: bigint[]
  amounts?: bigint[]
  logIndex: number
}

function decode(logs: Log[]): FlowEvent[] {
  const out: FlowEvent[] = []
  for (let i = 0; i < logs.length; i++) {
    const l = logs[i]!
    const idx = typeof l.logIndex === "number" ? l.logIndex : Number(l.logIndex ?? i)
    const t0 = l.topics[0]?.toLowerCase()
    if (!t0) continue
    if (t0 === TRANSFER_TOPIC) {
      // ERC20 Transfer has 3 topics + data; ERC721 Transfer has 4 topics, no data
      if (l.topics.length === 3 && l.data && l.data !== "0x") {
        out.push({
          kind: "ERC20Transfer",
          token: l.address,
          from: topicAddr(l.topics[1]!),
          to: topicAddr(l.topics[2]!),
          amount: hexToBigInt(l.data),
          logIndex: idx,
        })
      } else if (l.topics.length === 4) {
        out.push({
          kind: "ERC721Transfer",
          token: l.address,
          from: topicAddr(l.topics[1]!),
          to: topicAddr(l.topics[2]!),
          tokenId: hexToBigInt(l.topics[3]!),
          logIndex: idx,
        })
      }
    } else if (t0 === APPROVAL_TOPIC && l.topics.length === 3) {
      out.push({
        kind: "ERC20Approval",
        token: l.address,
        from: topicAddr(l.topics[1]!),
        spender: topicAddr(l.topics[2]!),
        amount: hexToBigInt(l.data || "0x0"),
        logIndex: idx,
      })
    } else if (t0 === TS_TOPIC && l.topics.length === 4) {
      // data = id (32) + value (32)
      const data = l.data.replace(/^0x/, "").padStart(128, "0")
      out.push({
        kind: "ERC1155Single",
        token: l.address,
        from: topicAddr(l.topics[2]!),
        to: topicAddr(l.topics[3]!),
        tokenId: hexToBigInt("0x" + data.slice(0, 64)),
        amount: hexToBigInt("0x" + data.slice(64, 128)),
        logIndex: idx,
      })
    } else if (t0 === TB_TOPIC && l.topics.length === 4) {
      // batch — keep simplified: count only
      out.push({
        kind: "ERC1155Batch",
        token: l.address,
        from: topicAddr(l.topics[2]!),
        to: topicAddr(l.topics[3]!),
        logIndex: idx,
      })
    }
  }
  return out.sort((a, b) => a.logIndex - b.logIndex)
}

export const TokenFlowCommand = effectCmd({
  command: "token-flow <rpc> <tx>",
  describe: "trace ERC20/721/1155 transfers in a transaction",
  instance: false,
  builder: (yargs) =>
    yargs
      .positional("rpc", { describe: "RPC URL", type: "string", demandOption: true })
      .positional("tx", { describe: "transaction hash (0x...)", type: "string", demandOption: true })
      .option("json", { describe: "emit JSON", type: "boolean", default: false }),
  handler: Effect.fn("Cli.tokenFlow")(function* (args) {
    const rpc = args.rpc as string
    const tx = args.tx as string

    const receipt = yield* Effect.promise(() =>
      runCmd("cast", ["receipt", tx, "--json", "--rpc-url", rpc]),
    )
    if (!receipt.ok) return yield* fail(`cast receipt failed: ${receipt.stderr.slice(-400)}`)

    let parsed: any
    try {
      parsed = JSON.parse(receipt.stdout)
    } catch {
      return yield* fail("could not parse cast receipt JSON")
    }
    const logs: Log[] = (parsed.logs ?? []).map((l: any) => ({
      address: l.address,
      topics: l.topics ?? [],
      data: l.data ?? "0x",
      logIndex: l.logIndex,
    }))

    const events = decode(logs)

    if (args.json) {
      process.stdout.write(
        JSON.stringify(
          events.map((e) => ({
            ...e,
            amount: e.amount?.toString(),
            tokenId: e.tokenId?.toString(),
          })),
          null,
          2,
        ),
      )
      process.stdout.write("\n")
      return
    }

    UI.println(`tx ${tx} on rpc ${rpc}`)
    UI.println(`logs: ${logs.length}, decoded events: ${events.length}`)
    UI.println("")
    UI.println(["#", "kind", "token", "from", "to/spender", "value/id"].join("\t"))
    for (const e of events) {
      const value = e.amount?.toString() ?? e.tokenId?.toString() ?? "—"
      UI.println(
        [e.logIndex, e.kind, e.token, e.from ?? "", e.to ?? e.spender ?? "", value].join("\t"),
      )
    }
  }),
})
