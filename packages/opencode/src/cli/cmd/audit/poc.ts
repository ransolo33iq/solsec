import { Effect } from "effect"
import * as fs from "fs/promises"
import * as path from "path"
import { effectCmd, fail } from "../../effect-cmd"
import { UI } from "../../ui"

/**
 * solsec poc <name>
 *
 * Scaffolds a Foundry PoC for a 1day exploit or 0day finding. Generates:
 *   - test/<Name>.t.sol  (fork-pinned attacker/victim setup, profit assertion)
 *   - script/<Name>.s.sol  (replay-ready forge script)
 *   - poc/<Name>.md  (writeup template)
 *
 * If `--target 0xADDR@chain` is passed, fills in the target address + chain RPC
 * from the chain catalog. Otherwise leaves placeholders.
 */

const CHAIN_CATALOG: Record<string, { rpc: string; chainId: number }> = {
  mainnet: { rpc: "https://eth.llamarpc.com", chainId: 1 },
  ethereum: { rpc: "https://eth.llamarpc.com", chainId: 1 },
  base: { rpc: "https://mainnet.base.org", chainId: 8453 },
  arb: { rpc: "https://arb1.arbitrum.io/rpc", chainId: 42161 },
  arbitrum: { rpc: "https://arb1.arbitrum.io/rpc", chainId: 42161 },
  op: { rpc: "https://mainnet.optimism.io", chainId: 10 },
  optimism: { rpc: "https://mainnet.optimism.io", chainId: 10 },
  polygon: { rpc: "https://polygon-rpc.com", chainId: 137 },
  bnb: { rpc: "https://bsc-dataseed.binance.org", chainId: 56 },
  bsc: { rpc: "https://bsc-dataseed.binance.org", chainId: 56 },
  avax: { rpc: "https://api.avax.network/ext/bc/C/rpc", chainId: 43114 },
  avalanche: { rpc: "https://api.avax.network/ext/bc/C/rpc", chainId: 43114 },
  blast: { rpc: "https://rpc.blast.io", chainId: 81457 },
  scroll: { rpc: "https://rpc.scroll.io", chainId: 534352 },
  linea: { rpc: "https://rpc.linea.build", chainId: 59144 },
  mantle: { rpc: "https://rpc.mantle.xyz", chainId: 5000 },
}

function parseTarget(s?: string): { address: string; chain: string; rpc: string; chainId: number } | undefined {
  if (!s) return undefined
  const m = s.match(/^(0x[0-9a-fA-F]{40})(?:@(\w+))?$/)
  if (!m) return undefined
  const address = m[1]!
  const chain = (m[2] ?? "mainnet").toLowerCase()
  const meta = CHAIN_CATALOG[chain] ?? CHAIN_CATALOG.mainnet!
  return { address, chain, rpc: meta.rpc, chainId: meta.chainId }
}

function pascal(s: string): string {
  return s
    .replace(/[^A-Za-z0-9]+/g, " ")
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join("") || "Exploit"
}

function testTemplate(args: {
  name: string
  contract: string
  target?: ReturnType<typeof parseTarget>
  forkBlock?: number
}) {
  const target = args.target
  const rpcExpr = target ? `vm.envOr("RPC", string("${target.rpc}"))` : `vm.envString("RPC")`
  const blockExpr = args.forkBlock !== undefined ? args.forkBlock.toString() : "0 /* TODO: pin to a block before the patch */"
  const targetAddr = target?.address ?? "0x0000000000000000000000000000000000000000"
  return `// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

/// @notice Fork-pinned PoC for ${args.name}.
/// @dev DO NOT use vm.store on protocol storage. Use legitimate state transitions only.
contract ${args.contract}Test is Test {
    address constant TARGET = ${targetAddr};
    address attacker;
    address victim;
    uint256 forkId;

    function setUp() public {
        forkId = vm.createSelectFork(${rpcExpr}, ${blockExpr});
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        // TODO: deal/seed any prerequisite balances using vm.deal / IERC20.transfer
        //       NEVER vm.store into protocol state.
    }

    function testExploit_${args.contract}() public {
        uint256 attackerBalanceBefore = attacker.balance;
        // TODO: implement the exploit interaction sequence here.
        //       Each step should be a real on-chain call the attacker could submit.
        vm.startPrank(attacker);
        // ... attack steps ...
        vm.stopPrank();

        uint256 attackerBalanceAfter = attacker.balance;
        assertGt(
            attackerBalanceAfter,
            attackerBalanceBefore,
            "exploit must increase attacker balance"
        );
        emit log_named_uint("profit_wei", attackerBalanceAfter - attackerBalanceBefore);
    }
}
`
}

function scriptTemplate(args: { name: string; contract: string }) {
  return `// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Script.sol";

/// @notice Replay-ready script for ${args.name}.
contract ${args.contract}Script is Script {
    function run() external {
        uint256 pk = vm.envUint("ATTACKER_PK");
        vm.startBroadcast(pk);
        // TODO: copy the verified exploit sequence from ${args.contract}Test here.
        vm.stopBroadcast();
    }
}
`
}

function writeupTemplate(args: { name: string; contract: string; target?: ReturnType<typeof parseTarget> }) {
  return `# ${args.name}

| field | value |
|---|---|
| target | ${args.target?.address ?? "TODO"} |
| chain | ${args.target?.chain ?? "TODO"} |
| chain id | ${args.target?.chainId ?? "TODO"} |
| fork block | TODO |
| severity | TODO (Critical / High / Medium / Low) |
| swc | TODO |
| status | UNCONFIRMED |

## Summary

TODO: one-paragraph plain-English description of the vulnerability and impact.

## Root cause

TODO: pinpoint to file:line. Quote the exact code.

\`\`\`solidity
// vulnerable code here
\`\`\`

## Attack scenario

1. Attacker prepares ...
2. Attacker calls ...
3. State transitions ...
4. Profit assertion ...

## Proof of concept

See \`test/${args.contract}.t.sol\`. Run with:

\`\`\`bash
forge test --match-contract ${args.contract}Test -vvvv
\`\`\`

Profit observed: \`TODO\` wei (\`TODO\` USD at fork block).

## Recommended fix

TODO: minimal diff that closes the bug without behavior regressions.

## References

- TODO: similar exploits, prior writeups, audit reports, etc.
`
}

export const PocCommand = effectCmd({
  command: "poc <name>",
  describe: "scaffold a Foundry PoC harness (test + script + writeup)",
  instance: false,
  builder: (yargs) =>
    yargs
      .positional("name", { describe: "human name for the PoC (e.g., 'Euler Donation 2023')", type: "string", demandOption: true })
      .option("target", { describe: "0xADDR@chain (e.g., 0xabc...@mainnet)", type: "string" })
      .option("fork-block", { describe: "pin fork to specific block number", type: "number" })
      .option("dir", { describe: "output directory (default: cwd)", type: "string" })
      .option("force", { describe: "overwrite existing files", type: "boolean", default: false }),
  handler: Effect.fn("Cli.poc")(function* (args) {
    const name = args.name as string
    const contract = pascal(name)
    const dir = (args.dir as string | undefined) ?? process.cwd()
    const target = parseTarget(args.target as string | undefined)
    if (args.target && !target) return yield* fail(`invalid --target (expected 0xADDR@chain): ${args.target}`)

    const testPath = path.join(dir, "test", `${contract}.t.sol`)
    const scriptPath = path.join(dir, "script", `${contract}.s.sol`)
    const writeupPath = path.join(dir, "poc", `${contract}.md`)

    yield* Effect.promise(async () => {
      const written: string[] = []
      const skipped: string[] = []
      for (const [p, body] of [
        [testPath, testTemplate({ name, contract, target, forkBlock: args["fork-block"] as number | undefined })],
        [scriptPath, scriptTemplate({ name, contract })],
        [writeupPath, writeupTemplate({ name, contract, target })],
      ] as const) {
        const exists = await fs
          .stat(p)
          .then(() => true)
          .catch(() => false)
        if (exists && !args.force) {
          skipped.push(p)
          continue
        }
        await fs.mkdir(path.dirname(p), { recursive: true })
        await fs.writeFile(p, body, "utf8")
        written.push(p)
      }
      UI.println(`PoC scaffolded for "${name}" → ${contract}`)
      for (const p of written) UI.println(`  + ${path.relative(dir, p)}`)
      for (const p of skipped) UI.println(`  · ${path.relative(dir, p)} (exists, use --force to overwrite)`)
      if (target) {
        UI.println("")
        UI.println(`Target: ${target.address} on ${target.chain} (chainId ${target.chainId})`)
        UI.println(`RPC: ${target.rpc}`)
      }
      UI.println("")
      UI.println(`Run: ${"forge test --match-contract " + contract + "Test -vvvv"}`)
    })
  }),
})
