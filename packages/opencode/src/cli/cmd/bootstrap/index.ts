import { Effect } from "effect"
import { effectCmd } from "../../effect-cmd"
import { UI } from "../../ui"
import { bootstrap, needsBootstrap, BUNDLE } from "./lib"

export const BootstrapCommand = effectCmd({
  command: "bootstrap",
  describe: "first-run setup: provisions agents, installs required tools, refreshes the exploit KB",
  instance: false,
  builder: (yargs) =>
    yargs
      .option("force", {
        describe: "re-write all bundled files even if up to date",
        type: "boolean",
        default: false,
      })
      .option("skip-doctor", {
        describe: "skip `solsec doctor install --required-only`",
        type: "boolean",
        default: false,
      })
      .option("skip-kb", {
        describe: "skip `solsec kb update`",
        type: "boolean",
        default: false,
      }),
  handler: Effect.fn("Cli.bootstrap")(function* (args) {
    UI.println("")
    UI.println(UI.Style.TEXT_HIGHLIGHT_BOLD + "solsec — first-run setup" + UI.Style.TEXT_NORMAL)
    UI.println(UI.Style.TEXT_DIM + "  config dir: " + BUNDLE.configRoot() + UI.Style.TEXT_NORMAL)
    UI.println("")
    const result = yield* Effect.promise(() =>
      bootstrap({
        force: args.force as boolean,
        skipDoctor: args["skip-doctor"] as boolean,
        skipKb: args["skip-kb"] as boolean,
        verbose: true,
      }),
    )
    UI.println("")
    UI.println(UI.Style.TEXT_SUCCESS_BOLD + "  done" + UI.Style.TEXT_NORMAL)
    UI.println(`  files: ${result.written.length} written, ${result.skipped.length} unchanged`)
    UI.println(`  tools: ${result.doctorOk ? "ok" : UI.Style.TEXT_WARNING + "partial — run `solsec doctor install` to retry" + UI.Style.TEXT_NORMAL}`)
    UI.println(`  kb:    ${result.kbOk ? "ok" : UI.Style.TEXT_WARNING + "partial — run `solsec kb update` to retry" + UI.Style.TEXT_NORMAL}`)
    UI.println("")
    UI.println("Try it:")
    UI.println(UI.Style.TEXT_HIGHLIGHT + "  solsec" + UI.Style.TEXT_NORMAL + UI.Style.TEXT_DIM + "          # open the TUI" + UI.Style.TEXT_NORMAL)
    UI.println(UI.Style.TEXT_HIGHLIGHT + "  solsec /audit 0xADDR@base" + UI.Style.TEXT_NORMAL + UI.Style.TEXT_DIM + "  # audit a deployed contract" + UI.Style.TEXT_NORMAL)
  }),
})

export const StatusCommand = effectCmd({
  command: "bootstrap-status",
  describe: "show whether solsec needs first-run setup",
  instance: false,
  handler: Effect.fn("Cli.bootstrapStatus")(function* () {
    const need = yield* Effect.promise(needsBootstrap)
    UI.println(`needs_bootstrap: ${need}`)
    UI.println(`config_root: ${BUNDLE.configRoot()}`)
    UI.println(`bundle_version: ${BUNDLE.version}`)
    UI.println(`asset_count: ${BUNDLE.count}`)
  }),
})
