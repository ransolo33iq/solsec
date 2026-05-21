import type { Config } from "@/config/config"
import type { Provider } from "@/provider/provider"
import { ProviderTransform } from "@/provider/transform"
import type { MessageV2 } from "./message-v2"

const COMPACTION_BUFFER = 20_000

export function usable(input: { cfg: Config.Info; model: Provider.Model; outputTokenMax?: number }) {
  const context = input.model.limit.context
  if (context === 0) return 0

  const outputTokens = ProviderTransform.maxOutputTokens(input.model, input.outputTokenMax)
  const reserved =
    input.cfg.compaction?.reserved ?? Math.min(COMPACTION_BUFFER, outputTokens)
  return input.model.limit.input
    ? Math.max(0, input.model.limit.input - outputTokens - reserved)
    : Math.max(0, context - outputTokens)
}

export function isOverflow(input: {
  cfg: Config.Info
  tokens: MessageV2.Assistant["tokens"]
  model: Provider.Model
  outputTokenMax?: number
}) {
  if (input.cfg.compaction?.auto === false) return false
  if (input.model.limit.context === 0) return false

  const count =
    input.tokens.total || input.tokens.input + input.tokens.output + input.tokens.cache.read + input.tokens.cache.write
  return count >= usable(input)
}
