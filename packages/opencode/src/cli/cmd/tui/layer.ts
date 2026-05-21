import { Layer } from "effect"
import { TuiConfig } from "./config/tui"
import { Npm } from "@solsec-ai/core/npm"
import { Observability } from "@solsec-ai/core/effect/observability"

export const CliLayer = Observability.layer.pipe(Layer.merge(TuiConfig.layer), Layer.provide(Npm.defaultLayer))
