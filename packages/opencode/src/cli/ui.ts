import { EOL } from "os"
import { Schema } from "effect"
import { logo as glyphs } from "./logo"

const wordmark = [
  `⠀                                ▄     `,
  `█▀▀▀ █  █ █    █▀▀▄ █▀▀▀ █▀▀▄ █▀▀▄`,
  `█    █  █ █^^^ █  █ █    █  █ █  █`,
  `▀▀▀▀ ▀▀▀▀ ▀    ▀▀▀▀ ▀▀▀▀ ▀▀▀▀ ▀  ▀`,
]

export class CancelledError extends Schema.TaggedErrorClass<CancelledError>()("UICancelledError", {}) {}

export const Style = {
  TEXT_HIGHLIGHT: "[38;5;82m",
  TEXT_HIGHLIGHT_BOLD: "[38;5;82m[1m",
  TEXT_DIM: "[38;5;240m",
  TEXT_DIM_BOLD: "[38;5;240m[1m",
  TEXT_NORMAL: "\x1b[0m",
  TEXT_NORMAL_BOLD: "\x1b[1m",
  TEXT_WARNING: "[38;5;208m",
  TEXT_WARNING_BOLD: "[38;5;208m[1m",
  TEXT_DANGER: "[38;5;196m",
  TEXT_DANGER_BOLD: "[38;5;196m[1m",
  TEXT_SUCCESS: "[38;5;46m",
  TEXT_SUCCESS_BOLD: "[38;5;46m[1m",
  TEXT_INFO: "[38;5;39m",
  TEXT_INFO_BOLD: "[38;5;39m[1m",
}

export function println(...message: string[]) {
  print(...message)
  process.stderr.write(EOL)
}

export function print(...message: string[]) {
  blank = false
  process.stderr.write(message.join(" "))
}

let blank = false
export function empty() {
  if (blank) return
  println("" + Style.TEXT_NORMAL)
  blank = true
}

export function logo(pad?: string) {
  if (!process.stdout.isTTY && !process.stderr.isTTY) {
    const result = []
    for (const row of wordmark) {
      if (pad) result.push(pad)
      result.push(row)
      result.push(EOL)
    }
    return result.join("").trimEnd()
  }

  const result: string[] = []
  const reset = "\x1b[0m"
  const left = {
    fg: "\x1b[90m",
    shadow: "\x1b[38;5;235m",
    bg: "\x1b[48;5;235m",
  }
  const right = {
    fg: reset,
    shadow: "\x1b[38;5;238m",
    bg: "\x1b[48;5;238m",
  }
  const gap = " "
  const draw = (line: string, fg: string, shadow: string, bg: string) => {
    const parts: string[] = []
    for (const char of line) {
      if (char === "_") {
        parts.push(bg, " ", reset)
        continue
      }
      if (char === "^") {
        parts.push(fg, bg, "▀", reset)
        continue
      }
      if (char === "~") {
        parts.push(shadow, "▀", reset)
        continue
      }
      if (char === " ") {
        parts.push(" ")
        continue
      }
      parts.push(fg, char, reset)
    }
    return parts.join("")
  }
  glyphs.left.forEach((row, index) => {
    if (pad) result.push(pad)
    result.push(draw(row, left.fg, left.shadow, left.bg))
    result.push(gap)
    const other = glyphs.right[index] ?? ""
    result.push(draw(other, right.fg, right.shadow, right.bg))
    result.push(EOL)
  })
  return result.join("").trimEnd()
}

export async function input(prompt: string): Promise<string> {
  const readline = require("readline")
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  })

  return new Promise((resolve) => {
    rl.question(prompt, (answer: string) => {
      rl.close()
      resolve(answer.trim())
    })
  })
}

export function error(message: string) {
  if (message.startsWith("Error: ")) {
    message = message.slice("Error: ".length)
  }
  println(Style.TEXT_DANGER_BOLD + "Error: " + Style.TEXT_NORMAL + message)
}

export function markdown(text: string): string {
  return text
}

export * as UI from "./ui"
