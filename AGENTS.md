# AGENTS.md

## Cursor Cloud specific instructions

### What is runnable in this Linux cloud VM

This repo (`MobileGuard`) has two parts:

- **iOS SwiftUI app** (`ScanView.swift`, and the full `App/*.swift` set inside `owasp-ios-scanner.zip`). This **cannot be built or run on this Linux VM** — it requires macOS + Xcode. Cloud agents can only edit this Swift code, not compile/run it.
- **Supabase edge function** (`index.ts`) — a **Deno/TypeScript** HTTP function. This **is** the runnable/testable service here.

Note: root `index.ts` is byte-identical to `supabase/functions/analyze-ipa/index.ts` inside `owasp-ios-scanner.zip`. The full Swift project lives inside that zip.

### Toolchain / running the edge function

- Runtime is **Deno** (installed at `~/.deno/bin`, already on `PATH` via `~/.bashrc`). No `package.json`/lockfile, and no repo lint/test config exist.
- Type check (closest thing to a build): `deno check index.ts`
- Lint: `deno lint index.ts` — currently reports 2 pre-existing `no-explicit-any` warnings in the app code (lines 76–77). These are the repo's existing state; do not "fix" them as part of unrelated work.
- Run the dev server: `deno run --allow-net --allow-env index.ts` — serves on `http://localhost:8000` (Deno.serve default port).

### Non-obvious runtime behavior

- The function calls the **Anthropic API** (`https://api.anthropic.com/v1/messages`, model `claude-sonnet-5`) and requires the `ANTHROPIC_API_KEY` env var. Without it, a `POST` returns `500 {"error":"ANTHROPIC_API_KEY not set"}` — this is expected, not a bug.
- CORS preflight: `OPTIONS` returns `200` with body `ok` and permissive CORS headers.
- Request flow: it reads the whole request body as evidence JSON, sends it to Claude, then strips code fences and slices the first `{` … last `}` before `JSON.parse` (`extractJSON`). The response is the OWASP `ScanReport` JSON (`verdict`, `score`, `summary`, `findings[]`, `goodPractices[]`).
- To test the full evidence → report path without a real Anthropic key, mock `globalThis.fetch` for `api.anthropic.com` in a separate harness and dynamically import `./index.ts` (do not modify the app code). A real end-to-end run against Anthropic needs `ANTHROPIC_API_KEY` set and a valid model name.
