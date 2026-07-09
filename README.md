# MobileGuard — OWASP Mobile Top 10 iOS Scanner

A native SwiftUI iOS app. The user imports an `.ipa`, the app statically analyzes it on-device
(unzip, Info.plist / ATS config, framework inventory, binary strings, Mach-O flags), and a
Supabase edge function maps the findings to the **OWASP Mobile Top 10 (2024)** using Claude.
The graded report is shown in-app and can be **downloaded as a PDF**.

## What's here
```
App/                     SwiftUI source (build in Xcode)
  OWASPScannerApp.swift  @main entry
  RootView.swift         tabs + About (the Mobile Top 10 list)
  ScanView.swift         import .ipa -> analyze -> request report
  IPAAnalyzer.swift      unzip, Info.plist, ATS, frameworks, strings
  MachOInspector.swift   best-effort PIE / encryption flags (M7)
  SupabaseService.swift  calls the edge function  <-- paste your keys here
  Models.swift           Evidence + ScanReport + Finding
  ReportView.swift       graded report UI + PDF download
  PDFReport.swift        HTML -> PDF via UIPrintPageRenderer
  Theme.swift            colors
supabase/
  functions/analyze-ipa/index.ts   edge function (Claude, key stays server-side)
  schema.sql                       optional scans table + RLS
```

## Setup (≈10 min on a Mac)

1. **Xcode** → new iOS App (SwiftUI, iOS 16+), name it `MobileGuard`. Drop in every file from `App/`.
2. **Add ZIPFoundation**: File → Add Packages → `https://github.com/weichsel/ZIPFoundation` (up to next major).
3. **Supabase**: create a project. Then:
   ```
   supabase functions deploy analyze-ipa --no-verify-jwt
   supabase secrets set ANTHROPIC_API_KEY=sk-ant-...
   ```
   (Optional) run `supabase/schema.sql` in the SQL editor to persist scans.
4. In `SupabaseService.swift`, set `url` and `anonKey` from Project Settings → API.
5. Build to a device or simulator. Tap **Scan**, import an `.ipa` from Files, get the report, tap
   **Download report (PDF)**.

## Build it in Cursor
Point a Cursor cloud agent at the repo and prompt: *"Wire ScanView → IPAAnalyzer → SupabaseService
end to end, fix any Swift build errors, and add a scans-history screen backed by the scans table."*
Note: the final compile to a runnable app still happens in **Xcode / Xcode Cloud** (native iOS
can't be compiled in a Linux cloud VM).

## Scope (be honest in the demo)
- Only scans `.ipa` files the user **imports via Files** — iOS sandboxing prevents reading other installed apps.
- Static, advisory analysis mapped to the Mobile Top 10 — **not** a full manual penetration test.
- Deep binary checks (stack canaries, full symbol analysis) are out of scope; PIE/encryption are best-effort.
