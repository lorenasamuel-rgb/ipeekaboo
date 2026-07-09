// Supabase Edge Function: analyze-ipa
// Receives on-device evidence, asks Claude to map it to the OWASP Mobile Top 10 (2024),
// returns a strict JSON report. Keeps the model API key server-side (never in the app).
//
// Deploy:  supabase functions deploy analyze-ipa --no-verify-jwt
// Secret:  supabase secrets set ANTHROPIC_API_KEY=sk-ant-...

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const SYSTEM = `You are a senior mobile application security engineer. You receive JSON "evidence" extracted from an iOS .ipa (Info.plist facts, App Transport Security config, URL schemes, permission usage strings, embedded frameworks, Mach-O flags such as PIE and encryption, and a sample of suspicious strings pulled from the binary).

Assess the app against the OWASP Mobile Top 10 (2024):
M1 Improper Credential Usage; M2 Inadequate Supply Chain Security; M3 Insecure Authentication/Authorization; M4 Insufficient Input/Output Validation; M5 Insecure Communication; M6 Inadequate Privacy Controls; M7 Insufficient Binary Protections; M8 Security Misconfiguration; M9 Insecure Data Storage; M10 Insufficient Cryptography.

Return ONLY valid JSON, no code fences, matching exactly:
{"verdict":"critical"|"high"|"medium"|"low"|"clean","score":number,"summary":string,"findings":[{"masvsId":string,"category":string,"severity":"critical"|"high"|"medium"|"low","title":string,"evidence":string,"recommendation":string,"impact":string}],"goodPractices":[string]}

Guidance for mapping the evidence:
- atsAllowsArbitraryLoads true => M5, likely high (cleartext traffic permitted).
- suspiciousStrings containing keys/tokens/secrets => M1 and/or M10, high or critical.
- isPIE false => M7 (no ASLR), medium. isEncrypted false alone is not a finding by itself.
- Broad permission usage strings or file sharing enabled => M6 / M9.
- Many third-party frameworks => note M2 supply-chain review, low/medium.
- Custom URL schemes => M4 input validation risk, low/medium.
- Missing/weak signals => keep severity honest; do not invent issues without evidence.

Rules:
- verdict = highest severity across findings, or "clean" if none.
- score = 0-100 safety score (100 = clean; lower with more/worse issues).
- masvsId is the code only, e.g. "M5". category is "M5: Insecure Communication".
- Sort findings by severity, critical first. At most 8 findings.
- goodPractices: up to 4 positive signals actually present (e.g. ATS enforced, PIE enabled).
- Every string is one short sentence.`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  try {
    const apiKey = Deno.env.get("ANTHROPIC_API_KEY");
    if (!apiKey) {
      return json({ error: "ANTHROPIC_API_KEY not set" }, 500);
    }

    const evidence = await req.json();

    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-5",
        max_tokens: 4096,
        system: SYSTEM,
        messages: [{
          role: "user",
          content: "Analyze this iOS app evidence and return the JSON report:\n" +
            JSON.stringify(evidence),
        }],
      }),
    });

    if (!res.ok) {
      const t = await res.text();
      return json({ error: "model error", detail: t }, 502);
    }

    const data = await res.json();
    const text = (data.content ?? [])
      .filter((b: any) => b.type === "text")
      .map((b: any) => b.text)
      .join("\n");

    const report = extractJSON(text);
    return json(report, 200);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});

function extractJSON(text: string) {
  let t = text.replace(/```json/gi, "").replace(/```/g, "").trim();
  const s = t.indexOf("{");
  const e = t.lastIndexOf("}");
  if (s >= 0 && e > s) t = t.slice(s, e + 1);
  return JSON.parse(t);
}

function json(obj: unknown, status: number) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, "content-type": "application/json" },
  });
}
