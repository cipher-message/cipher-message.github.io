import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

const BOT_ID = "9e2f3b4a-1c2d-4e5f-8a6b-7c8d9e0f1a2b";
const GEMINI_KEY = Deno.env.get("GEMINI_API_KEY") ?? "";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

// Branded tier chain, strongest first. Verified 2026-09-16 against
// https://ai.google.dev/gemini-api/docs/models \u2014 every entry below is a
// currently-live, stable (non-preview) endpoint. Google previously shut down
// gemini-2.0-flash and gemini-2.0-flash-lite entirely, so those are gone for
// good; don't add them back. The frontend only ever sends us the INDEX of
// the tier it wants to try \u2014 it never picks the underlying Gemini model
// name directly, so this list is the single source of truth for both
// branding and fallback order.
const MODEL_CHAIN = [
  { label: "Cipher AI Pro",       model: "gemini-3.8-flash" },      // most capable current Flash model
  { label: "Cipher AI Flash",     model: "gemini-3.6-flash" },      // previous-gen Flash, still strong
  { label: "Cipher AI Mini",      model: "gemini-3.5-flash" },      // legacy Flash, separate quota pool
  { label: "Cipher AI SE",        model: "gemini-3.1-flash-lite" }, // frontier-class Lite tier
  { label: "Cipher AI SE Mini",   model: "gemini-2.5-flash" },      // 2.5-generation, distinct quota pool
  { label: "Cipher AI Basics",    model: "gemini-2.5-flash-lite", warning: "Poor quality" }, // cheapest live model
];

// Automatic fallback: when a tier is rate limited (429), overloaded (503) or
// gone (404) we move straight to the next tier down and keep going until one
// answers. A tier that just failed is remembered for a short cooldown (per warm
// instance, best effort) so the next messages skip it instead of failing over
// again every single time.
const FALLBACK_STATUSES = new Set([404, 429, 503]);
const cooldownUntil = new Map<number, number>();

async function readBoundedJson(req: Request) {
  const maxBytes = 65_536;
  if (Number(req.headers.get("content-length") ?? 0) > maxBytes || !req.body) throw new Error("invalid request size");
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) { await reader.cancel(); throw new Error("invalid request size"); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new Error("invalid JSON"); }
}

function cooldownMs(res: Response): number {
  if (res.status === 404) return 10 * 60_000;
  const retryAfter = Number(res.headers.get("retry-after"));
  if (Number.isFinite(retryAfter) && retryAfter > 0) return Math.min(retryAfter, 300) * 1000;
  return res.status === 503 ? 30_000 : 60_000;
}

const SYSTEM_INSTRUCTION = `You are Cipher AI, the built-in assistant inside a messaging app called Cipher. You're warm, a little witty, and genuinely helpful \u2014 like a clever friend in the group chat, not a corporate bot. Keep replies conversational and reasonably concise unless the person clearly wants depth or detail. Markdown-lite is fine: **bold**, *italics*, \`code\`, and short lists all render in this chat.

=== WHAT CIPHER IS ===
Cipher is a real-time messaging app with:
- Direct messages (1:1 chats) and Channels (group chats), which can be Private (invite-only) or Public (discoverable by anyone).
- Voice and video calling.
- Optional end-to-end encryption for messages.
- You, Cipher AI \u2014 summoned in any chat by typing "/ai" followed by a question.
You were built into this app to help people actually use it, so when someone seems stuck or confused about a feature, proactively walk them through it rather than giving a generic answer.

=== HOW TO CALL SOMEONE (VOICE/VIDEO) ===
- Calling only works inside a Direct Message (1:1 chat), NOT inside a group channel. The call and video icons only appear in the top bar once you've opened a DM with that person.
- To call: open the DM with that person, then tap the phone icon (voice) or camera icon (video) in the top bar of the chat.
- Common trouble: "I don't see a call button" almost always means they're inside a group channel instead of a DM \u2014 tell them to open (or start) a direct message with that specific person first, and the call buttons will appear.
- If a call won't connect, the most common causes are: the other person isn't online/active right now, or the browser hasn't granted mic/camera permission (check the browser's site permissions).

=== HOW TO CREATE A GROUP CHAT ===
- Groups in Cipher are called "Channels." To create one: in the sidebar, find the "Channels" section header and tap the "+" next to it (NOT the "+" next to "Direct messages" \u2014 that one only starts a 1:1 DM, which is the #1 mix-up people make).
- In the "Create a channel" dialog: give it a name, an optional topic, choose Private (invite-only, you add members manually by searching their username in that same dialog) or Public (discoverable \u2014 anyone can find and join it via "Browse public channels", the globe icon next to Channels).
- To add more people to an existing channel later, or to find public channels you haven't joined, point them to the globe/"Browse public channels" icon, or the channel's member list.
- Common trouble: "I made a chat but it's just me and one other person" usually means they used the DM "+" instead of the Channel "+".

=== HOW ENCRYPTION WORKS (AND HOW TO TURN IT ON) ===
Explain this simply unless they ask for technical depth:
- Cipher offers end-to-end encryption: each message is locked with a fresh, random key, and that key is individually wrapped for every recipient using their personal public key \u2014 meaning only the people in that conversation can ever unlock it, not even Cipher's own servers.
- To turn it on: the app will prompt with a "Set up encryption" dialog where you choose an encryption passphrase. This passphrase is separate from your login password, never leaves your device, and protects your personal encryption key.
- \u26a0\ufe0f Critical: if you forget your encryption passphrase, there is NO way to recover it \u2014 tell users this clearly and encourage them to pick something memorable (or store it in a password manager). The only fallback is resetting the encryption key entirely, which lets you send/receive new encrypted messages again but permanently loses access to everything encrypted under the old key. Messages that were sent as plain text are never affected by this.
- On a new device or browser, you'll be asked to re-enter your passphrase to unlock encryption there too \u2014 this is normal and expected, not a bug.
- If a message shows as locked/unreadable, it almost always means encryption hasn't been unlocked yet on that device (enter the passphrase), or it was sent before that person turned encryption on.
- If only one person in a chat has encryption turned on, messages fall back to sending as plain text until everyone in the conversation has it enabled.

=== GENERAL SUPPORT STYLE ===
- When someone describes a problem, first figure out which of the above areas it's likely in (calling, channels/groups, or encryption) before answering \u2014 many "it's broken" reports are actually one of the common mix-ups above.
- Give the specific next click/step, not vague advice like "check your settings."
- If something is genuinely a bug outside what's described here, say so plainly rather than guessing, and suggest they flag it to whoever manages this Cipher server/community.`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  if (!req.headers.get("content-type")?.toLowerCase().startsWith("application/json")) return json({ error: "Expected JSON" }, 415);

  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    const userClient = createClient(SUPABASE_URL, ANON_KEY, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: userData, error: userErr } = await userClient.auth.getUser();
    if (userErr || !userData?.user) return json({ error: "Unauthorized" }, 401);

    const input = await readBoundedJson(req);
    const { channel_id, prompt, history, model_index } = input ?? {};
    if (typeof channel_id !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(channel_id) ||
        typeof prompt !== "string" || prompt.length < 1 || new TextEncoder().encode(prompt).length > 16_384 ||
        !Array.isArray(history) || history.length > 12) return json({ error: "Invalid AI request" }, 400);
    for (const item of history) {
      if (!item || typeof item !== "object" || !["user", "bot"].includes(item.role) || typeof item.text !== "string" ||
          new TextEncoder().encode(item.text).length > 8_192) return json({ error: "Invalid AI history" }, 400);
    }

    // Clamp to a valid tier \u2014 never trust the client's index blindly.
    const idx = Number.isInteger(model_index) ? Math.max(0, Math.min(MODEL_CHAIN.length - 1, model_index)) : 0;
    const requested = MODEL_CHAIN[idx];

    const svc = createClient(SUPABASE_URL, SERVICE_KEY);

    const { data: membership } = await svc
      .from("channel_members")
      .select("user_id")
      .eq("channel_id", channel_id)
      .eq("user_id", userData.user.id)
      .maybeSingle();
    if (!membership) return json({ error: "This conversation is unavailable." }, 403);

    // Read the ban row from Postgres for every request so dashboard changes
    // take effect on the user's very next /ai request, including warm instances.
    const { data: ban, error: banError } = await svc
      .from("cipher_ai_bans")
      .select("ai_banned, ban_reason")
      .eq("user_id", userData.user.id)
      .maybeSingle();
    if (banError) {
      console.error("cipher-ai: ban lookup failed");
      return json({ error: "AI is temporarily unavailable." }, 503);
    }
    if (ban?.ai_banned) {
      const reason = typeof ban.ban_reason === "string" && ban.ban_reason.trim()
        ? ban.ban_reason.trim().slice(0, 500)
        : "the Cipher AI usage policy";
      return json({
        ai_banned: true,
        error: `You are banned from requesting Cipher AI because ${reason}`,
      }, 403);
    }

    if (!GEMINI_KEY) {
      console.error("cipher-ai: GEMINI_API_KEY secret is not set");
      return json({ error: "AI key not configured on the server yet. Add GEMINI_API_KEY in Edge Function secrets." }, 500);
    }

    const { error: quotaError } = await userClient.rpc("consume_cipher_ai_rate_limit");
    if (quotaError) {
      if (quotaError.message?.toLowerCase().includes("rate limit")) {
        return json({ error: "You've reached Cipher AI's limit of 10 requests per UTC day. Try again after the daily reset.", quota_limited: true }, 429);
      }
      console.error("cipher-ai: quota check failed");
      return json({ error: "AI is temporarily unavailable." }, 503);
    }

    // Gemini's Interactions API (the generateContent/API-key-in-URL API is being
    // retired) takes a flat list of user_input / model_output steps.
    const steps: Array<{ type: string; content: Array<{ type: string; text: string }> }> = [];
    if (Array.isArray(history)) {
      for (const h of history.slice(-12)) {
        steps.push({
          type: h.role === "bot" ? "model_output" : "user_input",
          content: [{ type: "text", text: String(h.text ?? "").slice(0, 4000) }],
        });
      }
    }
    steps.push({ type: "user_input", content: [{ type: "text", text: prompt.slice(0, 4000) }] });

    // Try the requested tier first, then step down one tier at a time until a
    // model answers. Tiers that failed very recently are skipped, but the final
    // tier always gets a real attempt.
    const lastIdx = MODEL_CHAIN.length - 1;
    let apiRes: Response | null = null;
    let usedIdx = idx;
    for (let i = idx; i <= lastIdx; i++) {
      if (i < lastIdx && (cooldownUntil.get(i) ?? 0) > Date.now()) continue;
      const t = MODEL_CHAIN[i];
      let res: Response;
      try {
        res = await fetch("https://generativelanguage.googleapis.com/v1beta/interactions", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": GEMINI_KEY,
          },
          body: JSON.stringify({
            model: t.model,
            input: steps,
            system_instruction: SYSTEM_INSTRUCTION,
            generation_config: { max_output_tokens: 1024 },
          }),
          signal: AbortSignal.timeout(20000),
        });
      } catch (e) {
        console.warn(`cipher-ai: ${t.label} (${t.model}) request failed or timed out, trying next tier`, String(e));
        cooldownUntil.set(i, Date.now() + 15_000);
        continue;
      }
      if (FALLBACK_STATUSES.has(res.status)) {
        await res.body?.cancel();
        console.warn(`cipher-ai: ${t.label} (${t.model}) returned ${res.status}, trying next tier`);
        cooldownUntil.set(i, Date.now() + cooldownMs(res));
        continue;
      }
      apiRes = res;
      usedIdx = i;
      break;
    }

    // Every tier from the requested one down is out of capacity.
    if (!apiRes) {
      return json({
        error: "Our AI server is finally exhausted. Please wait after 24h",
        exhausted: true,
        current_index: lastIdx,
        current_label: MODEL_CHAIN[lastIdx].label,
      }, 429);
    }
    const tier = MODEL_CHAIN[usedIdx];

    const rawText = await apiRes.text();
    let ijson: any = {};
    try { ijson = JSON.parse(rawText); } catch { ijson = { raw: rawText }; }

    if (!apiRes.ok) {
      console.error("cipher-ai: Interactions API request failed", apiRes.status);
      return json({ error: "AI could not complete that request. Please try again shortly." }, 502);
    }

    if (ijson.status === "failed") {
      console.error("cipher-ai: interaction failed");
      return json({ error: "AI could not complete that request. Please try again shortly." }, 502);
    }

    // Pull every text part out of every model_output step, in order.
    const outputSteps = (ijson.steps || []).filter((s: any) => s.type === "model_output");
    const reply = outputSteps
      .flatMap((s: any) => (s.content || []).filter((c: any) => c.type === "text" && typeof c.text === "string").map((c: any) => c.text))
      .join("")
      .trim() || "\u2026I've got nothing. Try asking that a different way?";
    if (new TextEncoder().encode(reply).length > 32_768) return json({ error: "The AI response was too large. Please ask for a shorter answer." }, 502);

    const { data: inserted, error: insErr } = await svc
      .from("messages")
      .insert({ channel_id, sender_id: BOT_ID, content: reply })
      .select()
      .single();
    if (insErr) {
      console.error("cipher-ai: message insert failed");
      return json({ error: "AI could not save its reply. Please try again." }, 500);
    }

    return json({
      ok: true,
      message: inserted,
      model_index: usedIdx,
      model_label: tier.label,
      fell_back: usedIdx > idx,
      requested_label: requested.label,
      warning: tier.warning || null,
    });
  } catch (e) {
    const message = e instanceof Error ? e.message : "";
    if (message === "invalid request size") return json({ error: "AI request exceeds the size limit." }, 413);
    if (message === "invalid JSON") return json({ error: "Invalid request." }, 400);
    console.error("cipher-ai: unhandled failure");
    return json({ error: "AI is temporarily unavailable." }, 500);
  }
});
