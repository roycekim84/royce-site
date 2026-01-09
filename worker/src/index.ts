export interface Env {
  CAFE24_API_BASE: string;
  INTERNAL_TOKEN: string;
  JWT_SECRET: string;

  OPENAI_API_KEY: string;
  OPENAI_MODEL: string;

  NEWS_JOB_TOKEN: string;
  ALLOWED_ORIGINS?: string;
}

/* ---------------- helpers ---------------- */
function json(data: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });
}

type JsonRecord = Record<string, unknown>;

async function readJson_new<T extends JsonRecord = JsonRecord>(req: Request): Promise<T> {
  try {
    return (await req.json()) as T;
  } catch {
    return {} as T;
  }
}


function getAllowedOrigin(req: Request, env: Env): string | null {
  const origin = req.headers.get("Origin");
  if (!origin) return null;
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
  if (allowed.length === 0) return origin; // dev 편의
  return allowed.includes(origin) ? origin : null;
}

function withCors(req: Request, env: Env, res: Response) {
  const allowedOrigin = getAllowedOrigin(req, env);
  const headers = new Headers(res.headers);
  if (allowedOrigin) {
    headers.set("Access-Control-Allow-Origin", allowedOrigin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "content-type, x-news-token");
    headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    headers.set("Vary", "Origin");
  }
  return new Response(res.body, { status: res.status, headers });
}

async function readJson(req: Request) {
  const ct = req.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return null;
  try { return await req.json(); } catch { return null; }
}

function buildSessionCookie(req: Request, token: string) {
  const isHttps = new URL(req.url).protocol === "https:";
  const parts = [
    `session=${token}`,
    "Path=/",
    "HttpOnly",
    `Max-Age=${60 * 60 * 24 * 7}`, // 7일
  ];

  if (isHttps) {
    // ✅ 크로스사이트( pages.dev -> workers.dev )에서 쿠키 붙이려면 필요
    parts.push("Secure");
    parts.push("SameSite=None");
  } else {
    // 로컬 http 개발용
    parts.push("SameSite=Lax");
  }

  return parts.join("; ");
}


/* ---------------- JWT HS256 (same as v0.4) ---------------- */
function b64urlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlEncodeJson(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}
function b64urlDecodeToU8(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}
const keyCache = new Map<string, Promise<CryptoKey>>();
function getHmacKey(secret: string) {
  if (!keyCache.has(secret)) {
    keyCache.set(secret, crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign","verify"]
    ));
  }
  return keyCache.get(secret)!;
}
async function signJwt(payload: Record<string, any>, env: Env) {
  const header = { alg:"HS256", typ:"JWT" };
  const h = b64urlEncodeJson(header);
  const p = b64urlEncodeJson(payload);
  const msg = `${h}.${p}`;
  const key = await getHmacKey(env.JWT_SECRET);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return `${msg}.${b64urlEncode(sig)}`;
}
async function verifyJwt(token: string, env: Env): Promise<Record<string, any> | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h,p,s] = parts;
  const msg = `${h}.${p}`;
  const sig = b64urlDecodeToU8(s);
  const key = await getHmacKey(env.JWT_SECRET);
  const ok = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(msg));
  if (!ok) return null;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecodeToU8(p)));
    const now = Math.floor(Date.now()/1000);
    if (payload.exp && now > payload.exp) return null;
    return payload;
  } catch { return null; }
}

function getWindowLast24hKst(nowUtcMs: number) {
  const KST_OFFSET_MS = 9 * 60 * 60 * 1000;
  const pad2 = (n: number) => String(n).padStart(2, "0");

  const nowKstMs = nowUtcMs + KST_OFFSET_MS;
  const startKstMs = nowKstMs - 24 * 60 * 60 * 1000;

  // KST timeline(ms) -> KST 문자열(YYYY-MM-DD HH:MM:SS)
  const toKstStrFromKstMs = (kstMs: number) => {
    const d = new Date(kstMs);
    return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())} ${pad2(
      d.getUTCHours()
    )}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
  };

  return {
    startKstStr: toKstStrFromKstMs(startKstMs),
    endKstStr: toKstStrFromKstMs(nowKstMs),
    startMsKst: startKstMs,
    endMsKst: nowKstMs,
  };
}

/* ---------------- cookies ---------------- */
function getCookie(req: Request, name: string): string | null {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";").map(s => s.trim());
  for (const part of parts) {
    if (part.startsWith(name + "=")) return decodeURIComponent(part.slice(name.length + 1));
  }
  return null;
}
function makeSessionCookie(req: Request, token: string) {
  const isHttps = new URL(req.url).protocol === "https:";
  const attrs = [
    `session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${60 * 60 * 24 * 7}`,
  ];
  if (isHttps) attrs.push("Secure");
  return attrs.join("; ");
}
function clearSessionCookie(req: Request) {
  const isHttps = new URL(req.url).protocol === "https:";
  const attrs = ["session=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (isHttps) attrs.push("Secure");
  return attrs.join("; ");
}

/* ---------------- cafe24 internal api ---------------- */
async function callCafe24(env: Env, path: string, init: RequestInit = {}) {
  const base = env.CAFE24_API_BASE?.replace(/\/$/, "");
  if (!base || !env.INTERNAL_TOKEN) throw new Error("Missing CAFE24_API_BASE or INTERNAL_TOKEN");

  const url = `${base}/${path.replace(/^\//, "")}`;

  // method 기본값: body 있으면 POST, 아니면 GET
  const method = (init.method ?? (init.body ? "POST" : "GET")).toUpperCase();

  const headers = new Headers(init.headers || {});
  headers.set("X-Internal-Token", env.INTERNAL_TOKEN);
  headers.set("Accept", "application/json");
  // 카페24 WAF가 Worker UA를 막는 경우가 있어 브라우저 UA로 우회
  headers.set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36");

  // ✅ GET 요청에는 Content-Type 넣지 않기 (카페24/WAF에서 406 원인)
  if (method !== "GET") {
    headers.set("Content-Type", "application/json; charset=utf-8");
  } else {
    headers.delete("Content-Type");
  }

  const r = await fetch(url, { ...init, method, headers });

  const text = await r.text();
  let data: any = text;
  try { data = JSON.parse(text); } catch {}
  return { r, data };
}

async function requireUser(req: Request, env: Env) {
  const token = getCookie(req, "session");
  if (!token) return { ok:false as const, status:401, error:"Not logged in" };
  const payload = await verifyJwt(token, env);
  if (!payload) return { ok:false as const, status:401, error:"Invalid session" };
  return { ok:true as const, user:{ id:String(payload.sub), email:String(payload.email) } };
}

/* ---------------- time window (KST 12h) ---------------- */
const KST_OFFSET_MS = 9 * 60 * 60 * 1000;
function pad2(n:number){ return String(n).padStart(2,"0"); }
function toKstMysql(dt: Date): string {
  // dt is UTC date object; convert to KST string
  const k = new Date(dt.getTime() + KST_OFFSET_MS);
  return `${k.getUTCFullYear()}-${pad2(k.getUTCMonth()+1)}-${pad2(k.getUTCDate())} ${pad2(k.getUTCHours())}:${pad2(k.getUTCMinutes())}:${pad2(k.getUTCSeconds())}`;
}
function getRunTypeFromCron(cron: string | undefined): "morning" | "evening" | "manual" {
  if (!cron) return "manual";
  if (cron.includes(" 21 ")) return "morning"; // UTC 21 => KST 06
  if (cron.includes(" 9 ")) return "evening";  // UTC 09 => KST 18
  return "manual";
}
function getWindowKst(runType:"morning"|"evening"|"manual", scheduledTimeMs:number) {
  // scheduledTimeMs is UTC timestamp
  const endUtc = new Date(scheduledTimeMs);
  // endKstString is “scheduled time in KST”
  const endKst = new Date(endUtc.getTime() + KST_OFFSET_MS);

  // Align to 06:00 or 18:00 for cron runs (manual은 now 기준 12h)
  let endAligned = endKst;
  if (runType === "morning") {
    endAligned = new Date(Date.UTC(endKst.getUTCFullYear(), endKst.getUTCMonth(), endKst.getUTCDate(), 6, 0, 0));
  } else if (runType === "evening") {
    endAligned = new Date(Date.UTC(endKst.getUTCFullYear(), endKst.getUTCMonth(), endKst.getUTCDate(), 18, 0, 0));
  } else {
    // manual: 현재 KST 기준
    endAligned = endKst;
  }

  const startAligned = new Date(endAligned.getTime() - 12 * 60 * 60 * 1000);
  // back to UTC timeline string by treating these as KST strings
  return {
    startKstStr: `${startAligned.getUTCFullYear()}-${pad2(startAligned.getUTCMonth()+1)}-${pad2(startAligned.getUTCDate())} ${pad2(startAligned.getUTCHours())}:${pad2(startAligned.getUTCMinutes())}:${pad2(startAligned.getUTCSeconds())}`,
    endKstStr: `${endAligned.getUTCFullYear()}-${pad2(endAligned.getUTCMonth()+1)}-${pad2(endAligned.getUTCDate())} ${pad2(endAligned.getUTCHours())}:${pad2(endAligned.getUTCMinutes())}:${pad2(endAligned.getUTCSeconds())}`,
    // also return comparable JS timestamps in KST timeline (actually stored in Date.UTC fields)
    startMsKst: startAligned.getTime(),
    endMsKst: endAligned.getTime(),
  };
}

/* ---------------- RSS search (topic-driven) ---------------- */
function decodeXmlEntities(s: string) {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}
function stripCdata(s: string) {
  return s.replace(/^<!\[CDATA\[/, "").replace(/\]\]>$/, "");
}
function pickTag(block: string, tag: string): string | null {
  const re = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const m = block.match(re);
  if (!m) return null;
  return decodeXmlEntities(stripCdata(m[1].trim()));
}
type SourceItem = { title: string; url: string; publishedAtKstStr: string; publishedMsKst: number };

function parsePubDateToKstMs(pub: string): number {
  const d = new Date(pub);
  const utcMs = isNaN(d.getTime()) ? Date.now() : d.getTime();
  return utcMs + KST_OFFSET_MS; // compare in KST timeline
}

async function fetchNewsCandidatesByTopicTitle(topicTitle: string, limit = 30): Promise<SourceItem[]> {
  // Google News RSS search
  const q = encodeURIComponent(topicTitle);
  const feed = `https://news.google.com/rss/search?q=${q}&hl=ko&gl=KR&ceid=KR:ko`;

  const r = await fetch(feed, { headers: { "user-agent": "royce-site-bot/0.6" } });
  if (!r.ok) throw new Error(`RSS fetch failed: ${r.status}`);
  const xml = await r.text();

  const out: SourceItem[] = [];
  const itemMatches = xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/gi);

  for (const m of itemMatches) {
    const block = m[1];
    const title = pickTag(block, "title") || "";
    const link = pickTag(block, "link") || "";
    const pub = pickTag(block, "pubDate") || "";
    if (!title || !link) continue;

    const pubMsKst = pub ? parsePubDateToKstMs(pub) : (Date.now() + KST_OFFSET_MS);
    // pubKstStr: just for DB string (KST)
    const pubKstStr = toKstMysql(new Date(pub ? new Date(pub).getTime() : Date.now()));

    out.push({ title, url: link, publishedAtKstStr: pubKstStr, publishedMsKst: pubMsKst });
    if (out.length >= limit) break;
  }

  // link 기준 dedupe
  const seen = new Set<string>();
  const uniq: SourceItem[] = [];
  for (const it of out) {
    if (seen.has(it.url)) continue;
    seen.add(it.url);
    uniq.push(it);
  }
  return uniq;
}

/* ---------------- OpenAI article generation ---------------- */
async function openaiMakeArticle(
  env: Env,
  topicTitle: string,
  windowStartKst: string,
  windowEndKst: string,
  sources: { title: string }[]
): Promise<{ headline: string; body_md: string }> {
  // v0.4에서 요약 실패가 있어도 v0.6은 “실패하면 fallback”이면 충분(지금 우선순위 낮다 했으니)
  if (!env.OPENAI_API_KEY || !env.OPENAI_MODEL) throw new Error("Missing OPENAI env");

  const prompt = [
    `너는 뉴스 에디터다.`,
    `주제: ${topicTitle}`,
    `집계 구간(KST): ${windowStartKst} ~ ${windowEndKst}`,
    ``,
    `아래 "제목 목록"을 바탕으로, 이 구간의 흐름을 종합한 "기사 1개"를 한국어로 작성해.`,
    `요구사항:`,
    `- 링크/출처 URL을 본문에 쓰지 마라.`,
    `- 과장/추측 금지. 모르는 건 "불확실"이라고 써라.`,
    `- 최신 흐름만(이 구간)`,
    `- 출력은 반드시 JSON만: {"headline":"...","body_md":"..."} `,
    `- body_md는 마크다운(섹션/불릿 OK)`,
    ``,
    `제목 목록:`,
    ...sources.slice(0, 20).map((s, i) => `${i + 1}. ${s.title}`),
  ].join("\n");

  const r = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: env.OPENAI_MODEL,
      input: prompt,
      // JSON only 유도 (실패하면 fallback)
      text: { format: { type: "json_object" } },
    }),
  });

  const raw = await r.text();
  if (!r.ok) throw new Error(`OpenAI error: ${r.status} ${raw}`);

  const data = JSON.parse(raw);

  // raw responses에서 텍스트 추출 (안 되면 실패로 처리)
  let text = "";
  if (typeof data?.output_text === "string") text = data.output_text;
  if (!text && Array.isArray(data?.output)) {
    for (const item of data.output) {
      if (item?.type === "message" && Array.isArray(item.content)) {
        for (const c of item.content) {
          if (c?.type === "output_text" && typeof c.text === "string") text += c.text;
        }
      }
    }
  }
  text = (text || "").trim();
  const parsed = JSON.parse(text);

  const headline = String(parsed.headline || "").trim();
  const body_md = String(parsed.body_md || "").trim();
  if (!headline || !body_md) throw new Error("Invalid OpenAI article json");

  return { headline, body_md };
}

/* ---------------- v0.6 generation pipeline ---------------- */
type Topic = { id: number; slug: string; title: string };

async function getActiveTopics(env: Env): Promise<Topic[]> {
  const { r, data } = await callCafe24(env, "active_topics.php", { method: "GET" });
  if (!r.ok) throw new Error(`active_topics failed: ${r.status}`);
  return (data?.topics ?? []) as Topic[];
}

async function generateArticleForTopic(env: Env, topic: Topic, runType:"morning"|"evening"|"manual", window: ReturnType<typeof getWindowKst>) {
  // 1) 후보 수집
  const candidates = await fetchNewsCandidatesByTopicTitle(topic.title, 40);

  // 2) 시간 구간 필터 (KST timeline)
  const inWindow = candidates.filter(it => it.publishedMsKst >= window.startMsKst && it.publishedMsKst < window.endMsKst);

  // 너무 없으면: 구간 밖이라도 최신 몇 개로 fallback
  const used = inWindow.length >= 5 ? inWindow.slice(0, 20) : candidates.slice(0, 12);

  // 3) 기사 생성 (OpenAI 실패하면 fallback 기사)
  let article: { headline: string; body_md: string };
  try {
    article = await openaiMakeArticle(
      env,
      topic.title,
      window.startKstStr,
      window.endKstStr,
      used.map(u => ({ title: u.title }))
    );
  } catch {
    // fallback: 제목 기반 “브리핑 기사”
    const bullets = used.slice(0, 10).map(u => `- ${u.title}`).join("\n");
    article = {
      headline: `${topic.title} | ${runType === "morning" ? "오전" : runType === "evening" ? "오후" : "수동"} 종합`,
      body_md: [
        `## 요약`,
        `요약 생성이 실패해서 제목 기반 브리핑으로 대체했습니다.`,
        ``,
        `## 핵심 이슈`,
        bullets || "- (수집된 항목이 부족합니다)",
        ``,
        `## 한 줄`,
        `이 구간의 핵심 흐름은 "동향 정리 필요" 입니다.`,
      ].join("\n"),
    };
  }

  // 4) DB 저장 (기사 + sources)
  const { r, data } = await callCafe24(env, "article_upsert.php", {
    method: "POST",
    body: JSON.stringify({
      topic_id: topic.id,
      run_type: runType,
      period_start: window.startKstStr,
      period_end: window.endKstStr,
      headline: article.headline,
      body_md: article.body_md,
      sources: used.slice(0, 20).map(u => ({ title: u.title, url: u.url, published_at: u.publishedAtKstStr })),
    }),
  });

  if (!r.ok) throw new Error(`article_upsert failed: ${r.status} ${JSON.stringify(data)}`);

  return { ok:true, topic_id: topic.id, topic: topic.title, runType, used: used.length };
}

/* ---------------- API routes ---------------- */
export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const runType = getRunTypeFromCron((event as any).cron);
    const window = getWindowKst(runType, event.scheduledTime);

    ctx.waitUntil((async () => {
      try {
        const topics = await getActiveTopics(env);
        for (const t of topics) {
          try { await generateArticleForTopic(env, t, runType, window); }
          catch (e) { console.log("topic gen failed:", t.id, t.title, String(e)); }
        }
      } catch (e) {
        console.log("scheduled failed:", String(e));
      }
    })());
  },

  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") return withCors(req, env, new Response(null, { status: 204 }));

    // health
    if (req.method === "GET" && url.pathname === "/api/health") {
      return withCors(req, env, json({ ok:true, service:"worker", v:"0.6", ts:new Date().toISOString() }));
    }

    // ---------- public read-only (no login required) ----------
    // GET /api/public/topics
    if (req.method === "GET" && url.pathname === "/api/public/topics") {
      try {
        const topics = await getActiveTopics(env);
        return withCors(req, env, json({ ok: true, topics }));
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }

    // GET /api/public/articles?topic_id=123&limit=20
    if (req.method === "GET" && url.pathname === "/api/public/articles") {
      const topic_id = Number(url.searchParams.get("topic_id") || "0");
      const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || "20"), 1), 50);
      if (!Number.isInteger(topic_id) || topic_id <= 0) {
        return withCors(req, env, json({ ok: false, error: "Invalid topic_id" }, { status: 400 }));
      }

      try {
        const active = await getActiveTopics(env);
        if (!active.find(t => t.id === topic_id)) {
          return withCors(req, env, json({ ok: false, error: "Topic not available" }, { status: 404 }));
        }

        const { r, data } = await callCafe24(env, "articles_list.php", {
          method: "POST",
          body: JSON.stringify({ topic_id, limit }),
        });
        if (!r.ok) return withCors(req, env, json({ ok: false, error: "articles_list failed", cafe24: data }, { status: 502 }));

        return withCors(req, env, json({ ok: true, articles: data?.articles ?? [] }));
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }

    // GET /api/public/article?article_id=999
    if (req.method === "GET" && url.pathname === "/api/public/article") {
      const article_id = Number(url.searchParams.get("article_id") || "0");
      if (!Number.isInteger(article_id) || article_id <= 0) {
        return withCors(req, env, json({ ok: false, error: "Invalid article_id" }, { status: 400 }));
      }

      try {
        const { r, data } = await callCafe24(env, "article_get.php", {
          method: "POST",
          body: JSON.stringify({ article_id }),
        });
        if (!r.ok) return withCors(req, env, json({ ok: false, error: "article_get failed", cafe24: data }, { status: 502 }));

        const article = data?.article ?? null;
        if (!article) return withCors(req, env, json({ ok: true, article: null }));

        const active = await getActiveTopics(env);
        const tid = Number(article.topic_id || 0);
        if (!active.find(t => t.id === tid)) {
          return withCors(req, env, json({ ok: false, error: "Article not available" }, { status: 404 }));
        }

        return withCors(req, env, json({ ok: true, article }));
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }


    /* ---------- auth (same behavior) ---------- */
    if (req.method === "POST" && url.pathname === "/api/auth/register") {
      // v0.6 public-mode: sign-up disabled (login only)
      return withCors(req, env, json({ ok:false, error:"Not Found" }, { status:404 }));
    }


    if (req.method === "POST" && url.pathname === "/api/auth/login") {
      const body = await readJson_new<{ email?: string; password?: string }>(req);
      const email = String(body.email ?? "").trim().toLowerCase();
      const password = String(body.password ?? "");

      if (!email || !email.includes("@")) return withCors(req, env, json({ ok:false, error:"Invalid email" }, { status:400 }));
      if (!password) return withCors(req, env, json({ ok:false, error:"Missing password" }, { status:400 }));

      try {
        const { r, data } = await callCafe24(env, "users_verify.php", { method:"POST", body: JSON.stringify({ email, password }) });
        if (!r.ok) return withCors(req, env, json({ ok:false, error: data?.error || "Invalid credentials" }, { status:401 }));

        const user = data.user;
        const now = Math.floor(Date.now()/1000);
        const token = await signJwt({ sub:String(user.id), email:user.email, iat:now, exp: now + 60*60*24*7 }, env);

        const res = json({ ok:true, user:{ id:user.id, email:user.email } });
        const headers = new Headers(res.headers);
        const cookie = buildSessionCookie(req, token);

        return withCors(req, env, json({ ok: true, user }, {
          headers: { "Set-Cookie": cookie }
        }));

        //headers.append("Set-Cookie", makeSessionCookie(req, token));
        //return withCors(req, env, new Response(res.body, { status:200, headers }));
      } catch (e:any) {
        return withCors(req, env, json({ ok:false, error:String(e?.message ?? e) }, { status:500 }));
      }
    }

    if (req.method === "POST" && url.pathname === "/api/auth/logout") {
      const res = json({ ok:true });
      const headers = new Headers(res.headers);
      headers.append("Set-Cookie", clearSessionCookie(req));
      return withCors(req, env, new Response(res.body, { status:200, headers }));
    }

    /* ---------- v0.6: me + my topics ---------- */
    if (req.method === "GET" && url.pathname === "/api/me") {
      const auth = await requireUser(req, env);
      if (!auth.ok) return withCors(req, env, json({ ok:false, error:auth.error }, { status:auth.status }));

      try {
        const { r, data } = await callCafe24(env, "user_topics_list.php", {
          method: "POST",
          body: JSON.stringify({ user_id: Number(auth.user.id) }),
        });
        const topics = r.ok ? (data?.topics ?? []) : [];
        return withCors(req, env, json({ ok:true, user:{ id:auth.user.id, email:auth.user.email }, topics }));
      } catch {
        return withCors(req, env, json({ ok:true, user:{ id:auth.user.id, email:auth.user.email }, topics: [] }));
      }
    }

    // GET /api/my/topics
    if (req.method === "GET" && url.pathname === "/api/my/topics") {
      const auth = await requireUser(req, env);
      if (!auth.ok) return withCors(req, env, json({ ok:false, error:auth.error }, { status:auth.status }));

      const { r, data } = await callCafe24(env, "user_topics_list.php", {
        method:"POST",
        body: JSON.stringify({ user_id: Number(auth.user.id) }),
      });
      if (!r.ok) return withCors(req, env, json({ ok:false, error:"Failed to load topics" }, { status:502 }));
      return withCors(req, env, json({ ok:true, topics: data?.topics ?? [] }));
    }

    // POST /api/my/topics  {title}
    if (req.method === "POST" && url.pathname === "/api/my/topics") {
      const auth = await requireUser(req, env);
      if (!auth.ok) return withCors(req, env, json({ ok:false, error:auth.error }, { status:auth.status }));

      const body = await readJson_new<{ title?: string }>(req);
      const title = String(body.title ?? "").trim();
      if (!title) return withCors(req, env, json({ ok:false, error:"Missing title" }, { status:400 }));

      // 1) topic upsert
      const t = await callCafe24(env, "topic_upsert.php", { method:"POST", body: JSON.stringify({ title }) });
      if (!t.r.ok) return withCors(req, env, json({ ok:false, error:"topic_upsert failed", cafe24:t.data }, { status:502 }));

      // 2) subscribe
      const topic = t.data.topic;
      const s = await callCafe24(env, "user_topics_add.php", {
        method:"POST",
        body: JSON.stringify({ user_id: Number(auth.user.id), topic_id: Number(topic.id) }),
      });
      if (!s.r.ok) return withCors(req, env, json({ ok:false, error:"subscribe failed", cafe24:s.data }, { status:502 }));

      return withCors(req, env, json({ ok:true, topic }));
    }

    // DELETE /api/my/topics?topic_id=123
    if (req.method === "DELETE" && url.pathname === "/api/my/topics") {
      const auth = await requireUser(req, env);
      if (!auth.ok) return withCors(req, env, json({ ok:false, error:auth.error }, { status:auth.status }));

      const topic_id = Number(url.searchParams.get("topic_id") || "0");
      if (!Number.isInteger(topic_id) || topic_id <= 0) {
        return withCors(req, env, json({ ok:false, error:"Invalid topic_id" }, { status:400 }));
      }

      const { r, data } = await callCafe24(env, "user_topics_remove.php", {
        method:"POST",
        body: JSON.stringify({ user_id: Number(auth.user.id), topic_id }),
      });
      if (!r.ok) return withCors(req, env, json({ ok:false, error:"remove failed", cafe24:data }, { status:502 }));
      return withCors(req, env, json({ ok:true }));
    }
// GET /api/articles?topic_id=123&limit=20
if (req.method === "GET" && url.pathname === "/api/articles") {
  const auth = await requireUser(req, env);
  if (!auth.ok) return withCors(req, env, json({ ok:false, error:auth.error }, { status:auth.status }));

  const topic_id = Number(url.searchParams.get("topic_id") || "0");
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") || "20"), 1), 50);

  if (!Number.isInteger(topic_id) || topic_id <= 0) {
    return withCors(req, env, json({ ok:false, error:"Invalid topic_id" }, { status:400 }));
  }

  // 내 구독 토픽인지 확인(보안)
  const my = await callCafe24(env, "user_topics_list.php", {
    method: "POST",
    body: JSON.stringify({ user_id: Number(auth.user.id) }),
  });
  const topics = (my.data?.topics ?? []) as { id:number }[];
  if (!topics.find(t => Number(t.id) === topic_id)) {
    return withCors(req, env, json({ ok:false, error:"Not subscribed topic" }, { status:403 }));
  }

  const { r, data } = await callCafe24(env, "articles_list.php", {
    method: "POST",
    body: JSON.stringify({ topic_id, limit }),
  });
  if (!r.ok) return withCors(req, env, json({ ok:false, error:"articles_list failed", cafe24:data }, { status:502 }));

  return withCors(req, env, json({ ok:true, articles: data?.articles ?? [] }));
}
// GET /api/article?article_id=999
if (req.method === "GET" && url.pathname === "/api/article") {
  const auth = await requireUser(req, env);
  if (!auth.ok) return withCors(req, env, json({ ok:false, error:auth.error }, { status:auth.status }));

  const article_id = Number(url.searchParams.get("article_id") || "0");
  if (!Number.isInteger(article_id) || article_id <= 0) {
    return withCors(req, env, json({ ok:false, error:"Invalid article_id" }, { status:400 }));
  }

  const { r, data } = await callCafe24(env, "article_get.php", {
    method: "POST",
    body: JSON.stringify({ article_id }),
  });
  if (!r.ok) return withCors(req, env, json({ ok:false, error:"article_get failed", cafe24:data }, { status:502 }));

  // (선택) 여기서도 “내 토픽 글인지” 검증하려면 article.topic_id로 한번 더 체크 가능
  return withCors(req, env, json({ ok:true, article: data?.article ?? null }));
}

    /* ---------- v0.6: latest article per topic ---------- */
    // GET /api/articles/latest?topic_id=123
    if (req.method === "GET" && url.pathname === "/api/articles/latest") {
      const auth = await requireUser(req, env);
      if (!auth.ok) return withCors(req, env, json({ ok:false, error:auth.error }, { status:auth.status }));

      const topic_id = Number(url.searchParams.get("topic_id") || "0");
      if (!Number.isInteger(topic_id) || topic_id <= 0) {
        return withCors(req, env, json({ ok:false, error:"Invalid topic_id" }, { status:400 }));
      }

      const { r, data } = await callCafe24(env, "article_latest.php", {
        method:"POST",
        body: JSON.stringify({ topic_id }),
      });
      if (!r.ok) return withCors(req, env, json({ ok:false, error:"article_latest failed" }, { status:502 }));
      return withCors(req, env, json({ ok:true, article: data?.article ?? null }));
    }
    // POST /api/articles/generate-24h?topic_id=123
// 로그인 유저가 버튼 누르면: "현재시간 기준 최근 24시간" 기사 1개 생성
if (req.method === "POST" && url.pathname === "/api/articles/generate-24h") {
  const auth = await requireUser(req, env);
  if (!auth.ok) return withCors(req, env, json({ ok: false, error: auth.error }, { status: auth.status }));

  const topic_id = Number(url.searchParams.get("topic_id") || "0");
  if (!Number.isInteger(topic_id) || topic_id <= 0) {
    return withCors(req, env, json({ ok: false, error: "Invalid topic_id" }, { status: 400 }));
  }

  // ✅ 유저가 구독한 topic인지 확인
  const my = await callCafe24(env, "user_topics_list.php", {
    method: "POST",
    body: JSON.stringify({ user_id: Number(auth.user.id) }),
  });
  if (!my.r.ok) return withCors(req, env, json({ ok: false, error: "Failed to load my topics" }, { status: 502 }));

  const topics = (my.data?.topics ?? []) as { id: number; slug: string; title: string }[];
  const t = topics.find(x => Number(x.id) === topic_id);
  if (!t) return withCors(req, env, json({ ok: false, error: "Not subscribed topic" }, { status: 403 }));

  // (추천 +@) 너무 연타 방지: 최근 2분 내 생성된 기사가 있으면 그거 반환
  const latest = await callCafe24(env, "article_latest.php", {
    method: "POST",
    body: JSON.stringify({ topic_id }),
  });
  if (latest.r.ok && latest.data?.article?.created_at) {
    const createdAt = new Date(String(latest.data.article.created_at)).getTime();
    if (!isNaN(createdAt) && Date.now() - createdAt < 2 * 60 * 1000) {
      return withCors(req, env, json({ ok: true, reused: true, article: latest.data.article }));
    }
  }

  const window = getWindowLast24hKst(Date.now());
  try {
    // generateArticleForTopic(env, topic, runType, window) 기존 함수 그대로 활용
    const result = await generateArticleForTopic(
      env,
      { id: topic_id, slug: t.slug, title: t.title },
      "manual",
      window
    );

    // 생성 후 최신 다시 조회해서 돌려주면 UI가 편함
    const again = await callCafe24(env, "article_latest.php", {
      method: "POST",
      body: JSON.stringify({ topic_id }),
    });

    return withCors(req, env, json({
      ok: true,
      result,
      article: again.r.ok ? (again.data?.article ?? null) : null,
    }));
  } catch (e: any) {
    return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
  }
}


    /* ---------- v0.6: manual generate (admin token) ---------- */
    // POST /api/articles/generate?topic_id=123
    if (req.method === "POST" && url.pathname === "/api/articles/generate") {
      const token = req.headers.get("X-News-Token") || "";
      if (!env.NEWS_JOB_TOKEN || token !== env.NEWS_JOB_TOKEN) {
        return withCors(req, env, json({ ok:false, error:"Unauthorized" }, { status:401 }));
      }

      const runType: "manual" = "manual";
      const window = getWindowKst(runType, Date.now());

      const topic_id = Number(url.searchParams.get("topic_id") || "0");
      if (topic_id > 0) {
        // topic 정보를 가져오려면 active_topics에서 찾아도 되고, 여기선 단순히 active_topics에서 찾는다
        const topics = await getActiveTopics(env);
        const t = topics.find(x => x.id === topic_id);
        if (!t) return withCors(req, env, json({ ok:false, error:"topic not active/subscribed" }, { status:404 }));

        const r = await generateArticleForTopic(env, t, runType, window);
        return withCors(req, env, json({ ok:true, result:r }));
      }

      // 전체
      const topics = await getActiveTopics(env);
      const results: any[] = [];
      for (const t of topics) {
        try { results.push(await generateArticleForTopic(env, t, runType, window)); }
        catch (e:any) { results.push({ ok:false, topic_id:t.id, topic:t.title, error:String(e?.message ?? e) }); }
      }
      return withCors(req, env, json({ ok:true, results }));
    }

    return withCors(req, env, json({ ok:false, error:"Not Found" }, { status:404 }));
  },
};
