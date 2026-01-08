export interface Env {
  CAFE24_API_BASE: string;
  INTERNAL_TOKEN: string;
  JWT_SECRET: string;

  // 선택: "https://xxx.pages.dev,https://yourdomain.com"
  ALLOWED_ORIGINS?: string;
}

function json(data: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });
}

function getAllowedOrigin(req: Request, env: Env): string | null {
  const origin = req.headers.get("Origin");
  if (!origin) return null;

  const allowed = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  // v0.x 개발 편의: 설정 없으면 origin 허용
  if (allowed.length === 0) return origin;
  return allowed.includes(origin) ? origin : null;
}

function withCors(req: Request, env: Env, res: Response) {
  const allowedOrigin = getAllowedOrigin(req, env);
  const headers = new Headers(res.headers);

  if (allowedOrigin) {
    headers.set("Access-Control-Allow-Origin", allowedOrigin);
    headers.set("Access-Control-Allow-Credentials", "true");
    headers.set("Access-Control-Allow-Headers", "content-type, x-internal-token");
    headers.set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    headers.set("Vary", "Origin");
  }

  return new Response(res.body, { status: res.status, headers });
}

async function readJson(req: Request) {
  const ct = req.headers.get("content-type") || "";
  if (!ct.includes("application/json")) return null;
  try {
    return await req.json<any>();
  } catch {
    return null;
  }
}

// ---------- JWT (HS256) ----------
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
    keyCache.set(
      secret,
      crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      )
    );
  }
  return keyCache.get(secret)!;
}

async function signJwt(payload: Record<string, any>, env: Env) {
  const header = { alg: "HS256", typ: "JWT" };
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

  const [h, p, s] = parts;
  const msg = `${h}.${p}`;
  const sig = b64urlDecodeToU8(s);

  const key = await getHmacKey(env.JWT_SECRET);
  const ok = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(msg));
  if (!ok) return null;

  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecodeToU8(p)));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// ---------- cookies ----------
function getCookie(req: Request, name: string): string | null {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";").map((s) => s.trim());
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
    `Max-Age=${60 * 60 * 24 * 7}`, // 7 days
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

// ---------- Cafe24 internal API helper ----------
async function callCafe24(env: Env, path: string, init: RequestInit) {
  const base = env.CAFE24_API_BASE?.replace(/\/$/, "");
  if (!base || !env.INTERNAL_TOKEN) throw new Error("Missing CAFE24_API_BASE or INTERNAL_TOKEN");

  const url = `${base}/${path.replace(/^\//, "")}`;
  const headers = new Headers(init.headers || {});
  headers.set("X-Internal-Token", env.INTERNAL_TOKEN);
  headers.set("Content-Type", "application/json");

  const r = await fetch(url, { ...init, headers });
  const text = await r.text();
  let data: any = text;
  try {
    data = JSON.parse(text);
  } catch {
    // ignore
  }
  return { r, data };
}

async function requireUser(req: Request, env: Env) {
  const token = getCookie(req, "session");
  if (!token) return { ok: false as const, status: 401, error: "Not logged in" };
  const payload = await verifyJwt(token, env);
  if (!payload) return { ok: false as const, status: 401, error: "Invalid session" };
  return { ok: true as const, user: { id: String(payload.sub), email: String(payload.email) } };
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "OPTIONS") {
      return withCors(req, env, new Response(null, { status: 204 }));
    }

    // v0.1 유지
    if (req.method === "GET" && url.pathname === "/api/health") {
      return withCors(req, env, json({ ok: true, service: "worker", ts: new Date().toISOString() }));
    }

    if (req.method === "GET" && url.pathname === "/api/ping-db") {
      try {
        const { r, data } = await callCafe24(env, "health.php", { method: "GET" });
        return withCors(
          req,
          env,
          json({ ok: r.ok, cafe24: { status: r.status, data } }, { status: r.ok ? 200 : 502 })
        );
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }

    // ---------------- v0.2 AUTH ----------------
    if (req.method === "POST" && url.pathname === "/api/auth/register") {
      if (!env.JWT_SECRET) return withCors(req, env, json({ ok: false, error: "Missing JWT_SECRET" }, { status: 500 }));

      const body = await readJson(req);
      const email = body?.email ? String(body.email).trim() : "";
      const password = body?.password ? String(body.password) : "";

      if (!email || !email.includes("@")) return withCors(req, env, json({ ok: false, error: "Invalid email" }, { status: 400 }));
      if (!password || password.length < 8) return withCors(req, env, json({ ok: false, error: "Password must be at least 8 characters" }, { status: 400 }));

      try {
        const { r, data } = await callCafe24(env, "users_create.php", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });

        if (!r.ok) {
          return withCors(req, env, json({ ok: false, error: data?.error || "Register failed", cafe24: data }, { status: r.status }));
        }

        const user = data.user;
        const now = Math.floor(Date.now() / 1000);
        const token = await signJwt(
          { sub: String(user.id), email: user.email, iat: now, exp: now + 60 * 60 * 24 * 7 },
          env
        );

        const res = json({ ok: true, user: { id: user.id, email: user.email } }, { status: 201 });
        const headers = new Headers(res.headers);
        headers.append("Set-Cookie", makeSessionCookie(req, token));
        return withCors(req, env, new Response(res.body, { status: 201, headers }));
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }

    if (req.method === "POST" && url.pathname === "/api/auth/login") {
      if (!env.JWT_SECRET) return withCors(req, env, json({ ok: false, error: "Missing JWT_SECRET" }, { status: 500 }));

      const body = await readJson(req);
      const email = body?.email ? String(body.email).trim() : "";
      const password = body?.password ? String(body.password) : "";

      if (!email || !email.includes("@")) return withCors(req, env, json({ ok: false, error: "Invalid email" }, { status: 400 }));
      if (!password) return withCors(req, env, json({ ok: false, error: "Missing password" }, { status: 400 }));

      try {
        const { r, data } = await callCafe24(env, "users_verify.php", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });

        if (!r.ok) {
          return withCors(req, env, json({ ok: false, error: data?.error || "Invalid credentials" }, { status: 401 }));
        }

        const user = data.user;
        const now = Math.floor(Date.now() / 1000);
        const token = await signJwt(
          { sub: String(user.id), email: user.email, iat: now, exp: now + 60 * 60 * 24 * 7 },
          env
        );

        const res = json({ ok: true, user: { id: user.id, email: user.email } });
        const headers = new Headers(res.headers);
        headers.append("Set-Cookie", makeSessionCookie(req, token));
        return withCors(req, env, new Response(res.body, { status: 200, headers }));
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }

    if (req.method === "POST" && url.pathname === "/api/auth/logout") {
      const res = json({ ok: true });
      const headers = new Headers(res.headers);
      headers.append("Set-Cookie", clearSessionCookie(req));
      return withCors(req, env, new Response(res.body, { status: 200, headers }));
    }

    // ---------------- v0.3 NEW ----------------

    // GET /api/topics
    if (req.method === "GET" && url.pathname === "/api/topics") {
      try {
        const { r, data } = await callCafe24(env, "topics_list.php", { method: "GET" });
        return withCors(
          req,
          env,
          json({ ok: r.ok, topics: data?.topics ?? data }, { status: r.ok ? 200 : 502 })
        );
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }

    // PUT /api/me/topic  { topic_id: number|null }
    if (req.method === "PUT" && url.pathname === "/api/me/topic") {
      if (!env.JWT_SECRET) return withCors(req, env, json({ ok: false, error: "Missing JWT_SECRET" }, { status: 500 }));

      const auth = await requireUser(req, env);
      if (!auth.ok) return withCors(req, env, json({ ok: false, error: auth.error }, { status: auth.status }));

      const body = await readJson(req);
      const topicIdRaw = body?.topic_id;

      // null 허용(선택 해제)
      const topic_id =
        topicIdRaw === null || topicIdRaw === undefined ? null : Number(topicIdRaw);

      if (topic_id !== null && (!Number.isInteger(topic_id) || topic_id <= 0)) {
        return withCors(req, env, json({ ok: false, error: "topic_id must be a positive integer or null" }, { status: 400 }));
      }

      try {
        const { r, data } = await callCafe24(env, "user_profile_set.php", {
          method: "POST",
          body: JSON.stringify({ user_id: Number(auth.user.id), topic_id: topic_id ?? 0 }),
        });

        if (!r.ok) {
          return withCors(req, env, json({ ok: false, error: data?.error || "Failed to save topic", cafe24: data }, { status: r.status }));
        }

        return withCors(req, env, json({ ok: true }));
      } catch (e: any) {
        return withCors(req, env, json({ ok: false, error: String(e?.message ?? e) }, { status: 500 }));
      }
    }

    // GET /api/me (토픽 포함)
    if (req.method === "GET" && url.pathname === "/api/me") {
      if (!env.JWT_SECRET) return withCors(req, env, json({ ok: false, error: "Missing JWT_SECRET" }, { status: 500 }));

      const auth = await requireUser(req, env);
      if (!auth.ok) return withCors(req, env, json({ ok: false, error: auth.error }, { status: auth.status }));

      // profile 가져오기
      try {
        const { r, data } = await callCafe24(env, "user_profile_get.php", {
          method: "POST",
          body: JSON.stringify({ user_id: Number(auth.user.id) }),
        });

        const profile = r.ok ? data?.profile ?? null : null;

        return withCors(
          req,
          env,
          json({
            ok: true,
            user: {
              id: auth.user.id,
              email: auth.user.email,
              selected_topic: profile?.topic ?? null,
            },
          })
        );
      } catch {
        // profile 실패해도 me는 살아있게
        return withCors(
          req,
          env,
          json({ ok: true, user: { id: auth.user.id, email: auth.user.email, selected_topic: null } })
        );
      }
    }

    // GET /api/news/latest (v0.3: 더미)
    // topic은 query로 받거나, 없으면 /me의 selected_topic을 쓰면 되는데
    // v0.3에선 간단히 query topic(slug)만 처리.
    if (req.method === "GET" && url.pathname === "/api/news/latest") {
      const topic = url.searchParams.get("topic") || "ai";

      const items = [
        {
          id: "dummy-1",
          topic,
          title: `[${topic}] 오늘의 더미 뉴스 1`,
          summary: "v0.4에서 OpenAI + RSS로 진짜 뉴스가 채워질 예정입니다.",
          url: "https://example.com",
          published_at: new Date().toISOString(),
        },
        {
          id: "dummy-2",
          topic,
          title: `[${topic}] 오늘의 더미 뉴스 2`,
          summary: "지금은 API/DB/세션 구조 확인 단계라 더미로 갑니다.",
          url: "https://example.com",
          published_at: new Date().toISOString(),
        },
      ];

      return withCors(req, env, json({ ok: true, topic, items }));
    }

    return withCors(req, env, json({ ok: false, error: "Not Found" }, { status: 404 }));
  },
};
