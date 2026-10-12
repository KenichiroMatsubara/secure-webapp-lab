import type { MiddlewareHandler } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import type { AppEnv } from "../env";
import { dbClient } from "./db";

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** https か localhost のときだけ SameSite=None; Secure の Cookie を使える（CSRF 演習のクロスサイト再現に必要） */
export function canUseCrossSiteCookies(url: string): boolean {
  const u = new URL(url);
  return u.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
}

const LAB_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * 学習者を特定し、その人専用の DB（Durable Object）を c.var.db に載せる。
 *  - 本番（Access 経由）: 認証されたメールアドレスのハッシュ → 同じ人は別の端末でも同じ学習データ
 *  - ローカル開発: lab_id Cookie（ランダム UUID）
 */
export const learnerContext = (): MiddlewareHandler<AppEnv> => async (c, next) => {
  const crossSite = canUseCrossSiteCookies(c.req.url);
  c.set("crossSiteCookies", crossSite);

  let key: string;
  const email = c.get("accessEmail");
  if (email) {
    key = `u:${(await sha256Hex(email)).slice(0, 32)}`;
  } else {
    let id = getCookie(c, "lab_id");
    if (!id || !LAB_ID_RE.test(id)) {
      id = crypto.randomUUID();
      // クロスサイトの攻撃者ページからのリクエストでも同じ学習者の DB に届くよう SameSite=None にする（理由は docs/SAFETY.md）
      setCookie(c, "lab_id", id, {
        path: "/",
        httpOnly: true,
        maxAge: 60 * 60 * 24 * 30,
        sameSite: crossSite ? "None" : "Lax",
        secure: crossSite,
      });
    }
    key = `c:${id}`;
  }
  c.set("learner", key);
  c.set("db", dbClient(c.env.LAB.get(c.env.LAB.idFromName(key))));
  await next();
};
