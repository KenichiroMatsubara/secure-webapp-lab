import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "../env";

/**
 * Cloudflare Access の JWT 検証（多層防御の 2 枚目）。
 *
 * Access の前段ポリシーが外れたり、別のホスト名でこの Worker に直接届いたりしても、
 * 署名・issuer・audience が正しい JWT を持たないリクエストは常に拒否する。
 * ENVIRONMENT が "development" のとき（ローカル開発）だけ検証を省く。それ以外はすべて fail-closed。
 *
 * このファイルは、アプリ内で唯一の外部通信（Access の公開鍵 JWKS の取得）を行う場所。
 * scripts/check-no-egress.ts が、他のファイルに外部通信コードが入っていないことを確かめる。
 */

let jwksOverride: JWTVerifyGetKey | null = null;
const jwksCache = new Map<string, JWTVerifyGetKey>();

/** テスト用: JWKS の取得先を差し替える */
export function __setJwksForTest(fn: JWTVerifyGetKey | null): void {
  jwksOverride = fn;
}

function normalizeTeamDomain(raw: string): string {
  const withScheme = /^https?:\/\//.test(raw) ? raw : `https://${raw}`;
  return withScheme.replace(/\/+$/, "");
}

function jwksFor(issuer: string): JWTVerifyGetKey {
  if (jwksOverride) return jwksOverride;
  let jwks = jwksCache.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`), {
      cooldownDuration: 30_000,
      cacheMaxAge: 10 * 60_000,
    });
    jwksCache.set(issuer, jwks);
  }
  return jwks;
}

export const accessGate = (): MiddlewareHandler<AppEnv> => {
  return async (c, next) => {
    if (c.env.ENVIRONMENT === "development") {
      c.set("accessEmail", null);
      return next();
    }

    const teamRaw = c.env.ACCESS_TEAM_DOMAIN?.trim();
    const aud = c.env.ACCESS_AUD?.trim();
    if (!teamRaw || !aud) {
      return c.text(
        "このラボは未設定のため停止しています（ACCESS_TEAM_DOMAIN / ACCESS_AUD が必要）。docs/DEPLOY.md を参照してください。",
        503,
      );
    }

    const token = c.req.header("Cf-Access-Jwt-Assertion");
    if (!token) return c.text("Forbidden: Cloudflare Access を経由してアクセスしてください。", 403);

    const issuer = normalizeTeamDomain(teamRaw);
    try {
      const { payload } = await jwtVerify(token, jwksFor(issuer), {
        issuer,
        audience: aud,
        algorithms: ["RS256"],
      });
      const email = typeof payload.email === "string" ? payload.email.toLowerCase() : null;
      if (!email) return c.text("Forbidden: メールアドレスのない Access トークンです。", 403);

      const allowed = (c.env.ALLOWED_EMAILS ?? "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
      if (allowed.length > 0 && !allowed.includes(email)) {
        return c.text("Forbidden: 許可されていないユーザーです。", 403);
      }
      c.set("accessEmail", email);
    } catch {
      return c.text("Forbidden: Access トークンを検証できませんでした。", 403);
    }
    return next();
  };
};
