import { env, exports } from "cloudflare:workers";
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import worker from "../src/index";
import { __setJwksForTest } from "../src/lab/access";

// ENVIRONMENT=production（本番相当）で動かして、Access の JWT 検証が fail-closed であることを確かめる
const TEAM = "https://labteam.cloudflareaccess.com";
const AUD = "test-aud-tag";

const prodEnv = (over: Record<string, string> = {}) => ({
  LAB: env.LAB,
  ENVIRONMENT: "production",
  ACCESS_TEAM_DOMAIN: TEAM,
  ACCESS_AUD: AUD,
  ALLOWED_EMAILS: "",
  LAB_TTL_HOURS: "24",
  PBKDF2_ITERATIONS: "1000",
  ...over,
});

const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
const call = (e: ReturnType<typeof prodEnv>, path: string, headers: Record<string, string> = {}) =>
  worker.fetch(new Request(`https://lab.test${path}`, { headers }), e as never, ctx);

let privateKey: CryptoKey;
let otherKey: CryptoKey;

async function token(opts: { email?: string; aud?: string; iss?: string; exp?: string; key?: CryptoKey; kid?: string } = {}) {
  const jwt = new SignJWT({ email: opts.email ?? "learner@example.com" })
    .setProtectedHeader({ alg: "RS256", kid: opts.kid ?? "k1" })
    .setIssuer(opts.iss ?? TEAM)
    .setAudience(opts.aud ?? AUD)
    .setIssuedAt()
    .setExpirationTime(opts.exp ?? "5m");
  return jwt.sign(opts.key ?? privateKey);
}

beforeAll(async () => {
  const pair = await generateKeyPair("RS256", { extractable: true });
  privateKey = pair.privateKey;
  otherKey = (await generateKeyPair("RS256")).privateKey;
  const jwk: JWK = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  __setJwksForTest(createLocalJWKSet({ keys: [jwk] }));
});

describe("Cloudflare Access の検証（本番相当）", () => {
  it("設定がなければ全リクエストを止める（fail-closed）", async () => {
    const res = await call(prodEnv({ ACCESS_TEAM_DOMAIN: "", ACCESS_AUD: "" }), "/");
    expect(res.status).toBe(503);
  });

  it("JWT がなければ 403", async () => {
    expect((await call(prodEnv(), "/")).status).toBe(403);
  });

  it("壊れた JWT・別の鍵で署名した JWT は 403", async () => {
    expect((await call(prodEnv(), "/", { "Cf-Access-Jwt-Assertion": "x.y.z" })).status).toBe(403);
    const forged = await token({ key: otherKey });
    expect((await call(prodEnv(), "/", { "Cf-Access-Jwt-Assertion": forged })).status).toBe(403);
  });

  it("audience / issuer / 有効期限が違えば 403", async () => {
    for (const t of [await token({ aud: "other" }), await token({ iss: "https://evil.example" }), await token({ exp: "-1m" })]) {
      expect((await call(prodEnv(), "/", { "Cf-Access-Jwt-Assertion": t })).status).toBe(403);
    }
  });

  it("alg=none の偽造トークンは 403", async () => {
    const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    const none = `${b64({ alg: "none", typ: "JWT" })}.${b64({ email: "a@example.com", aud: AUD, iss: TEAM, exp: 9999999999 })}.`;
    expect((await call(prodEnv(), "/", { "Cf-Access-Jwt-Assertion": none })).status).toBe(403);
  });

  it("正しい JWT なら通り、拒否レスポンスにも noindex / CSP が付く", async () => {
    const ok = await call(prodEnv(), "/", { "Cf-Access-Jwt-Assertion": await token() });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("x-robots-tag")).toContain("noindex");
    const denied = await call(prodEnv(), "/");
    expect(denied.headers.get("x-robots-tag")).toContain("noindex");
    expect(denied.headers.get("content-security-policy")).toBeTruthy();
  });

  it("ALLOWED_EMAILS に含まれないメールは 403（二重チェック）", async () => {
    const e = prodEnv({ ALLOWED_EMAILS: "me@example.com" });
    expect((await call(e, "/", { "Cf-Access-Jwt-Assertion": await token({ email: "other@example.com" }) })).status).toBe(403);
    expect((await call(e, "/", { "Cf-Access-Jwt-Assertion": await token({ email: "ME@example.com" }) })).status).toBe(200);
  });

  it("メールごとに学習データが分かれ、別のメールには見えない", async () => {
    const e = prodEnv();
    const ta = await token({ email: "a@example.com" });
    const tb = await token({ email: "b@example.com" });
    await call(e, "/attacker/xss-reflected/collect?c=secret-of-a", { "Cf-Access-Jwt-Assertion": ta });
    const a = await (await call(e, "/attacker/xss-reflected/", { "Cf-Access-Jwt-Assertion": ta })).text();
    const b = await (await call(e, "/attacker/xss-reflected/", { "Cf-Access-Jwt-Assertion": tb })).text();
    expect(a).toContain("secret-of-a");
    expect(b).not.toContain("secret-of-a");
  });
});

describe("ローカル開発モード", () => {
  it("ENVIRONMENT=development では Access なしで動く", async () => {
    const res = await exports.default.fetch("http://lab.test/");
    expect(res.status).toBe(200);
  });
});
