import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import type { AppEnv } from "../src/env";
import { applyLabGuard, isLabSafeHost } from "../src/lab/guard";

// ガード単体のテスト。ダミーのルートからリダイレクトを返し、外側で止められることを確かめる
const t = new Hono<AppEnv>();
t.get("/x/dummy/vuln/go", (c) => c.redirect(c.req.query("to") ?? "/", 302));
t.get("/x/dummy/fixed/csp", (c) => c.text("ok", 200, { "Content-Security-Policy": "script-src 'self'" }));
t.get("/x/dummy/vuln/cookie", (c) => {
  c.header("Set-Cookie", "sid=abc; HttpOnly");
  return c.redirect("https://www.google.com/", 302);
});
t.get("/x/dummy/fixed/go", (c) => c.redirect(c.req.query("to") ?? "/", 302));
const get = async (path: string) => {
  const req = new Request(`https://lab.test${path}`);
  return applyLabGuard(req, await t.fetch(req));
};

describe("ラボガード: リダイレクト", () => {
  it("同一オリジン・相対パスはそのまま通す", async () => {
    const res = await get("/x/dummy/vuln/go?to=%2Fdone");
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/done");
  });

  it("予約ドメイン（.example / .test / example.com）への転送は通す", async () => {
    for (const to of ["https://evil.example/login", "http://phish.test/", "https://sub.example.com/x", "//evil.example/"]) {
      const res = await get(`/x/dummy/vuln/go?to=${encodeURIComponent(to)}`);
      expect(res.status, to).toBe(302);
    }
  });

  it("実在しうるサイトへの転送は止めて、Location の値だけを表示する", async () => {
    for (const to of ["https://www.google.com/", "//attacker.com/", "https://evil.example.attacker.net/", "https://example.com.attacker.net/"]) {
      const res = await get(`/x/dummy/vuln/go?to=${encodeURIComponent(to)}`);
      expect(res.status, to).toBe(200);
      expect(res.headers.get("location"), to).toBeNull();
      expect(await res.text()).toContain("ラボガード");
    }
  });

  it("javascript: / data: の Location も止める", async () => {
    for (const to of ["javascript:alert(1)", "data:text/html,hi"]) {
      const res = await get(`/x/dummy/fixed/go?to=${encodeURIComponent(to)}`);
      expect(res.status, to).toBe(200);
    }
  });

  it("止めたページに入力値が生で出ない（ガード自身がXSSにならない）", async () => {
    const res = await get(`/x/dummy/vuln/go?to=${encodeURIComponent("https://a.com/?<script>alert(1)</script>")}`);
    const html = await res.text();
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("ラボガード: ヘッダー", () => {
  it("脆弱版・修正版には持ち出し防止の CSP、攻撃者ページには sandbox、その他には厳格な CSP", async () => {
    const v = (await get("/x/dummy/vuln/go")).headers.get("content-security-policy")!;
    expect(v).toContain("connect-src 'self'");
    expect(v).toContain("form-action 'self'");
    expect(v).toContain("frame-ancestors 'self'");
    expect((await get("/x/dummy/fixed/go")).headers.get("content-security-policy")).toContain("connect-src 'self'");
    expect((await get("/attacker/dummy/")).headers.get("content-security-policy")).toMatch(/^sandbox allow-forms allow-scripts;/);
    const shell = await get("/anything");
    expect(shell.headers.get("content-security-policy")).toContain("script-src 'self'");
    expect(shell.headers.get("x-frame-options")).toBe("DENY");
  });

  it("修正版が自前で付けた CSP と、ガードの CSP の両方が残る", async () => {
    const res = await get("/x/dummy/fixed/csp");
    const all = res.headers.get("content-security-policy")!;
    expect(all).toContain("script-src 'self'");
    expect(all).toContain("connect-src 'self'");
  });

  it("止めたリダイレクトでも Set-Cookie は維持する", async () => {
    const res = await get("/x/dummy/vuln/cookie");
    expect(res.status).toBe(200);
    expect(res.headers.getSetCookie()).toContain("sid=abc; HttpOnly");
  });

  it("全レスポンスに noindex・no-store・nosniff が付く", async () => {
    const res = await get("/x/dummy/vuln/go");
    expect(res.headers.get("x-robots-tag")).toContain("noindex");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    // no-referrer だと同一オリジンの POST にも Origin: null が付き、Origin 検証が誤って拒否する
    expect(res.headers.get("referrer-policy")).toBe("same-origin");
  });
});

describe("isLabSafeHost", () => {
  it("予約ドメインだけを安全とみなす", () => {
    for (const h of ["evil.example", "a.b.test", "example.com", "x.example.org", "localhost", "foo.localhost", "foo.invalid"])
      expect(isLabSafeHost(h), h).toBe(true);
    for (const h of ["google.com", "example.com.evil.net", "notexample.com", "evil-example.com", "test.com"])
      expect(isLabSafeHost(h), h).toBe(false);
  });
});
