import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

const q = (s: string) => `?q=${encodeURIComponent(s)}`;

describe("反射型XSS", () => {
  it("脆弱版: 入力値がそのままHTMLに出る（本文）", async () => {
    const b = new Browser();
    const html = await b.text(`/x/xss-reflected/vuln/${q("<script>alert(1)</script>")}`);
    expect(html).toContain("<p>「<script>alert(1)</script>」の検索結果");
  });

  it("脆弱版: 引用符なしの属性に追加の属性を差し込める", async () => {
    const b = new Browser();
    const html = await b.text(`/x/xss-reflected/vuln/${q("x onfocus=alert(1) autofocus")}`);
    expect(html).toContain("<input name=q value=x onfocus=alert(1) autofocus>");
  });

  it("修正版: 本文も属性もエスケープされ、タグにも属性にもならない", async () => {
    const b = new Browser();
    const html = await b.text(`/x/xss-reflected/fixed/${q('"><script>alert(1)</script>')}`);
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain('value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"');
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;」の検索結果");
  });

  it("修正版: 属性を差し込む入力も文字列のままになる", async () => {
    const b = new Browser();
    const html = await b.text(`/x/xss-reflected/fixed/${q('x" onfocus="alert(1)')}`);
    expect(html).toContain('value="x&quot; onfocus=&quot;alert(1)"');
  });

  it("Cookie: 脆弱版は JS から読め、修正版は HttpOnly", async () => {
    const b = new Browser();
    const v = await b.get("/x/xss-reflected/vuln/");
    const f = await b.get("/x/xss-reflected/fixed/");
    expect(v.headers.getSetCookie().find((c) => c.startsWith("demo_secret="))).not.toMatch(/HttpOnly/i);
    expect(f.headers.getSetCookie().find((c) => c.startsWith("demo_secret="))).toMatch(/HttpOnly/i);
  });

  it("修正版は CSP でインラインスクリプトを禁止し、脆弱版も外部への持ち出しはガードされる", async () => {
    const b = new Browser();
    const f = await b.get("/x/xss-reflected/fixed/");
    expect(f.headers.get("content-security-policy")).toContain("script-src 'self'");
    const v = await b.get("/x/xss-reflected/vuln/");
    const csp = v.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("img-src 'self' data:");
  });

  it("攻撃者サイト: 盗まれた Cookie が記録され、一覧に出る", async () => {
    const b = new Browser();
    await b.get("/x/xss-reflected/vuln/"); // demo_secret を受け取る
    const cookie = b.cookie("demo_secret")!;
    const res = await b.get(`/attacker/xss-reflected/collect?c=${encodeURIComponent("demo_secret=" + cookie)}`);
    expect(res.status).toBe(204);
    const page = await b.text("/attacker/xss-reflected/");
    expect(page).toContain("demo_secret=SESSION-DEMO-1234");
    // 攻撃者ページは sandbox CSP で別オリジン扱い
    const r = await b.get("/attacker/xss-reflected/");
    expect(r.headers.get("content-security-policy")).toContain("sandbox");
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await a.get(`/attacker/xss-reflected/collect?c=only-for-a`);
    expect(await a.text("/attacker/xss-reflected/")).toContain("only-for-a");
    expect(await other.text("/attacker/xss-reflected/")).not.toContain("only-for-a");
  });
});

describe("解説ページ", () => {
  it("原因のコード・修正の差分が表示され、[!] の行がハイライトされる", async () => {
    const b = new Browser();
    const html = await b.text("/x/xss-reflected");
    expect(html).toContain("反射型XSS");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
