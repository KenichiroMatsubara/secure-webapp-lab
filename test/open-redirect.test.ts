import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

const ORIGIN = "http://lab.test";
const VULN_HOME = "/x/open-redirect/vuln/mypage";
const FIXED_HOME = "/x/open-redirect/fixed/mypage";

// 転送先の例はすべて予約ドメイン（evil.example）
const ATTACKS = [
  "https://evil.example/login",
  "//evil.example/login",
  "/\\evil.example/login",
  "https://example.com@evil.example/",
];

/** ブラウザが Location をどう解釈して移動するか */
const hostOf = (location: string) => new URL(location, ORIGIN).host;

async function loginRedirect(b: Browser, base: string, next: string) {
  return b.post(`${base}/login`, { next });
}

describe("オープンリダイレクト 脆弱版 (A) 検証なし", () => {
  it("正常系: next が無ければマイページ、相対パスならそのパスへ", async () => {
    const b = new Browser();
    const res = await loginRedirect(b, "/x/open-redirect/vuln", "");
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(VULN_HOME);
    const res2 = await loginRedirect(b, "/x/open-redirect/vuln", VULN_HOME);
    expect(res2.headers.get("location")).toBe(VULN_HOME);
  });

  it("攻撃成立: ログイン後の next に外部のURLを入れると、そのまま Location になる", async () => {
    const b = new Browser();
    for (const next of ATTACKS) {
      const res = await loginRedirect(b, "/x/open-redirect/vuln", next);
      expect(res.status).toBe(303);
      expect(res.headers.get("location")).toBe(next);
      expect(hostOf(next)).toBe("evil.example");
    }
  });

  it("攻撃成立: /redirect?url= も検証なしで転送する", async () => {
    const b = new Browser();
    for (const url of ATTACKS) {
      const res = await b.get(`/x/open-redirect/vuln/redirect?url=${encodeURIComponent(url)}`);
      expect(res.status).toBe(302);
      expect(res.headers.get("location")).toBe(url);
    }
  });

  it("ログイン画面に、転送先（Location）とブラウザの移動先が表示される", async () => {
    const b = new Browser();
    const html = await b.text(`/x/open-redirect/vuln/login?next=${encodeURIComponent("https://example.com@evil.example/")}`);
    expect(html).toContain("Location: https://example.com@evil.example/");
    expect(html).toContain("<code>evil.example</code>（別のサイト）");
    // 入力値は属性値にも安全に埋め込まれる（この演習の主題は XSS ではない）
    const html2 = await b.text(`/x/open-redirect/vuln/login?next=${encodeURIComponent('"><script>alert(1)</script>')}`);
    expect(html2).not.toContain("<script>alert(1)");
  });
});

describe("オープンリダイレクト 脆弱版 (B) startsWith(\"/\") だけの検証", () => {
  it("絶対URLは弾かれ、既定のマイページに戻る（検証が効いて見える）", async () => {
    const b = new Browser();
    const res = await loginRedirect(b, "/x/open-redirect/vuln/b", "https://evil.example/login");
    expect(res.headers.get("location")).toBe(VULN_HOME);
    const res2 = await b.get(`/x/open-redirect/vuln/b/redirect?url=${encodeURIComponent("https://example.com@evil.example/")}`);
    expect(res2.headers.get("location")).toBe(VULN_HOME);
  });

  it("攻撃成立: // と /\\ で始まる値は検証を通り抜け、外部へ転送される", async () => {
    const b = new Browser();
    for (const next of ["//evil.example/login", "/\\evil.example/login"]) {
      const res = await loginRedirect(b, "/x/open-redirect/vuln/b", next);
      expect(res.status).toBe(303);
      expect(res.headers.get("location")).toBe(next);
      expect(hostOf(next)).toBe("evil.example");
      const res2 = await b.get(`/x/open-redirect/vuln/b/redirect?url=${encodeURIComponent(next)}`);
      expect(res2.headers.get("location")).toBe(next);
    }
  });

  it("正常系: 通常の相対パスは通る", async () => {
    const b = new Browser();
    const res = await loginRedirect(b, "/x/open-redirect/vuln/b", "/x/open-redirect/vuln/");
    expect(res.headers.get("location")).toBe("/x/open-redirect/vuln/");
  });
});

describe("オープンリダイレクト 修正版", () => {
  const tricky = [
    ...ATTACKS,
    "http://lab.test.evil.example/",
    "https://lab.test@evil.example/",
    "//lab.test@evil.example/",
    "/\\/evil.example/",
    "/\t/evil.example/",
    "/\n/evil.example/",
    "\\\\evil.example\\login",
    "/..//evil.example", // 正規化すると //evil.example になる
    "/a/..//evil.example/login",
    "javascript:alert(1)",
    "data:text/html,x",
    "http://lab.test/x/open-redirect/fixed/mypage", // 同じオリジンでも絶対URLは採用しない（相対パスだけ）
    "",
  ];

  it("攻撃失敗: どの入力も、ログイン後の転送先は既定のマイページに落ちる", async () => {
    const b = new Browser();
    for (const next of tricky) {
      const res = await loginRedirect(b, "/x/open-redirect/fixed", next);
      expect(res.status, next).toBe(303);
      expect(res.headers.get("location"), next).toBe(FIXED_HOME);
    }
  });

  it("攻撃失敗: /redirect?url= も同じ", async () => {
    const b = new Browser();
    for (const url of tricky) {
      const res = await b.get(`/x/open-redirect/fixed/redirect?url=${encodeURIComponent(url)}`);
      expect(res.status, url).toBe(302);
      expect(res.headers.get("location"), url).toBe(FIXED_HOME);
    }
  });

  it("どんな入力でも、Location をブラウザが解釈した先は必ず自分のオリジン", async () => {
    const b = new Browser();
    const inputs = [...tricky, "/%5Cevil.example", "/%2F/evil.example", "/a/../../evil.example", "/ /evil.example"];
    for (const next of inputs) {
      const res = await loginRedirect(b, "/x/open-redirect/fixed", next);
      const loc = res.headers.get("location")!;
      expect(new URL(loc, ORIGIN).origin, next).toBe(ORIGIN);
    }
  });

  it("正常系: 相対パス（クエリ・ハッシュ付き）はそのまま採用される", async () => {
    const b = new Browser();
    const res = await loginRedirect(b, "/x/open-redirect/fixed", "/x/open-redirect/fixed/mypage?tab=orders#top");
    expect(res.headers.get("location")).toBe("/x/open-redirect/fixed/mypage?tab=orders#top");
    const res2 = await b.get(`/x/open-redirect/fixed/redirect?url=${encodeURIComponent("/x/open-redirect/fixed/")}`);
    expect(res2.headers.get("location")).toBe("/x/open-redirect/fixed/");
  });

  it("許可リスト方式: 識別子で外部の行き先を選べ、リスト外は既定のページに戻る", async () => {
    const b = new Browser();
    const ok = await b.get("/x/open-redirect/fixed/go?site=partner");
    expect(ok.status).toBe(302);
    expect(ok.headers.get("location")).toBe("https://partner.example/");
    for (const site of ["https://evil.example/", "//evil.example/", "constructor", "__proto__", ""]) {
      const res = await b.get(`/x/open-redirect/fixed/go?site=${encodeURIComponent(site)}`);
      expect(res.headers.get("location"), site).toBe(FIXED_HOME);
    }
  });

  it("ログイン画面は、修正後の Location を表示する", async () => {
    const b = new Browser();
    const html = await b.text(`/x/open-redirect/fixed/login?next=${encodeURIComponent("//evil.example/login")}`);
    expect(html).toContain(`Location: ${FIXED_HOME}`);
    expect(html).toContain("このサイトの中");
  });
});

describe("オープンリダイレクト 転送先チェッカーと攻撃者ページ", () => {
  it("チェッカー: 脆弱版は (A)(B) を、修正版は修正後の Location を示す", async () => {
    const b = new Browser();
    const v = await b.text(`/x/open-redirect/vuln/inspect?value=${encodeURIComponent("//evil.example/login")}`);
    expect(v).toContain("脆弱版 (A) 検証なし");
    expect(v).toContain("脆弱版 (B) startsWith");
    expect(v).toContain("evil.example（別のサイト）");
    const f = await b.text(`/x/open-redirect/fixed/inspect?value=${encodeURIComponent("//evil.example/login")}`);
    expect(f).not.toContain("別のサイト");
    expect(f).toContain(FIXED_HOME);
  });

  it("攻撃者ページ: sandbox の CSP が付き、手口ごとの結果が出る。スクリプトは無い", async () => {
    const b = new Browser();
    const res = await b.get("/attacker/open-redirect/");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("sandbox");
    expect(csp).not.toContain("allow-same-origin");
    const html = await res.text();
    expect(html).not.toContain("<script");
    // 手口 × (A, B, 修正版) の表: B は // と /\ を通し、修正版はすべて内部に落ちる
    expect(html).toContain("<code>https://evil.example/login</code>");
    expect(html).toContain("<code>//evil.example/login</code>");
    expect(html).toContain("<code>/\\evil.example/login</code>");
    expect(html).toContain('class="ng">外部へ</span>');
    expect(html).toContain('class="ok">サイト内</span>');
    // 罠のリンクは、正規サイト（脆弱版）のログイン画面を指す
    expect(html).toContain("/x/open-redirect/vuln/login?next=https%3A%2F%2Fevil.example%2Flogin");
  });

  it("状態を持たない演習: どの学習者でも同じ結果で、Cookie は lab_id しか発行しない", async () => {
    const a = new Browser();
    const other = new Browser();
    const ra = await loginRedirect(a, "/x/open-redirect/vuln", "https://evil.example/login");
    const ro = await loginRedirect(other, "/x/open-redirect/vuln", "https://evil.example/login");
    expect(ra.headers.get("location")).toBe(ro.headers.get("location"));
    for (const r of [ra, ro]) {
      expect(r.headers.getSetCookie().every((c) => c.startsWith("lab_id="))).toBe(true);
    }
  });
});

describe("オープンリダイレクト 解説ページ", () => {
  it("原因のコード・修正の差分が表示され、[!] の行がハイライトされる", async () => {
    const html = await new Browser().text("/x/open-redirect");
    expect(html).toContain("オープンリダイレクト");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
