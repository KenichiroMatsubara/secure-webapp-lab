import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

type Mode = "vuln" | "fixed";

// 攻撃者ページ（sandbox で別オリジン扱い）から送られた POST を模す
const CROSS_SITE = { "Sec-Fetch-Site": "cross-site", Origin: "null" };

async function login(b: Browser, mode: Mode) {
  return b.post(`/x/csrf/${mode}/login`, { username: "alice", password: "alice-pass" });
}

async function myPage(b: Browser, mode: Mode): Promise<string> {
  return b.text(`/x/csrf/${mode}/`);
}

async function currentEmail(b: Browser, mode: Mode): Promise<string | undefined> {
  return /id="current-email">([^<]*)</.exec(await myPage(b, mode))?.[1];
}

function tokenIn(html: string): string | undefined {
  return /name="csrf_token" value="([0-9a-f]*)"/.exec(html)?.[1];
}

describe("CSRF 脆弱版", () => {
  it("ログインでき、マイページにメールアドレスが出る", async () => {
    const b = new Browser();
    expect(await myPage(b, "vuln")).toContain("会員サイト（ログイン）");
    const res = await login(b, "vuln");
    expect(res.status).toBe(303);
    expect(await currentEmail(b, "vuln")).toBe("alice@example.com");
  });

  it("パスワードが違えばログインできない", async () => {
    const b = new Browser();
    const res = await b.post("/x/csrf/vuln/login", { username: "alice", password: "wrong" });
    expect(res.status).toBe(401);
    expect(await myPage(b, "vuln")).toContain("会員サイト（ログイン）");
  });

  it("攻撃成立: クロスサイト（Origin: null）の POST でも、Cookie が付いていればメールアドレスが書き換わる", async () => {
    const b = new Browser();
    await login(b, "vuln");
    const res = await b.post("/x/csrf/vuln/change-email", { email: "attacker@evil.example" }, CROSS_SITE);
    expect(res.status).toBe(303);
    expect(await currentEmail(b, "vuln")).toBe("attacker@evil.example");
  });

  it("攻撃者ページのフォームの内容をそのまま送ると、攻撃が成立する", async () => {
    const b = new Browser();
    await login(b, "vuln");
    const page = await b.text("/attacker/csrf/");
    const m = /<form method="post" action="(\/x\/csrf\/vuln\/change-email)">\s*<input type="hidden" name="email" value="([^"]+)">/.exec(
      page,
    );
    expect(m).not.toBeNull();
    await b.post(m![1], { email: m![2] }, CROSS_SITE);
    expect(await currentEmail(b, "vuln")).toBe("attacker@evil.example");
  });

  it("Cookie が付かない（SameSite が効いた）場合は、未ログイン扱いで変更されない", async () => {
    const b = new Browser();
    await login(b, "vuln");
    const onlyLab = { Cookie: `lab_id=${b.cookie("lab_id")}` };
    const res = await b.post("/x/csrf/vuln/change-email", { email: "attacker@evil.example" }, { ...CROSS_SITE, ...onlyLab });
    expect(res.status).toBe(401);
    expect(await currentEmail(b, "vuln")).toBe("alice@example.com");
  });

  it("Cookie: https では SameSite=None; Secure; HttpOnly", async () => {
    const b = new Browser("https://lab.test");
    const res = await login(b, "vuln");
    const line = res.headers.getSetCookie().find((c) => c.startsWith("csrf_vuln_sid="))!;
    expect(line).toMatch(/SameSite=None/i);
    expect(line).toMatch(/;\s*Secure/i);
    expect(line).toMatch(/HttpOnly/i);
  });

  it("Cookie: クロスサイト用の Cookie が使えない環境では Lax にフォールバックし、画面に注意書きが出る", async () => {
    const b = new Browser("http://lab.test");
    const res = await login(b, "vuln");
    const line = res.headers.getSetCookie().find((c) => c.startsWith("csrf_vuln_sid="))!;
    expect(line).toMatch(/SameSite=Lax/i);
    expect(line).not.toMatch(/;\s*Secure/i);
    expect(await myPage(b, "vuln")).toContain("この環境ではクロスサイトの再現ができません");
    // localhost なら SameSite=None が使える
    const local = new Browser("http://localhost:8787");
    const res2 = await login(local, "vuln");
    expect(res2.headers.getSetCookie().find((c) => c.startsWith("csrf_vuln_sid="))).toMatch(/SameSite=None/i);
  });

  it("ログアウトでセッションが消える", async () => {
    const b = new Browser();
    await login(b, "vuln");
    await b.post("/x/csrf/vuln/logout");
    expect(await myPage(b, "vuln")).toContain("会員サイト（ログイン）");
  });
});

describe("CSRF 修正版", () => {
  it("フォームに CSRF トークン（128bit 以上の乱数）が埋め込まれ、ログインのたびに変わる", async () => {
    const a = new Browser();
    await login(a, "fixed");
    const t1 = tokenIn(await myPage(a, "fixed"));
    expect(t1).toMatch(/^[0-9a-f]{32,}$/);
    const other = new Browser();
    await login(other, "fixed");
    expect(tokenIn(await myPage(other, "fixed"))).not.toBe(t1);
  });

  it("攻撃失敗: クロスサイト（Origin: null）の POST は、Cookie が付いていても 403 で、メールアドレスは変わらない", async () => {
    const b = new Browser();
    await login(b, "fixed");
    const res = await b.post("/x/csrf/fixed/change-email", { email: "attacker@evil.example" }, CROSS_SITE);
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("Origin");
    expect(await currentEmail(b, "fixed")).toBe("alice@example.com");
  });

  it("攻撃失敗: Cookie が付かない場合も、拒否され、メールアドレスは変わらない（Cookie が無かったことが画面に出る）", async () => {
    const b = new Browser();
    await login(b, "fixed");
    const onlyLab = { Cookie: `lab_id=${b.cookie("lab_id")}` };
    const res = await b.post("/x/csrf/fixed/change-email", { email: "attacker@evil.example" }, { ...CROSS_SITE, ...onlyLab });
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("Cookie が付いていませんでした");
    expect(await currentEmail(b, "fixed")).toBe("alice@example.com");
  });

  it("トークンが無い、または違う場合は 403（同一オリジンからでも）", async () => {
    const b = new Browser();
    await login(b, "fixed");
    const none = await b.post("/x/csrf/fixed/change-email", { email: "x@example.com" });
    expect(none.status).toBe(403);
    const wrong = await b.post("/x/csrf/fixed/change-email", { email: "x@example.com", csrf_token: "0".repeat(64) });
    expect(wrong.status).toBe(403);
    const empty = await b.post("/x/csrf/fixed/change-email", { email: "x@example.com", csrf_token: "" });
    expect(empty.status).toBe(403);
    expect(await currentEmail(b, "fixed")).toBe("alice@example.com");
  });

  it("別のセッションのトークンは使えない", async () => {
    const a = new Browser();
    const other = new Browser();
    await login(a, "fixed");
    await login(other, "fixed");
    const tokenOfOther = tokenIn(await myPage(other, "fixed"))!;
    const res = await a.post("/x/csrf/fixed/change-email", { email: "x@example.com", csrf_token: tokenOfOther });
    expect(res.status).toBe(403);
  });

  it("トークンが漏れても、Origin が他サイトなら 403（2枚目の壁）", async () => {
    const b = new Browser();
    await login(b, "fixed");
    const token = tokenIn(await myPage(b, "fixed"))!;
    for (const origin of ["null", "https://evil.example", "http://lab.test.evil.example"]) {
      const res = await b.post("/x/csrf/fixed/change-email", { email: "attacker@evil.example", csrf_token: token }, { ...CROSS_SITE, Origin: origin });
      expect(res.status).toBe(403);
    }
    expect(await currentEmail(b, "fixed")).toBe("alice@example.com");
  });

  it("正常系: 同じオリジンの正規フォーム（トークン付き）からは変更できる", async () => {
    const b = new Browser();
    await login(b, "fixed");
    const token = tokenIn(await myPage(b, "fixed"))!;
    const res = await b.post("/x/csrf/fixed/change-email", { email: "bob@example.com", csrf_token: token }, { Origin: "http://lab.test" });
    expect(res.status).toBe(303);
    expect(await currentEmail(b, "fixed")).toBe("bob@example.com");
    // Origin ヘッダーが付かない古いブラウザでも、トークンが正しければ通る
    const res2 = await b.post("/x/csrf/fixed/change-email", { email: "carol@example.com", csrf_token: token });
    expect(res2.status).toBe(303);
    expect(await currentEmail(b, "fixed")).toBe("carol@example.com");
  });

  it("不正な形式のメールアドレスは 400", async () => {
    const b = new Browser();
    await login(b, "fixed");
    const token = tokenIn(await myPage(b, "fixed"))!;
    const res = await b.post("/x/csrf/fixed/change-email", { email: "not-an-email", csrf_token: token });
    expect(res.status).toBe(400);
  });

  it("Cookie は HttpOnly; SameSite=Lax（SameSite=None ではない）", async () => {
    const b = new Browser("https://lab.test");
    const res = await login(b, "fixed");
    const line = res.headers.getSetCookie().find((c) => c.startsWith("csrf_fixed_sid="))!;
    expect(line).toMatch(/HttpOnly/i);
    expect(line).toMatch(/SameSite=Lax/i);
    expect(line).not.toMatch(/SameSite=None/i);
  });

  it("脆弱版のセッション Cookie は修正版では使えない（逆も同じ）", async () => {
    const b = new Browser();
    await login(b, "vuln");
    const sid = b.cookie("csrf_vuln_sid")!;
    const res = await b.get("/x/csrf/fixed/", { Cookie: `lab_id=${b.cookie("lab_id")}; csrf_fixed_sid=${sid}` });
    expect(await res.text()).toContain("会員サイト（ログイン）");
  });

  it("ログアウトでセッションが消える（ログアウトも Origin 検証の対象）", async () => {
    const b = new Browser();
    await login(b, "fixed");
    const blocked = await b.post("/x/csrf/fixed/logout", {}, CROSS_SITE);
    expect(blocked.status).toBe(403);
    expect(await currentEmail(b, "fixed")).toBe("alice@example.com");
    await b.post("/x/csrf/fixed/logout");
    expect(await myPage(b, "fixed")).toContain("会員サイト（ログイン）");
  });
});

describe("CSRF 攻撃者ページ", () => {
  it("sandbox の CSP（allow-same-origin なし）が付き、自動送信するスクリプトを含まない", async () => {
    const b = new Browser();
    const res = await b.get("/attacker/csrf/");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("sandbox");
    expect(csp).not.toContain("allow-same-origin");
    const html = await res.text();
    expect(html).not.toContain("<script");
    expect(html).not.toMatch(/\.submit\s*\(/);
    expect(html).not.toMatch(/onload\s*=/i);
    expect(html).toContain('action="/x/csrf/vuln/change-email"');
    expect(html).toContain('action="/x/csrf/fixed/change-email"');
  });

  it("学習者ごとにデータが分かれる（片方の攻撃は、別の学習者には影響しない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await login(a, "vuln");
    await login(other, "vuln");
    await a.post("/x/csrf/vuln/change-email", { email: "attacker@evil.example" }, CROSS_SITE);
    expect(await currentEmail(a, "vuln")).toBe("attacker@evil.example");
    expect(await currentEmail(other, "vuln")).toBe("alice@example.com");
    expect(await other.text("/attacker/csrf/")).not.toContain("attacker@evil.example</td>");
  });
});

describe("CSRF 解説ページ", () => {
  it("原因のコード・修正の差分が表示され、[!] の行がハイライトされる", async () => {
    const html = await new Browser().text("/x/csrf");
    expect(html).toContain("CSRF");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
