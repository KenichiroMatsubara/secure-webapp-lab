import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

const base = (mode: "vuln" | "fixed") => `/x/header-injection/${mode}`;

describe("HTTPヘッダインジェクション: 脆弱版", () => {
  it("通常の言語設定: 生のレスポンスと解釈結果、Cookie が表示される", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/lang?lang=en`);
    expect(html).toContain("擬似環境です");
    expect(html).toContain("Set-Cookie: lang=en; Path=/");
    expect(html).toContain("<mark>␍␊</mark>");
    expect(html).toContain("想定どおり");
    expect(html).not.toContain("想定外");
    expect(html).toContain("本文は想定どおりです");
    // 模擬ブラウザの Cookie
    expect(html).toMatch(/<td>lang<\/td><td>en<\/td>/);
  });

  it("Set-Cookie を注入できる（%0d%0a）: 解析結果にヘッダーが増え、模擬ブラウザに sid が保存される", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/lang?lang=ja%0d%0aSet-Cookie:%20sid=attacker`);
    expect(html).toContain("想定外（注入された）");
    expect(html).toMatch(/<td>sid<\/td><td>attacker<\/td>/);
    expect(html).toMatch(/<td>lang<\/td><td>ja<\/td>/);
    expect(html).toContain("セッション固定化");
  });

  it("LF だけの注入（%0a）でも成立する", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/lang?lang=ja%0aSet-Cookie:%20sid=lf-only`);
    expect(html).toContain("想定外（注入された）");
    expect(html).toMatch(/<td>sid<\/td><td>lf-only<\/td>/);
    expect(html).toContain("<mark>␊</mark>");
  });

  it("空行の注入（%0d%0a%0d%0a）で本文を差し込める（レスポンス分割）", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/lang?lang=${encodeURIComponent("ja\r\n\r\n<h2>fake page</h2>")}`);
    expect(html).toContain("本文が本来のものと違います");
    // 差し込まれた本文はエスケープして表示され、プレビューは sandbox の iframe に入る
    expect(html).toContain("&lt;h2&gt;fake page&lt;/h2&gt;");
    expect(html).not.toContain("<h2>fake page</h2>");
    expect(html).toMatch(/<iframe sandbox[^>]*srcdoc="[^"]*&lt;h2&gt;fake page&lt;\/h2&gt;/);
    // 本来のヘッダー（Cache-Control）は本文側に回る
    const pre = html.slice(html.indexOf("<h3>本文</h3>"));
    expect(pre).toContain("Cache-Control: no-store");
  });

  it("リダイレクト先 (Location) にも注入できる", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/go?url=${encodeURIComponent("/mypage\r\nSet-Cookie: sid=attacker")}`);
    expect(html).toContain("HTTP/1.1 302 Found");
    expect(html).toContain("想定外（注入された）");
    expect(html).toMatch(/<td>sid<\/td><td>attacker<\/td>/);
    // 正規の Location は生きている
    expect(html).toContain("<code>/mypage</code> へ移動します");
    // Location を 2 本注入すると 2 本目が想定外になる
    const two = await b.text(`${base("vuln")}/go?url=${encodeURIComponent("/a\r\nLocation: https://evil.example/")}`);
    expect(two).toContain("想定外（注入された）");
  });

  it("入力欄に %0d%0a と書いても、ブラウザが %25 にして送るので改行にはならない", async () => {
    const b = new Browser();
    // フォーム送信の再現: % は %25 になる
    const html = await b.text(`${base("vuln")}/lang?lang=${encodeURIComponent("ja%0d%0aSet-Cookie: sid=x")}`);
    expect(html).not.toContain("想定外");
  });

  it("入力は画面にエスケープして出る（この演習の主題は XSS ではない）", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/go?url=${encodeURIComponent("<script>alert(1)</script>")}`);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});

describe("HTTPヘッダインジェクション: 修正版", () => {
  it("通常の言語設定とリダイレクトは動く（HttpOnly などの属性も付く）", async () => {
    const b = new Browser();
    const html = await b.text(`${base("fixed")}/lang?lang=en`);
    expect(html).toContain("Set-Cookie: lang=en; Path=/; HttpOnly; SameSite=Lax");
    expect(html).not.toContain("想定外");
    expect(html).toMatch(/<td>lang<\/td><td>en<\/td>/);
    const go = await b.text(`${base("fixed")}/go?url=/mypage`);
    expect(go).toContain("Location: /mypage");
    expect(go).not.toContain("想定外");
    const abs = await b.text(`${base("fixed")}/go?url=${encodeURIComponent("https://www.example.com/home")}`);
    expect(abs).toContain("Location: https://www.example.com/home");
  });

  it("脆弱版と同じ注入（CRLF / LF / 空行 / Location）はすべて 400 で拒否され、何も保存されない", async () => {
    const b = new Browser();
    const attacks: [string, string][] = [
      ["lang", "ja\r\nSet-Cookie: sid=attacker"],
      ["lang", "ja\nSet-Cookie: sid=attacker"],
      ["lang", "ja\rSet-Cookie: sid=attacker"],
      ["lang", "ja\r\n\r\n<h2>fake page</h2>"],
      ["lang", "ja\0"],
      ["go", "/mypage\r\nSet-Cookie: sid=attacker"],
      ["go", "/a\r\nLocation: https://evil.example/"],
    ];
    for (const [route, value] of attacks) {
      const param = route === "lang" ? "lang" : "url";
      const res = await b.get(`${base("fixed")}/${route}?${param}=${encodeURIComponent(value)}`);
      const html = await res.text();
      expect(res.status, JSON.stringify(value)).toBe(400);
      expect(html, JSON.stringify(value)).toContain("ヘッダーに使えない文字");
      expect(html, JSON.stringify(value)).not.toContain("HTTP/1.1");
    }
    const top = await b.text(`${base("fixed")}/`);
    expect(top).toContain("まだありません");
    expect(top).not.toContain("attacker");
  });

  it("lang は許可リストから選ぶ（未知の値は ja になる）", async () => {
    const b = new Browser();
    const html = await b.text(`${base("fixed")}/lang?lang=${encodeURIComponent("fr; Domain=example.com")}`);
    expect(html).toContain("Set-Cookie: lang=ja; Path=/");
    expect(html).not.toContain("Domain=example.com;");
    expect(html).toMatch(/<td>lang<\/td><td>ja<\/td>/);
  });

  it("リダイレクト先は、サイト内のパスか許可したホストだけ", async () => {
    const b = new Browser();
    for (const u of ["https://evil.example/", "//evil.example/", "/\\evil.example", "javascript:alert(1)", "http://example.com.evil.example/", "mypage"]) {
      const res = await b.get(`${base("fixed")}/go?url=${encodeURIComponent(u)}`);
      expect(res.status, u).toBe(400);
      expect(await res.text()).toContain("許可されていない");
    }
  });
});

describe("実際の Workers ではどうなる？", () => {
  it("本物の Headers / Response は改行を拒否する（TypeError）", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/runtime`);
    expect(html).toContain("TypeError");
    expect(html).toContain("new Headers().set(&quot;X-Test&quot;, &quot;a\\r\\nb&quot;)");
    expect(html).toContain("擬似ではなく");
    // 直接も確かめる
    expect(() => new Headers().set("X-Test", "a\r\nb")).toThrow(TypeError);
    // 修正版からも同じページが見える
    expect(await b.text(`${base("fixed")}/runtime`)).toContain("TypeError");
  });
});

describe("模擬ブラウザの Cookie・学習者ごとの分離", () => {
  it("Cookie を消せる。脆弱版と修正版の Cookie は混ざらない", async () => {
    const b = new Browser();
    await b.get(`${base("vuln")}/lang?lang=${encodeURIComponent("ja\r\nSet-Cookie: sid=attacker")}`);
    await b.get(`${base("fixed")}/lang?lang=en`);
    const fixedTop = await b.text(`${base("fixed")}/`);
    expect(fixedTop).not.toContain("attacker");
    const res = await b.post(`${base("vuln")}/jar-clear`);
    expect(res.status).toBe(303);
    expect(await b.text(`${base("vuln")}/`)).not.toContain("attacker");
    expect(await b.text(`${base("fixed")}/`)).toMatch(/<td>lang<\/td><td>en<\/td>/);
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await a.get(`${base("vuln")}/lang?lang=${encodeURIComponent("ja\r\nSet-Cookie: sid=only-for-a")}`);
    expect(await a.text(`${base("vuln")}/`)).toContain("only-for-a");
    expect(await other.text(`${base("vuln")}/`)).not.toContain("only-for-a");
  });
});

describe("解説ページ", () => {
  it("原因のコード・修正の差分が表示される", async () => {
    const b = new Browser();
    const html = await b.text("/x/header-injection");
    expect(html).toContain("HTTPヘッダインジェクション");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain("%0d%0aSet-Cookie:%20sid=attacker");
  });
});
