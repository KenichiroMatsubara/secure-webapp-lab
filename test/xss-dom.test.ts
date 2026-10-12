import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

/**
 * DOM Based XSS。サーバー側のテストでは、次の3つを確かめる。
 *  1. サーバーは URL に関係なく同じ HTML を返す（危険な値を出力していない）
 *  2. 脆弱版 / 修正版のブラウザ側コードが、配信されたとおりの文字列として期待する形をしている
 *  3. その配信されたコードを疑似DOMの上で実際に動かし、innerHTML / textContent / href に何が渡るかを見る
 * 実ブラウザでの動作（alert が出る・Trusted Types が効く）は手で確かめる。
 */

const ORIGIN = "http://lab.test";
const IMG = "<img src=x onerror=alert(document.domain)>";

interface FakeEnv {
  hash?: string;
  search?: string;
  origin?: string;
}

/** 要素への代入を記録する疑似要素 */
function fakeElement() {
  const writes: [string, string][] = [];
  const store: Record<string, unknown> = {};
  const el = new Proxy(store, {
    set(t, k, v) {
      writes.push([String(k), String(v)]);
      t[String(k)] = v;
      return true;
    },
  });
  return { el, writes, store };
}

/** 配信されたブラウザ側コードを、疑似の document / location / window の上で動かす */
function runClient(code: string, env: FakeEnv = {}) {
  const els = { greeting: fakeElement(), back: fakeElement(), note: fakeElement() };
  const location = { hash: env.hash ?? "", search: env.search ?? "", origin: env.origin ?? ORIGIN };
  const listeners: Record<string, () => void> = {};
  const document = { getElementById: (id: keyof typeof els) => els[id].el };
  const window = { addEventListener: (type: string, fn: () => void) => (listeners[type] = fn) };
  const run = new Function("document", "location", "window", `${code}\n;return typeof safeBackHref === "function" ? safeBackHref : null;`);
  const safeBackHref = run(document, location, window) as ((value: string, origin: string) => string | null) | null;
  const written = (id: keyof typeof els, prop: string) => els[id].writes.filter(([k]) => k === prop).map(([, v]) => v);
  return {
    els,
    location,
    listeners,
    safeBackHref,
    /** その要素の最後の書き込み */
    last: (id: keyof typeof els, prop: string) => written(id, prop).at(-1),
    sinks: (id: keyof typeof els) => els[id].writes.map(([k]) => k),
  };
}

async function inlineScriptOf(b: Browser): Promise<string> {
  const html = await b.text("/x/xss-dom/vuln/");
  const m = /<script>([\s\S]*?)<\/script>/.exec(html);
  expect(m, "脆弱版にインラインスクリプトがある").toBeTruthy();
  return m![1];
}

async function appJs(b: Browser): Promise<string> {
  const res = await b.get("/x/xss-dom/fixed/app.js");
  expect(res.status).toBe(200);
  return res.text();
}

describe("DOM Based XSS: 脆弱版のページ", () => {
  it("ページ内のインラインスクリプトが、location.hash を innerHTML に、?back= を href に渡している", async () => {
    const html = await new Browser().text("/x/xss-dom/vuln/");
    const script = /<script>([\s\S]*?)<\/script>/.exec(html)![1];
    expect(script).toContain("location.hash");
    expect(script).toContain(".innerHTML =");
    expect(script).toContain("location.search");
    expect(script).toContain('getElementById("back").href = backTo');
    expect(script).not.toContain("textContent");
  });

  it("サーバーは URL の値を一切出力しない（クエリの有無でHTMLが完全に同じ）", async () => {
    const b = new Browser();
    const plain = await b.text("/x/xss-dom/vuln/");
    const withQuery = await b.text(`/x/xss-dom/vuln/?back=${encodeURIComponent("javascript:alert(1)")}&TOKEN-ZZZ=1`);
    const withHash = await b.text(`/x/xss-dom/vuln/#${encodeURIComponent(IMG)}`);
    expect(withQuery).toBe(plain);
    expect(withHash).toBe(plain);
    expect(plain).not.toContain("TOKEN-ZZZ");
    expect(plain).not.toContain("onerror");
    expect(plain).not.toContain("javascript:");
  });

  it("サーバーが返すHTMLは、URLの値が入る余地のない固定の文面", async () => {
    const html = await new Browser().text("/x/xss-dom/vuln/");
    expect(html).toContain('<p id="greeting">読み込み中…</p>');
    expect(html).toContain('<a id="back" href="/">戻る</a>');
  });

  it("疑似DOM: ハッシュのHTMLがそのまま innerHTML に渡る（img onerror が要素になる）", async () => {
    const code = await inlineScriptOf(new Browser());
    const raw = runClient(code, { hash: "#" + IMG });
    expect(raw.last("greeting", "innerHTML")).toBe(`ようこそ、${IMG}さん`);
    expect(raw.sinks("greeting")).not.toContain("textContent");

    // ブラウザが <> を %3C %3E に変えて返しても、ページ側が decodeURIComponent で戻すので同じ
    const encoded = runClient(code, { hash: "#" + encodeURIComponent(IMG) });
    expect(encoded.last("greeting", "innerHTML")).toBe(`ようこそ、${IMG}さん`);
  });

  it("疑似DOM: ?back= の値が検証なしで href に入る（javascript: も、他サイトも）", async () => {
    const code = await inlineScriptOf(new Browser());
    for (const value of ["javascript:alert(1)", "https://evil.example/", "//evil.example/", "data:text/html,x"]) {
      const r = runClient(code, { search: `?back=${encodeURIComponent(value)}` });
      expect(r.last("back", "href"), value).toBe(value);
    }
  });

  it("疑似DOM: 通常の使い方（名前なし・back なし）も動く", async () => {
    const code = await inlineScriptOf(new Browser());
    const r = runClient(code);
    expect(r.last("greeting", "innerHTML")).toBe("ようこそ、ゲストさん");
    expect(r.last("back", "href")).toBe("/");
    const named = runClient(code, { hash: "#" + encodeURIComponent("たろう") });
    expect(named.last("greeting", "innerHTML")).toBe("ようこそ、たろうさん");
  });

  it("疑似DOM: ハッシュを書き換えると（hashchange）再描画される", async () => {
    const code = await inlineScriptOf(new Browser());
    const r = runClient(code, { hash: "#a" });
    expect(r.last("greeting", "innerHTML")).toBe("ようこそ、aさん");
    r.location.hash = "#" + IMG;
    r.listeners["hashchange"]();
    expect(r.last("greeting", "innerHTML")).toBe(`ようこそ、${IMG}さん`);
  });

  it("壊れた % エスケープでも例外で止まらない", async () => {
    const code = await inlineScriptOf(new Browser());
    expect(() => runClient(code, { hash: "#%E0%A4%A" })).not.toThrow();
  });

  it("Cookie は JS から読める（HttpOnly なし）", async () => {
    const res = await new Browser().get("/x/xss-dom/vuln/");
    const c = res.headers.getSetCookie().find((l) => l.startsWith("demo_secret="));
    expect(c).toBeTruthy();
    expect(c).not.toMatch(/HttpOnly/i);
  });

  it("脆弱版でも、外部への持ち出しはガードされる（インライン実行は許す）", async () => {
    const csp = (await new Browser().get("/x/xss-dom/vuln/")).headers.get("content-security-policy") ?? "";
    expect(csp).toContain("connect-src 'self'");
    expect(csp).toContain("img-src 'self' data:");
    expect(csp).toContain("'unsafe-inline'");
  });
});

describe("DOM Based XSS: 修正版のページ", () => {
  it("インラインスクリプト・インラインのイベントハンドラ・style属性が一つもない", async () => {
    const html = await new Browser().text("/x/xss-dom/fixed/");
    // src を持たない <script> がない
    const scripts = html.match(/<script\b[^>]*>/gi) ?? [];
    expect(scripts).toEqual(['<script src="/x/xss-dom/fixed/app.js" defer>']);
    expect(html).not.toMatch(/<script[^>]*>\s*(?!<\/script>)\S/); // 中身のあるスクリプトがない
    expect(html).not.toMatch(/\son[a-z]+\s*=/i); // onclick= などの属性
    expect(html).not.toMatch(/\sstyle\s*=/i);
    expect(html).not.toContain("javascript:");
    expect(html).not.toContain("innerHTML");
  });

  it("サーバーが返すHTMLは脆弱版と同じ本文で、URLの値は入らない", async () => {
    const b = new Browser();
    const plain = await b.text("/x/xss-dom/fixed/");
    const withQuery = await b.text(`/x/xss-dom/fixed/?back=${encodeURIComponent("javascript:alert(1)")}&TOKEN-ZZZ=1`);
    expect(withQuery).toBe(plain);
    expect(plain).not.toContain("TOKEN-ZZZ");
    const vulnHtml = await b.text("/x/xss-dom/vuln/");
    for (const part of ['<p id="greeting">読み込み中…</p>', '<a id="back" href="/">戻る</a>', '<p id="note" class="ng"></p>']) {
      expect(plain).toContain(part);
      expect(vulnHtml).toContain(part);
    }
  });

  it("CSP: インラインスクリプト禁止と Trusted Types の要求が付く", async () => {
    const res = await new Browser().get("/x/xss-dom/fixed/");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("require-trusted-types-for 'script'");
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/);
    expect(csp).not.toContain("unsafe-eval");
  });

  it("app.js は同一オリジンの外部ファイルとして、text/javascript; charset=UTF-8 で配信される", async () => {
    const res = await new Browser().get("/x/xss-dom/fixed/app.js");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/javascript; charset=UTF-8");
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("content-security-policy")).toContain("script-src 'self'");
  });

  it("app.js は textContent を使い、innerHTML などの危険な出力先を使わない", async () => {
    const js = await appJs(new Browser());
    expect(js).toContain(".textContent =");
    expect(js).toContain("new URL(value, origin)");
    for (const sink of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setTimeout("]) {
      expect(js, sink).not.toContain(sink);
    }
  });

  it("疑似DOM: ハッシュの img タグは textContent に文字のまま入り、innerHTML には何も入らない", async () => {
    const js = await appJs(new Browser());
    const r = runClient(js, { hash: "#" + IMG });
    expect(r.last("greeting", "textContent")).toBe(`ようこそ、${IMG}さん`);
    expect(r.sinks("greeting")).not.toContain("innerHTML");
    expect(r.sinks("back")).not.toContain("innerHTML");
    expect(r.sinks("note")).not.toContain("innerHTML");

    const encoded = runClient(js, { hash: "#" + encodeURIComponent(IMG) });
    expect(encoded.last("greeting", "textContent")).toBe(`ようこそ、${IMG}さん`);
  });

  it("疑似DOM: ハッシュを書き換えても（hashchange）textContent で再描画される", async () => {
    const js = await appJs(new Browser());
    const r = runClient(js, { hash: "#a" });
    r.location.hash = "#" + IMG;
    r.listeners["hashchange"]();
    expect(r.last("greeting", "textContent")).toBe(`ようこそ、${IMG}さん`);
    expect(r.sinks("greeting")).not.toContain("innerHTML");
  });

  it("疑似DOM: 危険な ?back= は「/」に置き換わり、メッセージが出る", async () => {
    const js = await appJs(new Browser());
    for (const value of [
      "javascript:alert(1)",
      "JaVaScRiPt:alert(1)",
      " javascript:alert(1)",
      "java\tscript:alert(1)",
      "https://evil.example/",
      "//evil.example/",
      "\\\\evil.example",
      "data:text/html,<script>alert(1)</script>",
    ]) {
      const r = runClient(js, { search: `?back=${encodeURIComponent(value)}` });
      expect(r.last("back", "href"), value).toBe("/");
      expect(r.last("note", "textContent"), value).toContain("戻り先が不正");
    }
  });

  it("疑似DOM: 同じオリジンの戻り先は使え、メッセージは出ない", async () => {
    const js = await appJs(new Browser());
    const rel = runClient(js, { search: `?back=${encodeURIComponent("/x/xss-dom/fixed/?x=1")}` });
    expect(rel.last("back", "href")).toBe(`${ORIGIN}/x/xss-dom/fixed/?x=1`);
    expect(rel.last("note", "textContent")).toBe("");

    const abs = runClient(js, { search: `?back=${encodeURIComponent(`${ORIGIN}/about`)}` });
    expect(abs.last("back", "href")).toBe(`${ORIGIN}/about`);

    const none = runClient(js);
    expect(none.last("back", "href")).toBe(`${ORIGIN}/`);
    expect(none.last("note", "textContent")).toBe("");
    expect(none.last("greeting", "textContent")).toBe("ようこそ、ゲストさん");
  });

  it("Cookie は HttpOnly", async () => {
    const res = await new Browser().get("/x/xss-dom/fixed/");
    expect(res.headers.getSetCookie().find((l) => l.startsWith("demo_secret="))).toMatch(/HttpOnly/i);
  });
});

describe("safeBackHref（配信される app.js の判定関数）", () => {
  async function load() {
    const js = await appJs(new Browser());
    const r = runClient(js);
    expect(r.safeBackHref, "app.js が safeBackHref を定義している").toBeTypeOf("function");
    return r.safeBackHref!;
  }

  it("同一オリジンの http / https だけを通す", async () => {
    const f = await load();
    const origin = "https://lab.example";
    expect(f("/", origin)).toBe("https://lab.example/");
    expect(f("/x/a?b=1#c", origin)).toBe("https://lab.example/x/a?b=1#c");
    expect(f("about", origin)).toBe("https://lab.example/about");
    expect(f("https://lab.example/p", origin)).toBe("https://lab.example/p");
    expect(f("?only=query", origin)).toBe("https://lab.example/?only=query");
  });

  it("javascript: / data: / vbscript: / file: / blob: は、大文字小文字や空白を混ぜても通さない", async () => {
    const f = await load();
    const origin = "https://lab.example";
    for (const v of [
      "javascript:alert(1)",
      "JAVASCRIPT:alert(1)",
      "  javascript:alert(1)",
      "java\nscript:alert(1)",
      "\tjavascript:alert(1)",
      "data:text/html,x",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
      "blob:https://lab.example/uuid",
    ]) {
      expect(f(v, origin), JSON.stringify(v)).toBeNull();
    }
  });

  it("別オリジンは通さない（スキーム違い・ポート違い・サブドメイン・ユーザー情報の偽装を含む）", async () => {
    const f = await load();
    const origin = "https://lab.example";
    for (const v of [
      "https://evil.example/",
      "//evil.example/",
      "///evil.example/",
      "\\\\evil.example",
      "/\\evil.example",
      "http://lab.example/",
      "https://lab.example:8443/",
      "https://sub.lab.example/",
      "https://lab.example.evil.example/",
      "https://lab.example@evil.example/",
    ]) {
      expect(f(v, origin), JSON.stringify(v)).toBeNull();
    }
  });

  it("解析できない値は例外にせず null を返す", async () => {
    const f = await load();
    expect(f("http://", "https://lab.example")).toBeNull();
    expect(f("https://lab.example/", "not an origin")).toBeNull();
  });
});

describe("DOM Based XSS: 共通", () => {
  it("サーバーに学習者ごとの状態がない（別のブラウザにも同じHTMLを返す）", async () => {
    const a = new Browser();
    const other = new Browser();
    for (const mode of ["vuln", "fixed"]) {
      expect(await a.text(`/x/xss-dom/${mode}/`)).toBe(await other.text(`/x/xss-dom/${mode}/`));
    }
  });
});

describe("解説ページ", () => {
  it("原因のコード・修正の差分が表示され、[!] の行がハイライトされる", async () => {
    const html = await new Browser().text("/x/xss-dom");
    expect(html).toContain("DOM Based XSS");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
    // 原因のコードに、問題の2行（innerHTML と href への代入）が載っている
    expect(html).toContain("innerHTML");
    expect(html).toContain("require-trusted-types-for");
  });
});
