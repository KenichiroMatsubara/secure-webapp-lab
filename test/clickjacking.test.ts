import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

// 攻撃者ページの iframe（sandbox 継承）の中から送られるクリックは、Origin: null のクロスサイトのリクエストになる
const FROM_IFRAME = { "Sec-Fetch-Site": "cross-site", Origin: "null" };

async function state(b: Browser, mode: "vuln" | "fixed"): Promise<string | undefined> {
  return /id="state">([^<]*)</.exec(await b.text(`/x/clickjacking/${mode}/`))?.[1];
}

describe("クリックジャッキング 脆弱版", () => {
  it("埋め込みを拒否するヘッダーが無く、ガードも frame-ancestors を付けない（iframe に埋め込める）", async () => {
    const b = new Browser();
    const res = await b.get("/x/clickjacking/vuln/");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-frame-options")).toBeNull();
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).not.toContain("frame-ancestors");
    // 外部持ち出しのガードは引き続き効いている
    expect(csp).toContain("connect-src 'self'");
  });

  it("公開ボタンで公開状態が切り替わる", async () => {
    const b = new Browser();
    expect(await state(b, "vuln")).toBe("非公開");
    const res = await b.post("/x/clickjacking/vuln/toggle-public");
    expect(res.status).toBe(303);
    expect(await state(b, "vuln")).toBe("公開中");
    await b.post("/x/clickjacking/vuln/toggle-public");
    expect(await state(b, "vuln")).toBe("非公開");
  });

  it("攻撃成立: 攻撃者ページの iframe の中（Origin: null）からのクリックでも、学習者の公開状態が変わる", async () => {
    const b = new Browser();
    expect(await state(b, "vuln")).toBe("非公開");
    const res = await b.post("/x/clickjacking/vuln/toggle-public", {}, FROM_IFRAME);
    expect(res.status).toBe(303);
    expect(await state(b, "vuln")).toBe("公開中");
  });
});

describe("クリックジャッキング 修正版", () => {
  it("frame-ancestors 'none' と X-Frame-Options: DENY で埋め込みを拒否する", async () => {
    const b = new Browser();
    const res = await b.get("/x/clickjacking/fixed/");
    expect(res.status).toBe(200);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  it("操作後のリダイレクト（POST の応答）にも同じヘッダーが付く", async () => {
    const b = new Browser();
    const res = await b.post("/x/clickjacking/fixed/toggle-public");
    expect(res.status).toBe(303);
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
  });

  it("正常系: 直接開けば、これまでどおり操作できる。脆弱版とは状態が別", async () => {
    const b = new Browser();
    await b.post("/x/clickjacking/fixed/toggle-public");
    expect(await state(b, "fixed")).toBe("公開中");
    expect(await state(b, "vuln")).toBe("非公開");
  });
});

describe("クリックジャッキング 攻撃者ページ", () => {
  it("脆弱版を透明な iframe で重ね、おとりのボタンを同じ位置に置く。修正版に切り替えるリンクもある", async () => {
    const b = new Browser();
    const res = await b.get("/attacker/clickjacking/");
    const csp = res.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("sandbox");
    expect(csp).not.toContain("allow-same-origin");
    expect(csp).toContain("frame-src 'self'");
    const html = await res.text();
    expect(html).toContain('<iframe id="victim" name="victim" src="/x/clickjacking/vuln/"');
    expect(html).toContain('href="/x/clickjacking/fixed/" target="victim"');
    expect(html).toContain('type="range"'); // 透明度のスライダー
    expect(html).toContain("ここをクリックして景品をもらう");
    // おとりのボタンの位置 = iframe の高さ - 下の余白 - ボタンの高さ。設定ページの固定位置と一致している
    const page = await b.text("/x/clickjacking/vuln/");
    const fixedBtn = /\.cj-action\{position:fixed;left:(\d+)px;bottom:(\d+)px;width:(\d+)px;height:(\d+)px/.exec(page)!;
    const [, left, bottom, width, height] = fixedBtn.map(Number);
    const frameH = Number(/#victim\{[^}]*height:(\d+)px/.exec(html)![1]);
    const bait = /\.bait-btn\{position:absolute;left:(\d+)px;top:(\d+)px;width:(\d+)px;height:(\d+)px/.exec(html)!;
    expect(Number(bait[1])).toBe(left);
    expect(Number(bait[2])).toBe(frameH - bottom - height);
    expect(Number(bait[3])).toBe(width);
    expect(Number(bait[4])).toBe(height);
  });

  it("読み込んだだけでは何も送らない（自動クリック・自動送信のコードを含まない）", async () => {
    const b = new Browser();
    await b.get("/attacker/clickjacking/");
    const html = await b.text("/attacker/clickjacking/");
    expect(html).not.toMatch(/\.submit\s*\(/);
    expect(html).not.toMatch(/\.click\s*\(/);
    expect(html).not.toMatch(/onload\s*=/i);
    // 読み込んだだけでは、脆弱版の状態は変わらない
    expect(await state(b, "vuln")).toBe("非公開");
  });

  it("ラボ用の確認表に、現在の公開状態が出る", async () => {
    const b = new Browser();
    expect(await b.text("/attacker/clickjacking/")).toContain("<td>脆弱版</td><td>非公開</td>");
    await b.post("/x/clickjacking/vuln/toggle-public", {}, FROM_IFRAME);
    expect(await b.text("/attacker/clickjacking/")).toContain("<td>脆弱版</td><td>公開中</td>");
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await a.post("/x/clickjacking/vuln/toggle-public", {}, FROM_IFRAME);
    expect(await state(a, "vuln")).toBe("公開中");
    expect(await state(other, "vuln")).toBe("非公開");
    expect(await other.text("/attacker/clickjacking/")).toContain("<td>脆弱版</td><td>非公開</td>");
  });
});

describe("クリックジャッキング 解説ページ", () => {
  it("原因のコード・修正の差分が表示され、[!] の行がハイライトされる", async () => {
    const html = await new Browser().text("/x/clickjacking");
    expect(html).toContain("クリックジャッキング");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
