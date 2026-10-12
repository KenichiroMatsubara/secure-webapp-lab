import { describe, expect, it } from "vitest";
import { sha256Hex, verifyPassword } from "../src/lab/crypto";
import { COMMON_PASSWORDS } from "../src/lab/wordlist";
import { Browser } from "./helpers";
import { dbOf, locationOf } from "./pw-helpers";

const V = "/x/password-storage/vuln";
const F = "/x/password-storage/fixed";

type Stored = { username: string; stored: string };
const storedOf = (b: Browser, mode: "vuln" | "fixed") =>
  dbOf(b).all<Stored>("SELECT username, stored FROM password_storage_users WHERE mode = ? ORDER BY rowid", [mode]);

/** 修正版の初期ユーザーは PBKDF2 の負荷を分けて投入する。全員そろうまでページを開き直す */
async function openUntilSeeded(b: Browser, path: string): Promise<string> {
  for (let i = 0; i < 5; i++) {
    const html = await b.text(path);
    if (!html.includes("準備しています")) return html;
  }
  throw new Error("初期ユーザーの投入が終わらない");
}

describe("パスワードの保存: 脆弱版", () => {
  it("ソルトなしの SHA-256 で保存され、同じパスワードは同じ値になる", async () => {
    const b = new Browser();
    await b.get(`${V}/`);
    await b.post(`${V}/register`, { username: "tester1", password: "sunshine" });
    await b.post(`${V}/register`, { username: "tester2", password: "sunshine" });
    const rows = await storedOf(b, "vuln");
    const by = Object.fromEntries(rows.map((r) => [r.username, r.stored]));
    const expected = await sha256Hex("sunshine");
    expect(by.alice).toBe(expected);
    expect(by.dave).toBe(expected);
    expect(by.tester1).toBe(expected);
    expect(by.tester2).toBe(expected);
    // 旧システムから移行した平文のユーザー
    expect(by.legacy_user).toBe("welcome1");
  });

  it("DB 漏えいの模擬: stored がそのまま見え、同じ値のユーザーが指摘される", async () => {
    const b = new Browser();
    await b.get(`${V}/`);
    await b.post(`${V}/register`, { username: "tester1", password: "sunshine" });
    const html = await b.text(`${V}/dump`);
    expect(html).toContain(await sha256Hex("sunshine"));
    expect(html).toMatch(/alice[\s\S]*dave, tester1 と同じ値|dave[\s\S]*と同じ値/);
    expect(html).toContain("平文");
    expect(html).toContain("welcome1");
  });

  it("辞書攻撃: 事前計算表を引くだけで、辞書にあるパスワードが全員分判明する", async () => {
    const b = new Browser();
    await b.get(`${V}/`);
    await b.post(`${V}/register`, { username: "tester1", password: "qwerty123" });
    const html = await b.text(`${V}/crack`);
    expect(html).toContain("<td>sunshine</td>");
    expect(html).toContain("<td>Password1</td>");
    expect(html).toContain("<td>qwerty123</td>");
    expect(html).toContain("welcome1（平文なので、そのまま読める）");
    // 辞書にない長いパスフレーズは、この表では割り出せない
    expect(html).toMatch(/carol[\s\S]*?辞書にない/);
    expect(html).not.toContain("correct horse battery staple");
    expect(html).toMatch(/6 人中 5 人のパスワードが判明/);
  });

  it("パスワードの長さも質も検査しない（1 文字でも登録できる）", async () => {
    const b = new Browser();
    await b.get(`${V}/`);
    const res = await b.post(`${V}/register`, { username: "weak", password: "a" });
    expect(locationOf(res)).toBe(`${V}/?r=ok`);
  });
});

describe("パスワードの保存: 修正版", () => {
  it("初期ユーザーが PBKDF2（ソルト付き）で保存され、同じパスワードでも値が違う", async () => {
    const b = new Browser();
    await openUntilSeeded(b, `${F}/`);
    const rows = await storedOf(b, "fixed");
    const by = Object.fromEntries(rows.map((r) => [r.username, r.stored]));
    expect(Object.keys(by).sort()).toEqual(["alice", "bob", "carol", "dave"]);
    for (const s of Object.values(by)) expect(s).toMatch(/^pbkdf2\$1000\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
    expect(by.alice).not.toBe(by.dave);
    expect(await verifyPassword("sunshine", by.alice)).toBe(true);
    expect(await verifyPassword("sunshine", by.dave)).toBe(true);
    expect(await verifyPassword("Password1", by.bob)).toBe(true);
  });

  it("新規登録も、同じパスワードで別の値になる", async () => {
    const b = new Browser();
    await openUntilSeeded(b, `${F}/`);
    for (const u of ["tester1", "tester2"]) {
      const res = await b.post(`${F}/register`, { username: u, password: "violet-bicycle-2049" });
      expect(locationOf(res)).toBe(`${F}/?r=ok`);
    }
    const by = Object.fromEntries((await storedOf(b, "fixed")).map((r) => [r.username, r.stored]));
    expect(by.tester1).not.toBe(by.tester2);
    expect(await verifyPassword("violet-bicycle-2049", by.tester1)).toBe(true);
    expect(await verifyPassword("violet-bicycle-2049", by.tester2)).toBe(true);
  });

  it("事前計算表では逆引きできない（辞書の SHA-256 のどれとも一致しない）", async () => {
    const b = new Browser();
    await openUntilSeeded(b, `${F}/`);
    const table = new Set(await Promise.all(COMMON_PASSWORDS.map((w) => sha256Hex(w))));
    for (const r of await storedOf(b, "fixed")) {
      expect(table.has(r.stored)).toBe(false);
      expect(table.has(r.stored.split("$").pop()!)).toBe(false);
    }
  });

  it("辞書攻撃のページ: 表は使えず、1 ハッシュの実測とコストの見積もりが出る", async () => {
    const b = new Browser();
    await openUntilSeeded(b, `${F}/`);
    const html = await b.text(`${F}/crack`);
    expect(html).toContain("できない（ソルトが違うので");
    expect(html).toMatch(/実測は <strong>約 \d+(\.\d+)? ms<\/strong>/);
    expect(html).toContain("反復 600000 回");
    expect(html).toContain("辞書 150 語 × 4 ユーザー");
    expect(html).not.toContain("<td>sunshine</td>");
  });

  it("パスワードポリシー: 短い・よくあるパスワードは登録できない", async () => {
    const b = new Browser();
    await openUntilSeeded(b, `${F}/`);
    expect(locationOf(await b.post(`${F}/register`, { username: "x1", password: "short" }))).toBe(`${F}/?r=weak`);
    expect(locationOf(await b.post(`${F}/register`, { username: "x2", password: "sunshine" }))).toBe(`${F}/?r=common`);
    expect(locationOf(await b.post(`${F}/register`, { username: "x3", password: "Password123" }))).toBe(`${F}/?r=common`);
    expect(locationOf(await b.post(`${F}/register`, { username: "x4", password: "PASSWORD123" }))).toBe(`${F}/?r=common`);
    expect(locationOf(await b.post(`${F}/register`, { username: "alice", password: "violet-bicycle-2049" }))).toBe(`${F}/?r=dup`);
    expect(locationOf(await b.post(`${F}/register`, { username: "bad name!", password: "violet-bicycle-2049" }))).toBe(`${F}/?r=bad`);
  });

  it("パスワードを画面に再表示しない", async () => {
    const b = new Browser();
    await openUntilSeeded(b, `${F}/`);
    const secret = "very-secret-passphrase-777";
    const res = await b.post(`${F}/register`, { username: "tester9", password: secret });
    const follow = await b.text(locationOf(res));
    const dump = await b.text(`${F}/dump`);
    for (const html of [await res.text(), follow, dump]) expect(html).not.toContain(secret);
  });
});

describe("パスワードの保存: 共通", () => {
  it("脆弱版と修正版のユーザー表は別々", async () => {
    const b = new Browser();
    await b.get(`${V}/`);
    await openUntilSeeded(b, `${F}/`);
    await b.post(`${V}/register`, { username: "only_vuln", password: "abc" });
    expect(await b.text(`${V}/`)).toContain("only_vuln");
    expect(await b.text(`${F}/`)).not.toContain("only_vuln");
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await a.get(`${V}/`);
    await a.post(`${V}/register`, { username: "only_for_a", password: "abc" });
    expect(await a.text(`${V}/`)).toContain("only_for_a");
    expect(await other.text(`${V}/`)).not.toContain("only_for_a");
    expect(await other.text(`${V}/dump`)).not.toContain("only_for_a");
  });

  it("解説ページが表示され、[!] の行がハイライトされる", async () => {
    const b = new Browser();
    const html = await b.text("/x/password-storage");
    expect(html).toContain("パスワードの保存");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
  });
});
