import { describe, expect, it, vi } from "vitest";
import { Browser } from "./helpers";

const enc = encodeURIComponent;
const books = (mode: "vuln" | "fixed", category: string, sort?: string) =>
  `/x/sqli/${mode}/books?category=${enc(category)}${sort === undefined ? "" : `&sort=${enc(sort)}`}`;
const book = (mode: "vuln" | "fixed", id: string) => `/x/sqli/${mode}/book?id=${enc(id)}`;
const login = (b: Browser, mode: "vuln" | "fixed", username: string, password: string) =>
  b.post(`/x/sqli/${mode}/login`, { username, password }).then((r) => r.text());

// 攻撃ペイロード（解説の手順と同じもの）
const UNION_USERS = "' UNION SELECT id,username,password,role,0,'' FROM sqli_users--";
const UNION_MASTER = "' UNION SELECT 1,name,sql,type,0,'' FROM sqlite_master--";
const UNION_NOTES = "' UNION SELECT id,title,internal_note,category,price,'' FROM sqli_books--";
const NUM_UNION = "0 UNION SELECT id,username,password,role,0,'' FROM sqli_users";
const BLIND_TRUE =
  "CASE WHEN (SELECT substr(password,1,1) FROM sqli_users WHERE username='admin')='a' THEN price ELSE title END";
const BLIND_FALSE = BLIND_TRUE.replace("='a'", "='z'");
const DROP_BOOKS = "'; DROP TABLE sqli_books--";
const DROP_BOOKS_SEMI = "'; DROP TABLE sqli_books;--"; // 末尾の ; と -- を付けた形でも防げること
const UPDATE_PRICES = "id; UPDATE sqli_books SET price = 1";

const CATEGORY_ATTACKS = [
  "'",
  "' OR '1'='1",
  "' OR 1=1--",
  "' ORDER BY 7--",
  UNION_USERS,
  UNION_MASTER,
  UNION_NOTES,
  DROP_BOOKS,
  DROP_BOOKS_SEMI,
  "'; UPDATE sqli_books SET price = 1--",
];
const SORT_ATTACKS = [BLIND_TRUE, BLIND_FALSE, "(SELECT 1 FROM no_such_table)", "price; DROP TABLE sqli_books", UPDATE_PRICES, "constructor", "__proto__", "1,2,3"];
const ID_ATTACKS = ["1 OR 1=1", NUM_UNION, "1; DROP TABLE sqli_books", "-1", "1.5", "", "abc", "99999999999999"];

/** 漏えいした値（どれかが出たら、攻撃が成立している） */
const LEAKS = ["admin-pass-2024", "taro-pw", "hanako-pw", "原価", "CREATE TABLE"];

describe("SQLインジェクション: 脆弱版", () => {
  it("通常の検索ができ、実行された SQL が画面に出る", async () => {
    const html = await new Browser().text(books("vuln", "programming"));
    expect(html).toContain("Webアプリ入門ノート");
    expect(html).not.toContain("月曜日の図書室");
    expect(html).toContain("category = &#39;programming&#39; ORDER BY id");
  });

  it("引用符1文字でSQLが壊れ、DBのエラー文がそのまま出る（ステータスは 200）", async () => {
    const res = await new Browser().get(books("vuln", "'"));
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("unrecognized token");
    expect(html).toContain("SQLITE_ERROR");
  });

  it("' OR '1'='1 で、カテゴリに関係なく全件が出る", async () => {
    const html = await new Browser().text(books("vuln", "' OR '1'='1"));
    for (const t of ["Webアプリ入門ノート", "守りのWeb設計", "月曜日の図書室", "十五分でできる夕食"]) {
      expect(html).toContain(t);
    }
    expect(html).toContain("10 件");
  });

  it("ログイン回避: admin'-- でパスワードを知らなくても admin になる", async () => {
    const b = new Browser();
    const html = await login(b, "vuln", "admin'--", "wrong-password");
    expect(html).toContain("ログイン成功: admin（admin）");
  });

  it("ログイン回避: パスワード欄の ' OR '1'='1 でも通る。正規のログイン・間違ったログインは普通に動く", async () => {
    const b = new Browser();
    expect(await login(b, "vuln", "nobody", "' OR '1'='1")).toContain("ログイン成功");
    expect(await login(b, "vuln", "taro", "taro-pw")).toContain("ログイン成功: taro（user）");
    expect(await login(b, "vuln", "taro", "wrong")).toContain("ログイン失敗");
  });

  it("ログインのエラー文もそのまま出る", async () => {
    const html = await login(new Browser(), "vuln", "'", "x");
    expect(html).toContain("SQLITE_ERROR");
  });

  it("ORDER BY n で列数が分かる（6 は通り、7 はエラーで列数が漏れる）", async () => {
    const b = new Browser();
    const ok = await b.text(books("vuln", "' ORDER BY 6--"));
    expect(ok).not.toContain("SQLITE_ERROR");
    const ng = await b.text(books("vuln", "' ORDER BY 7--"));
    expect(ng).toContain("out of range");
    expect(ng).toContain("between 1 and 6");
  });

  it("UNION で別の表（ユーザー表）のパスワードが盗める", async () => {
    const html = await new Browser().text(books("vuln", UNION_USERS));
    expect(html).toContain("admin-pass-2024");
    expect(html).toContain("taro-pw");
  });

  it("sqlite_master から表名と定義を列挙できる", async () => {
    const html = await new Browser().text(books("vuln", UNION_MASTER));
    expect(html).toContain("sqli_users");
    expect(html).toContain("CREATE TABLE sqli_books");
  });

  it("非公開メモ（原価）が、画面に出ていない列から漏れる", async () => {
    const normal = await new Browser().text(books("vuln", "programming"));
    expect(normal).not.toContain("原価");
    const html = await new Browser().text(books("vuln", UNION_NOTES));
    expect(html).toContain("原価 1,100円");
  });

  it("数値コンテキスト: 引用符なしで全件・UNION が成立する", async () => {
    const b = new Browser();
    const all = await b.text(book("vuln", "1 OR 1=1"));
    expect(all).toContain("10 件");
    const union = await b.text(book("vuln", NUM_UNION));
    expect(union).toContain("admin-pass-2024");
  });

  it("ORDER BY への注入: 条件の真偽で並び順が変わる（ブラインド）／サブクエリのエラーで表名が出る", async () => {
    const b = new Browser();
    const pos = (html: string, t: string) => html.indexOf(t);
    const t = await b.text(books("vuln", "security", BLIND_TRUE)); // 真: 価格順
    const f = await b.text(books("vuln", "security", BLIND_FALSE)); // 偽: タイトル順
    expect(pos(t, "攻撃者の視点を学ぶ")).toBeLessThan(pos(t, "守りのWeb設計"));
    expect(pos(f, "守りのWeb設計")).toBeLessThan(pos(f, "攻撃者の視点を学ぶ"));
    const err = await b.text(books("vuln", "security", "(SELECT 1 FROM no_such_table)"));
    expect(err).toContain("no such table: no_such_table");
  });

  it("複数の文を実行できる: DROP TABLE で書籍表が消え、リセットで戻る", async () => {
    const b = new Browser();
    await b.get(books("vuln", DROP_BOOKS));
    const after = await b.text(books("vuln", "programming"));
    expect(after).toContain("no such table: sqli_books");
    // 壊れたあとの案内が出ている
    expect(after).toContain("データをリセットする");
    // リセットで元に戻る
    const reset = await b.post("/lab/reset");
    expect(reset.status).toBe(303);
    expect(await b.text(books("vuln", "programming"))).toContain("Webアプリ入門ノート");
  });

  it("ORDER BY の後ろからも文を足せる（引用符もコメントも不要）: 全商品の価格を書き換えられる", async () => {
    const b = new Browser();
    expect(await b.text(books("vuln", "programming"))).toContain("<td>2200</td>");
    await b.get(books("vuln", "programming", UPDATE_PRICES));
    const after = await b.text(books("vuln", "programming"));
    expect(after).not.toContain("<td>2200</td>");
    expect(after).toContain("<td>1</td></tr>");
  });

  it("先の SELECT が行を返していると DROP TABLE は locked で失敗する（UPDATE は通る）", async () => {
    const b = new Browser();
    const html = await b.text(books("vuln", "programming", "id; DROP TABLE sqli_books"));
    expect(html).toContain("database table is locked");
    expect(await b.text(books("vuln", "programming"))).toContain("Webアプリ入門ノート");
  });

  it("末尾に ;-- を付けると、DROP は実行されるがコメントだけの文でエラーが出る", async () => {
    const b = new Browser();
    const html = await b.text(books("vuln", DROP_BOOKS_SEMI));
    expect(html).toContain("did not contain a statement");
    expect(await b.text(books("vuln", "programming"))).toContain("no such table: sqli_books");
  });

  it("結果の表示は常にエスケープされる（この演習は XSS ではない）", async () => {
    const html = await new Browser().text(books("vuln", "' UNION SELECT 1,'<script>alert(1)</script>','x','y',0,''--"));
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});

describe("SQLインジェクション: 修正版", () => {
  it("正常系: カテゴリ検索・並べ替え・詳細・ログインが動く", async () => {
    const b = new Browser();
    const list = await b.text(books("fixed", "programming"));
    expect(list).toContain("Webアプリ入門ノート");
    expect(list).toContain("3 件");
    expect(list).not.toContain("月曜日の図書室");
    // SQL（プレースホルダ形式）とバインド値が分かれて見える
    expect(list).toContain("WHERE category = ? ORDER BY id");
    expect(list).toContain("バインド値");

    const byPrice = await b.text(books("fixed", "security", "price"));
    expect(byPrice).toContain("ORDER BY price");
    expect(byPrice.indexOf("ログと監査の基本")).toBeLessThan(byPrice.indexOf("守りのWeb設計"));

    expect(await b.text(book("fixed", "1"))).toContain("Webアプリ入門ノート");
    expect(await login(b, "fixed", "taro", "taro-pw")).toContain("ログイン成功: taro（user）");
    expect(await login(b, "fixed", "taro", "wrong")).toContain("ログイン失敗");
  });

  it("カテゴリの攻撃文字列はすべて、ただの文字列として比較されるだけ（漏えいもエラーもない）", async () => {
    const b = new Browser();
    for (const p of CATEGORY_ATTACKS) {
      const res = await b.get(books("fixed", p));
      expect(res.status, p).toBe(200);
      const html = await res.text();
      expect(html, p).toContain("該当する書籍はありません");
      expect(html, p).not.toContain("SQLITE_ERROR");
      for (const leak of LEAKS) expect(html, `${p} → ${leak}`).not.toContain(leak);
    }
    // 攻撃のあとも書籍表は無事
    expect(await b.text(books("fixed", "programming"))).toContain("Webアプリ入門ノート");
  });

  it("sort の攻撃文字列は許可リストに通らず、既定の ID 順になる", async () => {
    const b = new Browser();
    for (const p of SORT_ATTACKS) {
      const res = await b.get(books("fixed", "security", p));
      expect(res.status, p).toBe(200);
      const html = await res.text();
      expect(html, p).toContain("ORDER BY id");
      expect(html, p).toContain("3 件");
      expect(html, p).not.toContain("SQLITE_ERROR");
    }
    expect(await b.text(books("fixed", "programming"))).toContain("Webアプリ入門ノート");
  });

  it("ID の攻撃文字列は、整数の検証で 400 になる（DB には届かない）", async () => {
    const b = new Browser();
    for (const p of ID_ATTACKS) {
      const res = await b.get(book("fixed", p));
      expect(res.status, `id=${p}`).toBe(400);
      const html = await res.text();
      expect(html).toContain("整数で指定してください");
      for (const leak of LEAKS) expect(html, `${p} → ${leak}`).not.toContain(leak);
    }
    expect(await b.text(book("fixed", "2"))).toContain("SQLをはじめよう");
    // 存在しない整数は 200 で「該当なし」
    expect(await b.text(book("fixed", "999"))).toContain("該当する書籍はありません");
  });

  it("ログインの攻撃文字列はすべて失敗し、ユーザー表は漏れない", async () => {
    const b = new Browser();
    const attempts: [string, string][] = [
      ["admin'--", "x"],
      ["nobody", "' OR '1'='1"],
      ["' OR 1=1--", "x"],
      ["' UNION SELECT 1,'admin','admin','admin'--", "x"],
      ["admin", "' OR ''='"],
    ];
    for (const [u, p] of attempts) {
      const html = await login(b, "fixed", u, p);
      expect(html, u).toContain("ログイン失敗");
      expect(html, u).not.toContain("ログイン成功");
      for (const leak of LEAKS) expect(html, `${u} → ${leak}`).not.toContain(leak);
    }
  });

  it("DROP TABLE を送っても実行されない", async () => {
    const b = new Browser();
    await b.get(books("fixed", DROP_BOOKS));
    await b.get(books("fixed", "programming", UPDATE_PRICES));
    const html = await b.text(books("fixed", "programming"));
    expect(html).toContain("Webアプリ入門ノート");
    expect(html).toContain("<td>2200</td>"); // 価格の改ざんも効いていない
  });

  it("エラー時は汎用メッセージとエラーIDだけを画面に出し、詳細は console.error に残る", async () => {
    const b = new Browser();
    await b.get(books("vuln", DROP_BOOKS)); // 脆弱版で表を壊し、修正版でDBエラーを起こす
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const res = await b.get(books("fixed", "programming"));
      expect(res.status).toBe(500);
      const html = await res.text();
      expect(html).toContain("内部エラーが発生しました");
      expect(html).toMatch(/エラーID: [0-9a-f]{8}/);
      expect(html).not.toContain("no such table");
      expect(html).not.toContain("SQLITE_ERROR");
      const logged = spy.mock.calls.map((a) => a.map(String).join(" ")).join("\n");
      expect(logged).toMatch(/\[sqli:[0-9a-f]{8}\]/);
      expect(logged).toContain("no such table");
    } finally {
      spy.mockRestore();
    }
  });
});

describe("SQLインジェクション: 共通", () => {
  it("学習者ごとにデータが分かれる（片方が表を壊しても、もう片方は無事）", async () => {
    const a = new Browser();
    const other = new Browser();
    await a.get(books("vuln", DROP_BOOKS));
    expect(await a.text(books("vuln", "programming"))).toContain("no such table");
    expect(await other.text(books("vuln", "programming"))).toContain("Webアプリ入門ノート");
  });

  it("トップにログインフォームと検索フォームがある", async () => {
    for (const mode of ["vuln", "fixed"] as const) {
      const html = await new Browser().text(`/x/sqli/${mode}/`);
      expect(html).toContain(`action="/x/sqli/${mode}/login"`);
      expect(html).toContain(`action="/x/sqli/${mode}/books"`);
      expect(html).toContain(`action="/x/sqli/${mode}/book"`);
    }
  });

  it("解説ページ: 原因のコードがハイライトされ、修正の差分が出る", async () => {
    const html = await new Browser().text("/x/sqli");
    expect(html).toContain("SQLインジェクション");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
