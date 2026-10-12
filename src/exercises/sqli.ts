import { Hono } from "hono";
import type { AppEnv, Row } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * SQLインジェクション。小さな書店サイトで、ログイン・文字列検索・数値指定・ORDER BY の 4 か所を攻撃する。
 *
 *  - 脆弱版は SQL を文字列連結で作り、DB のエラー文もそのまま画面に出す
 *  - 修正版はプレースホルダ・整数の検証・ORDER BY の許可リスト・汎用エラーメッセージで防ぐ
 *  - どちらのページも「実際に実行された SQL」を画面に出す（入力が SQL のどこに混ざったかを目で追うため）
 *  - 結果の表示は常に table() / escapeHtml を通す。この演習の主題は XSS ではない
 */

const ID = "sqli";
type Mode = "vuln" | "fixed";
const base = (mode: Mode) => `/x/${ID}/${mode}`;

// ---- 画面の部品（脆弱版・修正版で共通。差分に出ないよう region の外に置く） ----

/** 1 回のクエリの結果。error は画面に出す文言（脆弱版は DB のエラーそのまま、修正版は汎用メッセージ） */
interface Result {
  sql: string;
  /** プレースホルダ形式のとき、SQL 文とは別に DB へ渡した値 */
  binds?: (string | number)[];
  rows: Row[];
  error?: string;
}

function sqlView(r: Pick<Result, "sql" | "binds">): string {
  if (!r.sql) return ""; // 検証で断ったときは、SQL を実行していない
  const head = `<h3>実行された SQL${r.binds ? "（プレースホルダ形式）" : ""}</h3><pre class="sql">${escapeHtml(r.sql)}</pre>`;
  if (!r.binds) return head;
  const items = r.binds
    .map((v, i) => `<li>${i + 1} 番目の <code>?</code> ← <code>${escapeHtml(JSON.stringify(v))}</code></li>`)
    .join("");
  return `${head}<h3>バインド値（SQL 文とは別に DB へ渡される）</h3><ul>${items}</ul>`;
}

function errorView(error?: string): string {
  if (!error) return "";
  return `<div class="notice notice--warn"><strong class="ng">エラー</strong><pre class="sql">${escapeHtml(error)}</pre></div>`;
}

/** 脆弱版の下に付ける。壊してしまったときの戻し方 */
function resetBox(mode: Mode): string {
  if (mode !== "vuln") return "";
  return `<details class="qa"><summary>データを壊してしまったら</summary>
<p>表を消したり書き換えたりしても、影響はあなた専用のデータベースだけです。次のボタンで、すべての演習のデータが初期状態に戻ります。</p>
<form method="post" action="/lab/reset"><button class="danger" type="submit">データをリセットする</button></form>
</details>`;
}

function shop(mode: Mode, title: string, body: string): string {
  return exercisePage({
    id: ID,
    mode,
    title,
    body: `<p><a href="${base(mode)}/">← 書店トップ</a></p>\n<h1>${escapeHtml(title)}</h1>\n${body}\n${resetBox(mode)}`,
  });
}

function home(mode: Mode): string {
  const b = base(mode);
  const cats = ["programming", "security", "novel", "cooking"]
    .map((c) => `<a href="${b}/books?category=${c}">${c}</a>`)
    .join(" / ");
  const body = `<h1>サンプル書店</h1>
<div class="notice">各ページの下に、アプリが<strong>実際に実行した SQL</strong>を表示します。入力した文字が SQL のどこに入ったのかを、目で追いながら試してください。</div>
<h2>ログイン</h2>
<form method="post" action="${b}/login">
  <p><label>ユーザー名 <input name="username" autocomplete="off"></label></p>
  <p><label>パスワード <input type="password" name="password" autocomplete="off"></label></p>
  <p><button type="submit">ログイン</button></p>
</form>
<p>テスト用アカウント: <code>taro</code> / <code>taro-pw</code></p>
<h2>書籍を探す（カテゴリ）</h2>
<form method="get" action="${b}/books">
  <p><label>カテゴリ <input name="category" value="programming" autocomplete="off"></label> <button type="submit">検索</button></p>
</form>
<p>カテゴリの例: ${cats}</p>
<h2>書籍の詳細（ID 指定）</h2>
<form method="get" action="${b}/book">
  <p><label>ID <input name="id" value="1" autocomplete="off"></label> <button type="submit">表示</button></p>
</form>
${resetBox(mode)}`;
  return exercisePage({ id: ID, mode, title: "サンプル書店", body });
}

function loginPage(mode: Mode, r: Result): string {
  const first = r.rows[0];
  const verdict = r.error
    ? ""
    : first
      ? `<p class="ok">ログイン成功: ${escapeHtml(String(first.username))}（${escapeHtml(String(first.role))}）としてログインしました。</p>`
      : `<p class="ng">ログイン失敗: ユーザー名またはパスワードが違います。</p>`;
  const rows = r.rows.length
    ? `<h3>SQL の結果（教材のために表示しています）</h3>${table(
        ["id", "username", "role"],
        r.rows.map((x) => [x.id, x.username, x.role]),
      )}`
    : "";
  return shop(mode, "ログイン結果", `${verdict}${errorView(r.error)}${rows}${sqlView(r)}`);
}

function booksPage(mode: Mode, category: string, r: Result): string {
  const b = base(mode);
  const list = r.error
    ? ""
    : r.rows.length
      ? `<p>${r.rows.length} 件</p>${table(
          ["ID", "タイトル", "著者", "カテゴリ", "価格(円)"],
          r.rows.map((x) => [x.id, x.title, x.author, x.category, x.price]),
        )}`
      : `<p>該当する書籍はありません。</p>`;
  const sorts = ["id", "title", "author", "price"]
    .map((s) => `<a href="${b}/books?category=${encodeURIComponent(category)}&amp;sort=${s}">${s}</a>`)
    .join(" | ");
  const note =
    mode === "fixed"
      ? `<p>ORDER BY の列名は <code>?</code> にできないため、許可リストから選んだ固定の文字列を SQL に入れています。</p>`
      : "";
  const body = `<form method="get" action="${b}/books">
  <p><label>カテゴリ <input name="category" value="${escapeHtml(category)}" autocomplete="off"></label> <button type="submit">検索</button></p>
</form>
<p>並べ替え（<code>sort</code>）: ${sorts}</p>
${errorView(r.error)}${list}${sqlView(r)}${note}`;
  return shop(mode, "書籍検索", body);
}

function bookPage(mode: Mode, r: Result): string {
  const list = r.error
    ? ""
    : r.rows.length
      ? `<p>${r.rows.length} 件</p>${table(
          ["ID", "タイトル", "著者", "カテゴリ", "価格(円)"],
          r.rows.map((x) => [x.id, x.title, x.author, x.category, x.price]),
        )}`
      : `<p>該当する書籍はありません。</p>`;
  return shop(mode, "書籍の詳細", `${errorView(r.error)}${list}${sqlView(r)}`);
}

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.post("/login", async (c) => {
  const form = await c.req.parseBody();
  const username = String(form.username ?? "");
  const password = String(form.password ?? "");
  const sql = `SELECT id, username, role FROM sqli_users WHERE username = '${username}' AND password = '${password}'`; // [!] 入力値を、文字列リテラルの内側へそのまま連結している
  const r: Result = { sql, rows: [] };
  try {
    r.rows = await c.var.db.all(sql);
  } catch (e) {
    r.error = (e as Error).message; // [!] DBのエラー文をそのまま画面に出している（テーブル名・構文の手がかりが漏れる）
  }
  return c.html(loginPage("vuln", r));
});

vuln.get("/books", async (c) => {
  const category = c.req.query("category") ?? "";
  const sort = c.req.query("sort") || "id";
  const sql = `SELECT * FROM sqli_books WHERE category = '${category}' ORDER BY ${sort}`; // [!] category（文字列）も sort（列名）も検証せずに連結している。SELECT * で非公開の列まで取っている
  const r: Result = { sql, rows: [] };
  try {
    r.rows = await c.var.db.all(sql);
  } catch (e) {
    r.error = (e as Error).message; // [!] DBのエラー文をそのまま画面に出している
  }
  return c.html(booksPage("vuln", category, r));
});

vuln.get("/book", async (c) => {
  const id = c.req.query("id") ?? "1";
  const sql = `SELECT * FROM sqli_books WHERE id = ${id}`; // [!] 数値のつもりの入力を検証せず連結している（引用符がないので ' を使わずに攻撃できる）
  const r: Result = { sql, rows: [] };
  try {
    r.rows = await c.var.db.all(sql);
  } catch (e) {
    r.error = (e as Error).message; // [!] DBのエラー文をそのまま画面に出している
  }
  return c.html(bookPage("vuln", r));
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

// ORDER BY の列名はプレースホルダにできない。許可リストの「キー → 固定の SQL 断片」で選ぶ
const SORTS = new Map([
  ["id", "id"],
  ["title", "title"],
  ["author", "author"],
  ["price", "price"],
]);

/** 画面には汎用メッセージとエラーIDだけを出し、詳細はサーバーのログに残す */
function failed(err: unknown): string {
  const errorId = crypto.randomUUID().slice(0, 8);
  console.error(`[sqli:${errorId}]`, err);
  return `内部エラーが発生しました（エラーID: ${errorId}）。時間をおいて、もう一度お試しください。`;
}

fixed.post("/login", async (c) => {
  const form = await c.req.parseBody();
  const username = String(form.username ?? "");
  const password = String(form.password ?? "");
  const sql = "SELECT id, username, role FROM sqli_users WHERE username = ? AND password = ?";
  const r: Result = { sql, binds: [username, password], rows: [] };
  try {
    r.rows = await c.var.db.all(sql, r.binds);
  } catch (e) {
    r.error = failed(e);
  }
  return c.html(loginPage("fixed", r), r.error ? 500 : 200);
});

fixed.get("/books", async (c) => {
  const category = c.req.query("category") ?? "";
  const sort = SORTS.get(c.req.query("sort") ?? "") ?? "id";
  const sql = `SELECT id, title, author, category, price FROM sqli_books WHERE category = ? ORDER BY ${sort}`; // ORDER BY に入るのは許可リストの固定文字列だけ
  const r: Result = { sql, binds: [category], rows: [] };
  try {
    r.rows = await c.var.db.all(sql, r.binds);
  } catch (e) {
    r.error = failed(e);
  }
  return c.html(booksPage("fixed", category, r), r.error ? 500 : 200);
});

fixed.get("/book", async (c) => {
  const raw = c.req.query("id") ?? "";
  if (!/^[0-9]{1,9}$/.test(raw)) {
    return c.html(bookPage("fixed", { sql: "", rows: [], error: "ID は整数で指定してください。" }), 400);
  }
  const sql = "SELECT id, title, author, category, price FROM sqli_books WHERE id = ?";
  const r: Result = { sql, binds: [Number(raw)], rows: [] };
  try {
    r.rows = await c.var.db.all(sql, r.binds);
  } catch (e) {
    r.error = failed(e);
  }
  return c.html(bookPage("fixed", r), r.error ? 500 : 200);
});
//#endregion

vuln.get("/", (c) => c.html(home("vuln")));
fixed.get("/", (c) => c.html(home("fixed")));

// 攻撃ペイロードのうち、URL に載せて開けるもの（解説の「開く」ボタン用）
const enc = encodeURIComponent;
const UNION_USERS = "' UNION SELECT id,username,password,role,0,'' FROM sqli_users--";
const UNION_MASTER = "' UNION SELECT 1,name,sql,type,0,'' FROM sqlite_master--";
const UNION_NOTES = "' UNION SELECT id,title,internal_note,category,price,'' FROM sqli_books--";
const NUM_UNION = "0 UNION SELECT id,username,password,role,0,'' FROM sqli_users";
const BLIND_TRUE =
  "CASE WHEN (SELECT substr(password,1,1) FROM sqli_users WHERE username='admin')='a' THEN price ELSE title END";
const BLIND_FALSE = BLIND_TRUE.replace("='a'", "='z'");
const DROP_BOOKS = "'; DROP TABLE sqli_books--";
const UPDATE_PRICES = "id; UPDATE sqli_books SET price = 1";

export const exercise: Exercise = {
  id: ID,
  title: "SQLインジェクション",
  summary: "入力値を連結して作った SQL は、入力の側から書き換えられる。ログイン回避、他の表の盗み見、データ破壊までを体験する。",
  level: 2,
  book: { chapter: 4, topic: "SQL呼び出しに伴う脆弱性（SQLインジェクション）" },
  schema: [
    `CREATE TABLE sqli_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL)`,
    `CREATE TABLE sqli_books (
       id INTEGER PRIMARY KEY, title TEXT NOT NULL, author TEXT NOT NULL, category TEXT NOT NULL,
       price INTEGER NOT NULL, internal_note TEXT NOT NULL
     )`,
  ],
  seed: [
    // パスワードは平文のダミー値。保存方法の問題はこの演習の主題ではない（password-storage 演習で扱う）
    `INSERT INTO sqli_users (id, username, password, role) VALUES
       (1, 'admin',  'admin-pass-2024', 'admin'),
       (2, 'taro',   'taro-pw',         'user'),
       (3, 'hanako', 'hanako-pw',       'user'),
       (4, 'guest',  'guest',           'guest')`,
    `INSERT INTO sqli_books (id, title, author, category, price, internal_note) VALUES
       (1,  'Webアプリ入門ノート',   'サンプル 太郎', 'programming', 2200, '原価 1,100円 / 仕入先: 見本出版 / 掛け率 50%'),
       (2,  'SQLをはじめよう',       'テスト 花子',   'programming', 2600, '原価 1,300円 / 在庫過多のため来月値下げ予定'),
       (3,  'TypeScript実践メモ',    'ダミー 次郎',   'programming', 3100, '原価 1,550円 / 重版未定'),
       (4,  '守りのWeb設計',         'サンプル 太郎', 'security',    3300, '原価 1,650円 / 法人まとめ買い向けの特別卸あり'),
       (5,  '攻撃者の視点を学ぶ',    '見本 三郎',     'security',    2900, '原価 1,450円 / 社外秘: 秋のフェア対象'),
       (6,  'ログと監査の基本',      'テスト 花子',   'security',    2700, '原価 1,350円'),
       (7,  '月曜日の図書室',        'ダミー 花',     'novel',       1500, '原価 750円 / 著者への支払いは翌月末'),
       (8,  '雨の日の列車',          '見本 四郎',     'novel',       1600, '原価 800円'),
       (9,  '十五分でできる夕食',    'サンプル 花',   'cooking',     1800, '原価 900円 / 返品率が高い'),
       (10, '常備菜のはなし',        'テスト 太郎',   'cooking',     1700, '原価 850円')`,
  ],
  vuln,
  fixed,
  doc: {
    goals: [
      "入力値が SQL の「データ」ではなく「構文」として解釈される仕組みを、画面に出る実行 SQL を見ながら説明できる",
      "ログイン回避、UNION による他の表の盗み見、表名の列挙、複数文によるデータ破壊と、被害が段階的に広がる流れを体験する",
      "対策の本命はプレースホルダだが、数値・列名（ORDER BY）・エラーメッセージでは別の対策が要ることを説明できる",
    ],
    background: `
SQLインジェクションは、アプリが組み立てる SQL 文に入力値が混ざるとき、入力値の一部が**データではなく SQL の命令として読まれてしまう**問題です。攻撃者は、アプリの作者が想定していない条件や別の問い合わせを、入力欄やURLのパラメータから差し込めます。

被害は、ログインの回避、非公開データの閲覧（他の表の中身を含む）、データの改ざん・削除と、アプリが持つDB権限の範囲で広がります。個人情報の漏えいに直結しやすく、古くからある脆弱性なのに今も繰り返し起きています。

この演習の書店サイトは、4つの入口（ログイン、カテゴリ検索、ID指定、並べ替え）で、SQL を文字列連結で組み立てています。各ページに**実行された SQL** が出るので、入力がどこに混ざったかを確かめながら進めてください。

なお、攻撃の影響は、あなた専用のデータベースの中だけに閉じています。壊してしまっても、脆弱版のページ下部にある「データをリセットする」で戻せます。
`,
    steps: [
      {
        title: "通常の動作と、実行される SQL を確かめる",
        body: "まず普通にカテゴリで検索します。ページの下に出る「実行された SQL」を読み、`'programming'` の部分に入力値がそのまま入っていることを確認してください。この「入力値が SQL の文字列に直接入る」場所が、以降のすべての攻撃の入口です。",
        payloads: [{ label: "カテゴリ", value: "programming" }],
        open: { label: "脆弱版で検索する", href: "vuln/books?category=programming" },
      },
      {
        title: "引用符で SQL を壊し、エラー文を観察する",
        body: "カテゴリに `'`（シングルクォート）1文字だけを入れます。文字列リテラルが途中で終わり、SQL が壊れます。画面に出たエラー文には、DBが SQL のどこを読めなかったかが書かれています。攻撃者にとっては「このパラメータはSQLに直接入っている」という確かな合図です。",
        payloads: [{ label: "カテゴリ", value: "'" }],
        open: { label: "このペイロードで試す", href: "vuln/books?category=" + enc("'") },
      },
      {
        title: "条件を常に真にして、全件を出す",
        body: "`WHERE category = '' OR '1'='1'` となるように入れます。末尾の引用符はアプリが付けてくれるので、`'1'='1` の最後の `'` を書かないのがコツです。カテゴリに関係なく全カテゴリの本が表示されます。",
        payloads: [{ label: "カテゴリ", value: "' OR '1'='1" }],
        open: { label: "このペイロードで試す", href: "vuln/books?category=" + enc("' OR '1'='1") },
      },
      {
        title: "ログインを回避する",
        body: "書店トップのログインフォームで、ユーザー名に `admin'--`、パスワードには適当な文字（例: `x`）を入れて送信します。`--` から行末までは SQL のコメントなので、パスワードの条件が丸ごと消え、パスワードを知らなくても admin としてログインできます。別解として、パスワード欄に `' OR '1'='1` を入れる方法もあります（ユーザー名は存在しない名前でも通ります。理由は SQL の AND と OR の優先順位です）。",
        payloads: [
          { label: "ユーザー名", value: "admin'--", note: "パスワードは何でもよい" },
          { label: "パスワード（別解）", value: "' OR '1'='1", note: "ユーザー名は nobody など" },
        ],
        open: { label: "ログインフォームを開く", href: "vuln/" },
      },
      {
        title: "列数を探って、UNION で別の表（ユーザー表）を読む",
        body: "`UNION` で別の表を結合するには、元の SELECT と**列数を合わせる**必要があります。まず `ORDER BY 番号` で列数を探ります。`ORDER BY 6` は通り、`ORDER BY 7` はエラーになれば、元の SELECT は6列です（エラー文が列数を教えてくれます）。列数がわかったら、`UNION SELECT` で `sqli_users` を読みます。画面に出るのは2〜5列目なので、ユーザー名とパスワードが「タイトル」「著者」の欄に並びます。",
        payloads: [
          { label: "ステップ1: 列数が合うか", value: "' ORDER BY 6--", note: "エラーにならない" },
          { label: "ステップ2: 1つ増やす", value: "' ORDER BY 7--", note: "エラー文に列数が出る" },
          { label: "ステップ3: UNION で盗む", value: UNION_USERS },
        ],
        open: { label: "ユーザー表を盗むペイロードで試す", href: "vuln/books?category=" + enc(UNION_USERS) },
      },
      {
        title: "表名・列名を調べて、非公開メモ（原価）を盗む",
        body: "標的の表名がわからなくても、SQLite には全表の定義を持つ `sqlite_master` があります。まずこれを UNION で読むと、このデータベースにどんな表があり、どんな列を持つかが丸見えになります。次に、公開画面には出ていない `internal_note`（原価などの社内メモ）を、画面に出る列の位置へ差し込んで盗みます。",
        payloads: [
          { label: "表の一覧と定義を読む", value: UNION_MASTER },
          { label: "原価メモを盗む", value: UNION_NOTES },
        ],
        open: { label: "表の定義を読む", href: "vuln/books?category=" + enc(UNION_MASTER) },
      },
      {
        title: "数値のパラメータ（引用符がない場所）を攻撃する",
        body: "書籍の詳細は `WHERE id = 入力値` と、引用符なしで SQL に入ります。ここでは `'` を一切使わずに攻撃できます。つまり「引用符をエスケープする」だけの対策は、数値の場所では役に立ちません。",
        payloads: [
          { label: "全件を出す", value: "1 OR 1=1" },
          { label: "UNION でユーザー表を盗む", value: NUM_UNION },
        ],
        open: { label: "このペイロードで試す", href: "vuln/book?id=" + enc(NUM_UNION) },
      },
      {
        title: "ORDER BY の注入（画面に結果が出なくても情報を抜く）",
        body: "並べ替えの `sort` は、列名として SQL にそのまま入ります。ここから `UNION` は使えませんが、式やサブクエリは書けます。次の2つは、「adminのパスワードの1文字目が `a` かどうか」という条件で並び順が変わります。左が `a` と仮定した場合（正しい仮定なので `price` 順）、右が `z` と仮定した場合（外れなので `title` 順）です。結果の並びを見るだけで、真偽が1ビットずつ読み取れます（ブラインドSQLインジェクション）。",
        payloads: [
          { label: "仮定が正しい（価格順になる）", value: BLIND_TRUE },
          { label: "仮定が外れる（タイトル順になる）", value: BLIND_FALSE },
          { label: "エラーで情報を出させる", value: "(SELECT 1 FROM no_such_table)", note: "エラー文に表名が出る" },
        ],
        open: {
          label: "仮定が正しい場合を開く",
          href: "vuln/books?category=security&sort=" + enc(BLIND_TRUE),
        },
      },
      {
        title: "複数の文を実行して、データを壊す・改ざんする",
        body: "このラボのデータベース（Durable Object の SQLite）は、`;` で区切った複数の文を1回の呼び出しで実行できることを、実際に確かめています（結果として画面に返るのは最後の文の分だけです）。カテゴリに `'; DROP TABLE sqli_books--` を入れると、検索の後ろで `DROP TABLE` が実行され、書籍表が消えます。もう一度書籍検索を開くと `no such table` のエラーになります。\n\n`sort` の後ろからでも文は足せます。2つ目のペイロードは、並べ替えを装って全商品の価格を1円に書き換えます。\n\n細かい挙動として、先の SELECT が行を返している間は `DROP TABLE` が `database table is locked` で失敗します（カテゴリ側のペイロードは先の SELECT が0件になるので通ります）。`UPDATE` や `DELETE` は、行を返していても通ります。\n\nなお、DBドライバには、複数の文を受け付けない設定が既定のものも多くあります。その場合はこの手順は通りませんが、手順3〜8（条件の書き換えと UNION）はそのまま成立します。「複数文が通らないから安全」とは言えません。壊れたデータは、ページ下部の「データをリセットする」で戻せます。",
        payloads: [
          { label: "カテゴリ（表を消す）", value: DROP_BOOKS },
          { label: "sort（価格を改ざんする）", value: UPDATE_PRICES, note: "カテゴリは programming など" },
        ],
        open: { label: "表を消すペイロードで試す（書籍表が消えます）", href: "vuln/books?category=" + enc(DROP_BOOKS) },
      },
    ],
    cause: `
原因は、**入力値を、SQL文の文字列にそのまま連結していること**です。ハイライトした行が問題です。

- ログイン: ユーザー名とパスワードを、引用符で囲んだ文字列リテラルの内側に連結しています。入力に \`'\` が含まれるとリテラルがそこで終わり、続きが SQL の構文として読まれます。\`--\` を入れれば、以降（パスワードの条件）はコメントになって消えます。
- 書籍検索: \`category\` を同じように連結しています。さらに \`sort\` は ORDER BY の後ろに連結しているので、引用符を使わなくても、式やサブクエリを差し込めます。
- 書籍詳細: 数値のつもりの \`id\` を、引用符なしで連結しています。攻撃に \`'\` が要らないので、引用符のエスケープだけでは防げません。
- エラー: DB のエラー文をそのまま画面に出しています。構文エラーや列数の不一致のメッセージは、攻撃者が列数や表名を探るヒントになります。
- \`SELECT *\`: 画面に出す列は5つだけですが、非公開の \`internal_note\` まで取り出しています。「画面に出していないから安全」ではなく、UNION で列数を合わせられると、出ている欄に好きな列を差し込まれます。

どれも「入力値は文字列（または数値）のはずだ」という思い込みから生まれます。DB から見ると、連結された SQL のどこまでがアプリの書いた命令で、どこからが入力値なのか区別できません。
`,
    fix: `
修正の本命は**プレースホルダ**です。SQL の骨組み（\`WHERE username = ? AND password = ?\`）と、値（入力された文字列）を**別々に** DB へ渡します。値は何が入っていても「ただの値」として扱われるので、\`'\` や \`--\` が入っていても SQL の構文にはなりません。修正版のページには、プレースホルダ形式の SQL とバインド値が別々に表示されます。

場所ごとの対策も入れています。

- 数値（ID）: プレースホルダに加えて、整数かどうかを先に検証します。想定外の入力は DB に届く前に 400 で断ります（検証は保険です）。
- ORDER BY の列名: 列名や並び順などの「識別子」は \`?\` にできません（\`ORDER BY ?\` は列を選ぶのではなく定数で並べるだけ）。そこで、許可リスト（\`SORTS\`）から固定の文字列を選び、リストにない値は既定の \`id\` 順にします。ユーザー入力が SQL に入ることはありません。
- エラー: 画面には汎用メッセージとエラーIDだけを出し、詳細は \`console.error\` でログに残します。調査はエラーIDで突き合わせます。
- 取る列: \`SELECT *\` をやめ、画面に必要な列だけを取ります。
`,
    verify: [
      "修正版の書籍検索に、手順2・3・5・6・9のペイロードをそのまま入れる。エラーにならず、「該当する書籍はありません」と表示される（カテゴリが文字列としてだけ比較されている）",
      "ページ下の「実行された SQL（プレースホルダ形式）」と「バインド値」が分かれていて、ペイロードがバインド値の欄にだけ入っていることを確かめる",
      "ログインで `admin'--` を試す。ログイン失敗になる。正しいアカウント（taro / taro-pw）では成功する",
      "書籍の詳細で `1 OR 1=1` を試す。400（ID は整数で指定してください）になる。`sort` に手順8・9のペイロードを入れても、エラーにならず ID 順に並ぶだけ（価格も書き換わらない）",
      "脆弱版で手順9を実行して表を消したあと、修正版の書籍検索を開く。エラー欄には「エラーID」と汎用メッセージだけが出て、DB のエラー文（`no such table` など）は出ない（詳細はサーバーのログに残る）",
    ],
    beyond: `
**プレースホルダを使っても残る注意点があります。** ORDER BY や表名・列名のような識別子は \`?\` にできないので、許可リストが必要です。\`LIKE\` を使う検索では、\`%\` や \`_\` が検索のワイルドカードとして働くため、それが困るなら別途エスケープします。ORM を使っていても、生の SQL 文字列に入力値を連結すれば同じ問題が起きます。

**パスワードを平文で保存している点は、この演習の主題ではないので省略しましたが、実務では大問題です。** UNION で盗めたのが平文のパスワードだったことが、被害を大きくしています。保存方法は「パスワードの保存」の演習で扱います。

**DB の権限は最小にします。** アプリ用の DB アカウントに、DROP や他の表への SELECT が許されていなければ、SQL インジェクションが成立しても被害は小さくなります。表ごと・操作ごとに権限を分けておくのは、プレースホルダに漏れがあったときの保険です。

**エラーメッセージを画面に出さない運用は、攻撃の足がかりを減らします。** ただしこれは「見えなくする」対策にすぎません。ブラインドSQLインジェクション（手順8）のように、エラーが見えなくても情報は抜けるので、原因（連結）を直すことが先です。

**複数文の実行はドライバ次第です。** このラボのDBは受け付けましたが、既定で拒否するドライバもあります。拒否されても、UNION や条件の書き換えは防げません。WAF（攻撃パターンの検知）も、根本対策の代わりにはなりません。
`,
    quiz: [
      {
        q: "数値の ID に対して、入力中の `'` を `\\'` に置き換える（エスケープする）だけでは、なぜ防げない？",
        a: "数値は引用符で囲まれずにSQLへ入るので、攻撃に `'` が要りません。`1 OR 1=1` のように、空白と英数字だけで条件を書き換えられます。数値は整数かどうかの検証とプレースホルダで守ります。",
      },
      {
        q: "ORDER BY の列名を `?` にバインドすればよい？ そうでないなら、どう守る？",
        a: "できません。`?` に渡した値は列名ではなく「値（定数）」として扱われ、列を選ぶ指定にならないからです。許可する列名のリストを用意して、入力値を固定の文字列に対応づけ、リストにない値は既定の並び順にします。",
      },
      {
        q: "エラーメッセージを画面に出さなければ、SQLインジェクションは防げる？",
        a: "防げません。エラーを隠しても、結果の並びや応答の違いから情報を抜くブラインドSQLインジェクションが成立します。原因である文字列連結を直すのが本命です。エラー文を隠すのは、攻撃者に手がかりを与えないための追加策です。",
      },
    ],
  },
};
