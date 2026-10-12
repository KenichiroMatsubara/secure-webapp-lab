import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * オープンリダイレクト。
 *
 * 「ログイン後に元のページへ戻す」(next) と、外部リンク用の転送 (/redirect?url=) を持つ小さなサイト。
 *  - 脆弱版 (A): 値を検証せずそのまま Location に使う
 *  - 脆弱版 (B): 「対策に失敗した例」。startsWith("/") だけで検証する（// や /\ で破られる）
 *  - 修正版: new URL() で解析して、オリジンが同じ相対パスだけを採用する。外部へは許可リスト（識別子）で
 *
 * 転送先の例はすべて予約ドメイン（evil.example）。ガードが、予約ドメイン以外への転送は止めて説明ページに差し替える。
 */

const ID = "open-redirect";
type Mode = "vuln" | "fixed";
type Ctx = Context<AppEnv>;

//#region vuln
const vuln = new Hono<AppEnv>();
const VULN_HOME = `/x/${ID}/vuln/mypage`;

// (A) 検証なし: 渡された値をそのまま転送先にする
function nextA(raw: string): string {
  return raw || VULN_HOME; // [!] 値を検証せず、そのまま Location に使う（外部のURLもそのまま通る）
}

// (B) 対策に失敗した例: 「/ で始まるなら自サイトの相対パスだろう」という思い込み
function nextB(raw: string): string {
  return raw.startsWith("/") ? raw : VULN_HOME; // [!] "//evil.example/" や "/\evil.example/" も "/" で始まるので通ってしまう
}

// ログイン後に元のページへ戻す (next) と、外部リンク用の転送 (url)
vuln.post("/login", async (c) => {
  const next = String((await c.req.parseBody())["next"] ?? "");
  return c.redirect(nextA(next), 303);
});
vuln.get("/redirect", (c) => c.redirect(nextA(c.req.query("url") ?? ""), 302));

// (B) の版。ルートの作りは (A) と同じ
vuln.post("/b/login", async (c) => {
  const next = String((await c.req.parseBody())["next"] ?? "");
  return c.redirect(nextB(next), 303);
});
vuln.get("/b/redirect", (c) => c.redirect(nextB(c.req.query("url") ?? ""), 302));
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();
const FIXED_HOME = `/x/${ID}/fixed/mypage`;

// 転送先として採用してよいのは、「このサイト内の相対パス」だけ
function safeNext(raw: string, origin: string): string {
  let u: URL;
  try {
    u = new URL(raw, origin); // 絶対URL も //host も /\host も、ブラウザと同じ規則で「本当の宛先」に解釈される
  } catch {
    return FIXED_HOME;
  }
  if (u.origin !== origin) return FIXED_HOME; // オリジンが違う＝外部サイトなので採用しない
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return FIXED_HOME; // 相対パス以外は採用しない
  const path = u.pathname + u.search + u.hash; // 解析・正規化した値を返す（生の入力はそのまま使わない）
  return path.startsWith("//") ? FIXED_HOME : path; // 正規化の結果が // で始まる入力（/..//evil.example など）も採用しない
}

fixed.post("/login", async (c) => {
  const next = String((await c.req.parseBody())["next"] ?? "");
  return c.redirect(safeNext(next, new URL(c.req.url).origin), 303);
});
fixed.get("/redirect", (c) => c.redirect(safeNext(c.req.query("url") ?? "", new URL(c.req.url).origin), 302));

// 外部サイトへ行かせたいときは、URL ではなく識別子で行き先を選ぶ（許可リスト）
const PARTNERS = new Map([
  ["partner", "https://partner.example/"],
  ["docs", "https://docs.example.com/"],
]);
fixed.get("/go", (c) => c.redirect(PARTNERS.get(c.req.query("site") ?? "") ?? FIXED_HOME, 302));
//#endregion

// ---- ここから先は、脆弱版・修正版で共通の画面（学習用の補助） ----
interface Variant {
  label: string;
  /** ルートの接頭辞（/login と /redirect が生えている場所） */
  base: string;
  pick: (raw: string, origin: string) => string;
}

const VARIANTS: Record<"a" | "b" | "fixed", Variant> = {
  a: { label: "脆弱版 (A) 検証なし", base: `/x/${ID}/vuln`, pick: nextA },
  b: { label: "脆弱版 (B) startsWith(\"/\") だけ", base: `/x/${ID}/vuln/b`, pick: nextB },
  fixed: { label: "修正版", base: `/x/${ID}/fixed`, pick: safeNext },
};

/** ブラウザは Location をこう解釈して移動する */
function destination(location: string, origin: string): { host: string; external: boolean } {
  try {
    const u = new URL(location, origin);
    return { host: u.host, external: u.origin !== origin };
  } catch {
    return { host: "（解釈できません）", external: true };
  }
}

function destinationLine(location: string, origin: string): string {
  const d = destination(location, origin);
  return d.external
    ? `<p class="ng">ブラウザの移動先: <code>${escapeHtml(d.host)}</code>（別のサイト）</p>`
    : `<p class="ok">ブラウザの移動先: <code>${escapeHtml(d.host)}</code>（このサイトの中）</p>`;
}

function loginPage(c: Ctx, mode: Mode, v: Variant): string {
  const origin = new URL(c.req.url).origin;
  const next = c.req.query("next") ?? "";
  const location = v.pick(next, origin);
  const body = `<h1>ログイン（擬似）</h1>
<p>認証そのものは主題ではないので、ボタンを押すとログインしたことになります。</p>
<p>ログインに成功すると、サーバーは次のように転送します（<code>next</code> の値: <code>${escapeHtml(next || "（なし）")}</code>）。</p>
<pre class="code"><code>HTTP/1.1 303 See Other
Location: ${escapeHtml(location)}</code></pre>
${destinationLine(location, origin)}
<form method="post" action="${v.base}/login">
  <input type="hidden" name="next" value="${escapeHtml(next)}">
  <button type="submit">ログインして進む</button>
</form>
<p><a href="/x/${ID}/${mode}/">← ショップのトップへ</a></p>`;
  return exercisePage({ id: ID, mode, title: "ログイン", body });
}

function homePage(mode: Mode): string {
  const v = mode === "vuln" ? VARIANTS.a : VARIANTS.fixed;
  const home = `/x/${ID}/${mode}/mypage`;
  const partner =
    mode === "vuln"
      ? `<li><a href="${v.base}/redirect?url=${encodeURIComponent("https://partner.example/")}">提携サイトへ（<code>/redirect?url=</code> を経由）</a></li>`
      : `<li><a href="${v.base}/go?site=partner">提携サイトへ（<code>/go?site=partner</code>：許可リスト）</a></li>`;
  const bBlock =
    mode === "vuln"
      ? `<h2>対策に失敗した例 (B)</h2>
<p><code>startsWith("/")</code> だけで検証する版です。<code>${VARIANTS.b.base}/login</code> と <code>${VARIANTS.b.base}/redirect</code> があります。</p>
<ul><li><a href="${VARIANTS.b.base}/login?next=${encodeURIComponent(home)}">(B) のログイン</a></li></ul>`
      : "";
  const body = `<h1>ショップ（ログインとリンク）</h1>
<h2>ログイン後に元のページへ戻す</h2>
<p>ログインが必要なページに来ると、ログイン後に戻る先を <code>next</code> パラメータで引き継ぎます。</p>
<ul><li><a href="${v.base}/login?next=${encodeURIComponent(home)}">マイページ（ログインが必要）へ</a></li></ul>
<h2>外部サイトへのリンク</h2>
<ul>${partner}</ul>
${bBlock}
<h2>転送先チェッカー</h2>
<p>値を入れると、各ルートが返す <code>Location</code> と、ブラウザの移動先を調べられます。</p>
<form method="get" action="/x/${ID}/${mode}/inspect">
  <input name="value" size="44" value="https://evil.example/login" aria-label="調べる値" autocomplete="off">
  <button type="submit">調べる</button>
</form>`;
  return exercisePage({ id: ID, mode, title: "ショップ", body });
}

function inspectPage(c: Ctx, mode: Mode): string {
  const origin = new URL(c.req.url).origin;
  const value = c.req.query("value") ?? "";
  const keys = mode === "vuln" ? (["a", "b"] as const) : (["fixed"] as const);
  const rows = keys
    .map((k) => {
      const v = VARIANTS[k];
      const location = v.pick(value, origin);
      const d = destination(location, origin);
      const q = encodeURIComponent(value);
      return `<tr><td>${escapeHtml(v.label)}</td><td><code>${escapeHtml(location)}</code></td>
<td class="${d.external ? "ng" : "ok"}">${escapeHtml(d.host)}（${d.external ? "別のサイト" : "このサイトの中"}）</td>
<td><a href="${v.base}/login?next=${q}">ログインで試す</a> / <a href="${v.base}/redirect?url=${q}">/redirect で試す</a></td></tr>`;
    })
    .join("");
  const body = `<h1>転送先チェッカー</h1>
<form method="get" action="/x/${ID}/${mode}/inspect">
  <input name="value" size="44" value="${escapeHtml(value)}" aria-label="調べる値" autocomplete="off">
  <button type="submit">調べる</button>
</form>
<table class="data"><thead><tr><th>ルート</th><th>返す Location</th><th>ブラウザの移動先</th><th>試す</th></tr></thead><tbody>${rows}</tbody></table>
<p><a href="/x/${ID}/${mode}/">← ショップのトップへ</a></p>`;
  return exercisePage({ id: ID, mode, title: "転送先チェッカー", body });
}

vuln.get("/login", (c) => c.html(loginPage(c, "vuln", VARIANTS.a)));
vuln.get("/b/login", (c) => c.html(loginPage(c, "vuln", VARIANTS.b)));
fixed.get("/login", (c) => c.html(loginPage(c, "fixed", VARIANTS.fixed)));

for (const [app, mode] of [
  [vuln, "vuln"],
  [fixed, "fixed"],
] as const) {
  app.get("/", (c) => c.html(homePage(mode)));
  app.get("/inspect", (c) => c.html(inspectPage(c, mode)));
  app.get("/mypage", (c) =>
    c.html(
      exercisePage({
        id: ID,
        mode,
        title: "マイページ",
        body: `<h1>マイページ（擬似）</h1><p>ログインできました。ここが、ログイン後の「元のページ」です。</p><p><a href="/x/${ID}/${mode}/">← ショップのトップへ</a></p>`,
      }),
    ),
  );
}

// ---- 攻撃者サイト役（/attacker/open-redirect）: 正規サイトのURLを使ったフィッシングメール ----
const PAYLOADS: { label: string; value: string }[] = [
  { label: "絶対URL", value: "https://evil.example/login" },
  { label: "スキーム省略（//）", value: "//evil.example/login" },
  { label: "バックスラッシュ（/\\）", value: "/\\evil.example/login" },
  { label: "@ を使った見せかけ", value: "https://example.com@evil.example/" },
];

const attacker = new Hono<AppEnv>();

attacker.get("/", (c) => {
  const origin = new URL(c.req.url).origin;
  const trap = `/x/${ID}/vuln/login?next=${encodeURIComponent(PAYLOADS[0].value)}`;
  const cell = (k: "a" | "b" | "fixed", value: string) => {
    const v = VARIANTS[k];
    const location = v.pick(value, origin);
    const d = destination(location, origin);
    return `<td><a href="${escapeHtml(`${v.base}/login?next=${encodeURIComponent(value)}`)}">開く</a><br>
<code>${escapeHtml(location)}</code><br><span class="${d.external ? "ng" : "ok"}">${d.external ? "外部へ" : "サイト内"}</span></td>`;
  };
  const rows = PAYLOADS.map(
    (p) =>
      `<tr><td>${escapeHtml(p.label)}<br><code>${escapeHtml(p.value)}</code></td>${cell("a", p.value)}${cell("b", p.value)}${cell("fixed", p.value)}</tr>`,
  ).join("");

  const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>攻撃者サイト（模擬）</title><link rel="stylesheet" href="/assets/lab.css"></head>
<body class="ex ex--guard"><main class="ex-main">
<div class="notice notice--warn">これは<strong>攻撃者側</strong>を演じる模擬ページです。リンクは<strong>あなたが押したときだけ</strong>動きます。転送先の <code>evil.example</code> は実在しない予約ドメインで、実際には外部へ何も送られません。</div>
<h1>① 攻撃者が送るメール（模擬）</h1>
<div class="result">
  <p>差出人: ショップ事務局（なりすまし）</p>
  <p>件名: 【重要】アカウントの確認をお願いします</p>
  <p>お客様のアカウントで、不審なログインがありました。<a href="${escapeHtml(trap)}">こちらからログイン</a>して、ご利用状況を確認してください。</p>
</div>
<p>リンクのドメインは、<strong>正規のショップのまま</strong>です（<code>${escapeHtml(origin)}</code>）。メールの文面を見ても、リンクにマウスを乗せても、怪しさに気づきにくいのが、この攻撃の厄介な点です。ログインするとサーバーが <code>next</code> の値へ転送するので、被害者は攻撃者のサイトに連れて行かれます。</p>
<pre class="code"><code>${escapeHtml(origin + trap)}</code></pre>
<p>転送先の <code>evil.example</code> は存在しないため、ブラウザは接続エラーを表示します。ここで確認するのは、<strong>正規サイトのログイン画面から、攻撃者が指定した別のサイトへ移動させられる</strong>ことです。</p>

<h2>② 手口ごとの結果（脆弱版 A・B と修正版）</h2>
<table class="data"><thead><tr><th>手口</th><th>脆弱版 (A) 検証なし</th><th>脆弱版 (B) startsWith</th><th>修正版</th></tr></thead><tbody>${rows}</tbody></table>
<p>「開く」を押すと、そのルートのログイン画面に進みます。表示される <code>Location</code> と「ブラウザの移動先」を確かめてください。</p>
<p><a href="/x/${ID}">← 解説へ戻る</a></p>
</main></body></html>`;
  return c.html(html);
});

export const exercise: Exercise = {
  id: ID,
  title: "オープンリダイレクト",
  summary: "ログイン後の戻り先や外部リンクの転送先を検証しないと、正規サイトのURLが攻撃者のサイトへの踏み台になる。",
  level: 1,
  book: { chapter: 4, topic: "リダイレクト処理にまつわる問題" },
  vuln,
  fixed,
  attacker,
  doc: {
    goals: [
      "オープンリダイレクトが成立する仕組みと、フィッシングの踏み台に使われる理由を説明できる",
      "startsWith(\"/\") のような文字列検査が、なぜ破られるのかを（ブラウザのURL解釈の観点から）説明できる",
      "転送先を new URL() で解析して検証する方法と、許可リスト（識別子）方式の使い分けを説明できる",
    ],
    background: `
オープンリダイレクトは、**転送先のURLを外部から指定できるリダイレクト機能**を、攻撃者が悪用できる状態のことです。典型的には、ログイン後に元のページへ戻すための \`next\` パラメータや、外部サイトへのリンクを中継する \`/redirect?url=\` が狙われます。

それ自体でデータが盗まれるわけではありません。問題は、**URLのドメインが正規サイトのまま**なのに、クリックした先が攻撃者のサイトになることです。メールのリンクを確認しても、フィルターの評判チェックを受けても、正規のドメインなので怪しく見えません。転送された先に本物そっくりのログイン画面を置けば、フィッシングが成立します。

この演習では、転送先の例にすべて予約ドメイン（\`evil.example\`）を使います。実在しないので、ブラウザは接続エラーを表示します。確認するのは、**サーバーが返す \`Location\` ヘッダーと、ブラウザの移動先**です。
`,
    steps: [
      {
        title: "通常の動作を確認する",
        body: "脆弱版のショップを開き、「マイページ（ログインが必要）へ」を押します。ログイン画面に、ログイン後の転送先（`Location`）が表示されます。「ログインして進む」で元のマイページに戻れることを確かめます。",
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "絶対URLで、別のサイトへ転送させる",
        body: "`next` に外部のURLを入れると、検証がないので、そのまま `Location` になります。ログイン画面の「ブラウザの移動先」が `evil.example`（別のサイト）になることを確かめてから、ボタンを押します。ブラウザが `evil.example` へ移動しようとして、接続エラーになるのは想定どおりです。",
        payloads: [{ label: "next", value: "https://evil.example/login" }],
        open: {
          label: "このペイロードで試す",
          href: "vuln/login?next=" + encodeURIComponent("https://evil.example/login"),
        },
      },
      {
        title: "外部リンク用の /redirect でも同じことが起きる",
        body: "ログインの戻り先だけでなく、外部リンクを中継する `/redirect?url=` も同じ作りです。このURLを開くと、サーバーが `Location: https://evil.example/login` を返します（開発者ツールの Network で確かめてください）。",
        payloads: [{ label: "url", value: "https://evil.example/login" }],
        open: {
          label: "このペイロードで試す",
          href: "vuln/redirect?url=" + encodeURIComponent("https://evil.example/login"),
        },
      },
      {
        title: "対策に失敗した例 (B) を破る",
        body: "(B) は「`/` で始まらない値は捨てる」検査です。手順2の絶対URLは確かに弾かれ、既定のマイページに戻ります。しかし、`//evil.example/login` や `/\\evil.example/login` は `/` で始まるので通ります。ブラウザは前者を「スキームを省略した別サイトのURL」、後者を（バックスラッシュをスラッシュ扱いして）同じく別サイトのURLとして解釈します。",
        payloads: [
          { label: "next（スキーム省略）", value: "//evil.example/login" },
          { label: "next（バックスラッシュ）", value: "/\\evil.example/login" },
        ],
        open: {
          label: "(B) に //evil.example を試す",
          href: "vuln/b/login?next=" + encodeURIComponent("//evil.example/login"),
        },
      },
      {
        title: "ホスト名の見せかけを調べる",
        body: "`https://example.com@evil.example/` を転送先チェッカーに入れます。`@` より前は認証情報（userinfo）で、**本当の宛先は `evil.example`** です。「`example.com` を含むか」「`https://example.com` で始まるか」といった文字列検査は、これで破られます。",
        payloads: [{ label: "チェッカーに入れる値", value: "https://example.com@evil.example/" }],
        open: {
          label: "転送先チェッカーで調べる",
          href: "vuln/inspect?value=" + encodeURIComponent("https://example.com@evil.example/"),
        },
      },
      {
        title: "攻撃者のメール（模擬）で通しで体験する",
        body: "攻撃者のページには、正規サイトのURLを使ったフィッシングメールがあります。リンクのドメインが正規のままであること、手口ごとに脆弱版 (A)、(B)、修正版の `Location` がどう変わるかを一覧で確かめられます。",
        open: { label: "攻撃者のメール（模擬）を開く", href: "/attacker/open-redirect/" },
      },
    ],
    cause: `
原因は、**転送先を決める入力値（\`next\` や \`url\`）を、検証せずに \`Location\` に使っていること**です。

- (A): 値をそのまま使います。攻撃者は、任意の外部URLを指定できます。
- (B): 「\`/\` で始まっていれば自サイトの相対パス」と考えて、先頭の1文字だけを見ています。しかしブラウザは、\`//evil.example/\` を別サイトのURLと解釈し、\`/\\evil.example/\` も、バックスラッシュをスラッシュとして扱って別サイトのURLと解釈します。

根っこは、**サーバーの文字列検査と、ブラウザのURLの解釈がずれている**ことです。文字列の見た目で判断すると、このずれを突かれます。
`,
    fix: `
修正の本命は、**転送先を、ブラウザと同じ規則で「解析してから」判断すること**です。\`new URL(next, 自分のオリジン)\` で解析し、次の2つを満たすときだけ採用します。

- 解析した結果のオリジンが、自分のオリジンと一致する
- 入力が \`/\` で始まり、\`//\` や \`/\\\` では始まらない（相対パスである）

それ以外は、既定のページ（マイページ）にフォールバックします。採用するときも、生の入力ではなく**解析済みの値**（パス + クエリ + ハッシュ）を返し、その結果が \`//\` で始まっていないかも確かめます（\`/..//evil.example\` は、ドットセグメントが取り除かれると \`//evil.example\` になるためです）。

外部のサイトへ行かせる必要があるときは、URLを受け取らず、**識別子で行き先を選ぶ許可リスト方式**にします（修正版の \`/go?site=partner\`）。許可リストに無い識別子は、既定のページに戻します。
`,
    verify: [
      "修正版の転送先チェッカーに、手順2〜5のペイロードと `/..//evil.example` をすべて入れる。`Location` がすべて既定のマイページになり、「ブラウザの移動先」が「このサイトの中」になる",
      "修正版のログイン画面に `next` として `https://evil.example/login` を渡す。「ログインして進む」を押しても、外部へは出ずマイページに戻る",
      "`next=/x/open-redirect/fixed/mypage` のような正当な相対パスは、そのまま採用される",
      "`/go?site=partner` は許可リストにある `partner.example` へ転送し、`/go?site=https://evil.example/` は既定のマイページに戻る",
    ],
    beyond: `
**フィッシングの踏み台になる仕組みです。** 攻撃者は、正規のドメインのURLを、メールやSNSで広めます。リンク先の評判チェックや、利用者の目視を通り抜けやすく、転送先の偽のログイン画面（「セッションが切れました」など）に誘導できます。ログイン直後に転送すると、利用者が警戒しにくい点も悪用されます。

**Referer にも注意します。** 外部へ転送すると、転送元のURL（\`next\` などのクエリ付き）が \`Referer\` として転送先に渡る可能性があります。トークンやセッションIDをURLに載せない、\`Referrer-Policy\` を設定する、といった対策が効きます（このラボは全ページに \`same-origin\`（外部へは Referer を送らない）を付けています）。

**外部への中継が必要なら、確認画面を挟む方法もあります。** 「外部サイトに移動します」と、転送先のURLを見せてから進ませる画面です。ユーザーに判断を委ねるので、フィッシングを完全には防げません。許可リストと併用する補助と考えてください。

**同じ問題は、OAuth の \`redirect_uri\` などにもあります。** 許可するURLは、完全一致で登録しておくのが基本です。また、\`Location\` に改行が混ざる問題は、HTTPヘッダインジェクションの演習で扱います。
`,
    quiz: [
      {
        q: "`startsWith(\"/\")` だけの検査は、なぜ破られるの？",
        a: "`/` で始まっていても、`//evil.example/` はスキームを省略した別サイトのURL、`/\\evil.example/` はバックスラッシュがスラッシュ扱いされて別サイトのURLになるからです。サーバーの文字列検査と、ブラウザのURL解釈がずれています。",
      },
      {
        q: "`https://example.com@evil.example/` は、どこへ転送される？ この値で、どんな検査が破られる？",
        a: "`evil.example` です。`@` より前は認証情報で、宛先ではありません。「`example.com` を含む」「`https://example.com` で始まる」といった文字列の検査が、この値で破られます。",
      },
      {
        q: "外部サイトへのリンクを中継する機能を、安全に作るには？",
        a: "URLそのものを受け取らず、`site=partner` のような識別子を受け取って、サーバー側の許可リストから転送先を引きます。リストに無い値は既定のページに戻します。URLを受け取る場合は、new URL() で解析してオリジンまで検証します。",
      },
    ],
  },
};
