import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import type { AppEnv } from "../env";
import { exercisePage } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * DOM Based XSS。
 *
 * サーバーは、URL がどうであっても「まったく同じ」安全なHTMLを返す。URL の値を読んで画面に出すのは、
 * ブラウザ側の JavaScript だけ。だから脆弱性はサーバーのコードではなく、サーバーが配るブラウザ側のコードにある。
 *
 *  - 脆弱版: ページ内のインラインスクリプトが、location.hash を innerHTML に、?back= の値を a.href に渡す
 *  - 修正版: 外部スクリプト /x/xss-dom/fixed/app.js が textContent を使い、戻り先を URL として検証する。
 *            CSP でインラインスクリプトを禁止し、Trusted Types で innerHTML への文字列代入もエラーにする
 *
 * ブラウザ側のコードは文字列の配列として持つ（各行の末尾の `// [!]` は、サーバー側の TypeScript のコメントなので、
 * 配信されるページには漏れない）。テストは、配信された同じコードを疑似DOMの上で動かして確かめる。
 */

const ID = "xss-dom";

// 脆弱版・修正版で同じ、サーバーが返すHTMLの本文。URL の # や ?back= の値は、ここには一切入らない
const pageBody = `<h1>会員ページ</h1>
<p>URL の <code>#</code> のあとに名前を付けて開くと、あいさつが変わります（例: <code>#たろう</code>）。</p>
<div class="result"><p id="greeting">読み込み中…</p></div>
<p><a id="back" href="/">戻る</a></p>
<p id="note" class="ng"></p>
<h2>このページのしくみ</h2>
<ul>
<li>サーバーは、URL がどうであっても<strong>まったく同じHTML</strong>を返します（「ページのソースを表示」で確かめられます）。</li>
<li>あいさつの名前と、「戻る」リンクの行き先（<code>?back=</code> の値）は、ブラウザ側の JavaScript が URL を読んで書き換えています。</li>
</ul>`;

//#region vuln
const vuln = new Hono<AppEnv>();

// ブラウザで動くコード（ページ内のインラインスクリプト）。サーバーは URL の # や ?back= を一切読まない
const inlineScript = [
  `function readHash() {`,
  `  try { return decodeURIComponent(location.hash.slice(1)); } catch (e) { return ""; }`,
  `}`,
  `function render() {`,
  `  var who = readHash() || "ゲスト";`,
  `  document.getElementById("greeting").innerHTML = "ようこそ、" + who + "さん";`, // [!] URLのハッシュ（攻撃者が決められる値）をHTMLとして解釈される innerHTML に代入している
  `}`,
  `render();`,
  `window.addEventListener("hashchange", render);`,
  ``,
  `var backTo = new URLSearchParams(location.search).get("back") || "/";`,
  `document.getElementById("back").href = backTo;`, // [!] ?back= の値を検証せず href に代入。javascript: で始まる値でも通る
].join("\n");

vuln.get("/", (c) => {
  // 学習用のダミーCookie。JavaScriptから読める（HttpOnlyなし）ので、XSSで盗めることを体験できる
  setCookie(c, "demo_secret", "SESSION-DEMO-1234", { path: "/" });

  const body = `${pageBody}\n<script>\n${inlineScript}\n</script>`;
  return c.html(exercisePage({ id: ID, mode: "vuln", title: "会員ページ", body }));
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

// 多層防御: インラインスクリプトを実行させず、innerHTML などへの文字列の代入もブラウザに止めさせる（Trusted Types）
fixed.use("*", async (c, next) => {
  await next();
  c.res.headers.set(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'",
  );
});

// 戻り先として安全かを判定する関数（ブラウザ側のコード）。http / https で、かつ同じオリジンのときだけ URL を返す
const safeBackHrefSource = [
  `function safeBackHref(value, origin) {`,
  `  try {`,
  `    var url = new URL(value, origin);`,
  `    var isWeb = url.protocol === "http:" || url.protocol === "https:";`,
  `    return isWeb && url.origin === origin ? url.href : null;`,
  `  } catch (e) {`,
  `    return null;`,
  `  }`,
  `}`,
].join("\n");

// ブラウザで動くコード（外部スクリプト /x/xss-dom/fixed/app.js）。画面に値を出すのは textContent だけ
const appJs = [
  `"use strict";`,
  safeBackHrefSource,
  ``,
  `function readHash() {`,
  `  try { return decodeURIComponent(location.hash.slice(1)); } catch (e) { return ""; }`,
  `}`,
  `function render() {`,
  `  var who = readHash() || "ゲスト";`,
  `  document.getElementById("greeting").textContent = "ようこそ、" + who + "さん";`,
  `}`,
  `render();`,
  `window.addEventListener("hashchange", render);`,
  ``,
  `var backTo = new URLSearchParams(location.search).get("back") || "/";`,
  `var safeHref = safeBackHref(backTo, location.origin);`,
  `document.getElementById("back").href = safeHref || "/";`,
  `document.getElementById("note").textContent = safeHref ? "" : "戻り先が不正なため、トップページに置き換えました。";`,
].join("\n");

fixed.get("/app.js", (c) => c.body(appJs, 200, { "Content-Type": "text/javascript; charset=UTF-8" }));

fixed.get("/", (c) => {
  // HttpOnly を付けると JavaScript から読めなくなり、XSS で盗まれにくくなる
  setCookie(c, "demo_secret", "SESSION-DEMO-1234", { path: "/", httpOnly: true, sameSite: "Lax" });

  // インラインスクリプトは書かない。同じオリジンの外部ファイルとして読み込む
  const head = `<script src="/x/${ID}/fixed/app.js" defer></script>`;
  return c.html(exercisePage({ id: ID, mode: "fixed", title: "会員ページ", body: pageBody, head }));
});
//#endregion

/** ハッシュに入れて渡す文字列（# のあとに付ける） */
const hashLink = (value: string) => `vuln/#${encodeURIComponent(value)}`;
const IMG_PAYLOAD = "<img src=x onerror=alert(document.domain)>";
const BACK_PAYLOAD = "javascript:alert(1)";

export const exercise: Exercise = {
  id: ID,
  title: "DOM Based XSS",
  summary: "サーバーは安全なHTMLを返しているのに、ブラウザ側のJavaScriptがURLの値を危険な場所に渡して攻撃が成立する。",
  level: 2,
  book: { chapter: 4, topic: "JavaScriptの問題 / 表示処理に伴う問題" },
  vuln,
  fixed,
  doc: {
    goals: [
      "DOM Based XSSが、サーバーのHTMLが安全でも、ブラウザ側のJavaScriptの書き方だけで成立することを説明できる",
      "コードの中から、攻撃者が決められる入力（source）と、危険な出力先（sink）の組み合わせを見つけられる",
      "対策の本命は「HTMLとして解釈させない書き方（textContent）」と「URLの許可リスト検証」で、CSPとTrusted Typesは保険だと位置づけられる",
    ],
    background: `
DOM Based XSSは、**ブラウザの中で動くJavaScript**が、攻撃者の決められる値を危険な場所に渡すことで起きるXSSです。サーバーが返すHTMLには危険な値が一切含まれていません。

コードを読むときは、次の2つの組み合わせを探します。

- **入力の入り口（source）**: 攻撃者が値を決められる場所です。\`location.hash\`（URLの \`#\` 以降）、\`location.search\`（\`?\` 以降）、\`document.referrer\`、\`window.name\`、\`postMessage\` で受け取ったデータなどです。
- **危険な出力先（sink）**: 渡された値をHTML・URL・コードとして解釈してしまう場所です。\`innerHTML\`、\`document.write\`、\`eval\`、\`a.href\` や \`location\` への代入などです。

反射型・格納型との違いは、**HTMLを組み立てているのがブラウザ側**だという点です。サーバー側でエスケープを徹底しても、このコードは防げません。特にURLの \`#\` 以降は、ブラウザからサーバーへ**送られません**。サーバーのログにも、WAF（Webアプリケーションファイアウォール）にも、攻撃は見えないのです。
`,
    steps: [
      {
        title: "ふつうの動作を確認する",
        body: "脆弱版を、URLの末尾に `#` と名前を付けて開きます。「ようこそ、○○さん」と表示されます。ページ内の「戻る」リンクの行き先は、`?back=` の値で変わります。",
        payloads: [{ label: "URLの末尾（# から）", value: "#たろう" }],
        open: { label: "#たろう で開く", href: hashLink("たろう") },
      },
      {
        title: "入力がHTMLとして解釈されることを確かめる",
        body: "名前の代わりにHTMLタグを入れます。太字で表示されれば、値が `innerHTML` を通ってHTMLとして解釈されている証拠です。なお、ブラウザは `#` 以降の `<` や `>` を自動で `%3C` `%3E` に変えることがありますが、ページ側が `decodeURIComponent` で戻すので結果は同じです。",
        payloads: [{ label: "URLの末尾（# から）", value: "#<b>太字</b>" }],
        open: { label: "このペイロードで試す", href: hashLink("<b>太字</b>") },
      },
      {
        title: "ハッシュからスクリプトを実行させる",
        body: "`innerHTML` で入れた `<script>` は実行されない決まりなので、存在しない画像を読み込ませて、失敗したときの `onerror` を使います。ダイアログにドメインが出れば、攻撃者の書いたスクリプトが、このサイトの権限（オリジン）で動いたということです。",
        payloads: [
          {
            label: "URLの末尾（# から）",
            value: "#" + IMG_PAYLOAD,
            note: "/x/xss-dom/vuln/ の後ろに付けて開く。すでにこのページを開いているなら、ハッシュだけ書き換えて Enter でもよい",
          },
        ],
        open: { label: "このペイロードで試す", href: hashLink(IMG_PAYLOAD) },
      },
      {
        title: "?back= から javascript: URL を動かす",
        body: "「戻る」リンクの行き先に `javascript:` で始まる値を渡します。リンクは `href` に入っただけなので、**クリックしたとき**にスクリプトが動きます。",
        payloads: [{ label: "URLの末尾（? から）", value: "?back=" + BACK_PAYLOAD }],
        open: { label: "このペイロードで試す", href: "vuln/?back=" + encodeURIComponent(BACK_PAYLOAD) },
      },
      {
        title: "サーバーのHTMLに、危険な値がないことを確かめる",
        body: "手順3のURLを開いたまま、ブラウザの「ページのソースを表示」（`view-source:`）を開きます。ソースには、`<img src=x onerror=…>` も `javascript:alert(1)` も**どこにもありません**。サーバーは毎回同じHTMLを返しているだけです。いっぽう開発者ツールの「要素」タブを見ると、画面上のDOMには `<img>` が作られています。\n\nつまり、サーバー側でどれだけ丁寧にエスケープしても、この脆弱性は防げません。原因は、サーバーが送ってきた**JavaScriptの書き方**にあります。",
        open: { label: "手順3のURLで開く", href: hashLink(IMG_PAYLOAD) },
      },
    ],
    cause: `
原因は、**ブラウザ側のコードが、URLから読んだ値をそのまま危険な出力先に渡していること**です。ハイライトした2行が問題です。

- 1行目: \`location.hash\` から読んだ名前を \`innerHTML\` に代入しています。\`innerHTML\` は文字列をHTMLとして解釈するので、\`<img onerror=…>\` が本物の要素になり、イベントハンドラが動きます。
- 2行目: \`?back=\` の値を確かめずに \`a.href\` に代入しています。\`javascript:\` で始まる値も、そのままリンクの行き先になります。

どちらも「このURLは自分のサイトが作ったものだろう」という思い込みが原因です。URLは、リンクを送る人が自由に作れます。名前を表示するだけ、リンクを作るだけという、ありふれた処理に脆弱性が潜んでいます。
`,
    fix: `
修正の本命は2つです。

- **HTMLとして解釈させる必要がない値は、\`textContent\` で入れる。** \`textContent\` は、渡された文字列を単なる文字として扱います。\`<img …>\` と書かれていても、画面にはその文字がそのまま出るだけです。
- **URLは、文字列のまま使わず、\`new URL()\` で解析して許可リストで検証する。** \`http:\` か \`https:\` で、しかも同じオリジンのときだけ \`href\` に入れます。これなら \`javascript:\` も、別サイトへの転送も入りません。\`javascript:\` で始まるかを文字列で調べる方法（禁止リスト）は、大文字小文字や空白の混ぜ方で回避されやすいので使いません。

あわせて、書き間違いが将来入っても被害を抑える保険を、2つ入れています。

- **CSPでインラインスクリプトを禁止する。** そのために、スクリプトをページの外の \`app.js\`（同じオリジンの外部ファイル）に移しました。仮に \`<img onerror=…>\` が作られても、インラインのイベントハンドラは実行されません。
- **Trusted Types（\`require-trusted-types-for 'script'\`）。** この指定があると、\`innerHTML\` や \`document.write\`、\`eval\` などに、ただの文字列を渡した時点でブラウザが例外を出して止めます。HTMLを入れる必要があるときは、サニタイズした結果だけを返す「ポリシー」を通した特別な値でなければ渡せません。\`innerHTML = 入力値\` と書いてしまうミスを、実行前に見つけられます。
`,
    verify: [
      "修正版で、手順2〜4のペイロードをそのまま試す。名前は `<img …>` という文字のまま表示され、ダイアログは出ない",
      "修正版で `?back=javascript:alert(1)` を開く。エラー表示が出て、「戻る」リンクはトップページ（`/`）になり、クリックしてもスクリプトは動かない",
      "修正版で、同じオリジンの `?back=/about` を開く。「戻る」リンクの行き先が `/about` になる（正当な使い方は動く）",
      "「ページのソースを表示」で、修正版にはインラインの `<script>` がなく、`app.js` を読み込んでいることを確かめる。`app.js` の中身を開いて、`innerHTML` が使われていないことも見る",
      "（Chrome や Edge で）開発者ツールのコンソールに `document.body.innerHTML = 'x'` と入力する。Trusted Types のエラーになる。応答ヘッダーに `Content-Security-Policy` が付いていることも確かめる",
    ],
    beyond: `
**DOM Based XSSは、サーバー側の検査では見つかりません。** 攻撃の値がサーバーに届かないことがあるので、ログやWAFに頼れません。ブラウザ側のコードで \`innerHTML\`、\`outerHTML\`、\`insertAdjacentHTML\`、\`document.write\`、\`eval\`、\`setTimeout\` に文字列を渡す書き方、\`location\` や \`href\` への代入を検索し、そこへ渡る値のもとをたどるのが基本です。ライブラリのHTMLを挿入する機能（jQueryの \`.html()\` など）や、フレームワークの生HTML出力機能（Reactの \`dangerouslySetInnerHTML\`、Vueの \`v-html\` など）も同じ仲間です。

**HTMLとして出す必要があるときは、サニタイザを使います。** 許可するタグと属性を決めて処理してくれる実績のあるライブラリで無害化し、その結果だけをTrusted Typesのポリシー経由で入れます。自作の正規表現でタグを除く方法は、回避されがちです。

**CSPとTrusted Typesは保険です。** 特にTrusted Typesはブラウザによって対応状況に差があり、対応していないブラウザではヘッダーが無視されるだけで何も起きません。\`textContent\` やURL検証という本命の対策は必須です。インラインスクリプトをなくす作業は、既存のアプリでは手間がかかるものの、それ自体が被害を減らします。

同じ原因（値をHTMLやURLとして解釈される場所に渡す）が、反射型XSS・格納型XSSの演習や、オープンリダイレクトの演習にも出てきます。
`,
    quiz: [
      {
        q: "サーバー側で `<` と `>` をエスケープして返すようにしても、脆弱版のハッシュを使った攻撃を防げないのはなぜ？",
        a: "`#` 以降はブラウザからサーバーに送られませんし、サーバーが返すHTMLにも攻撃の値は入っていないからです。値をHTMLとして解釈させているのは、ブラウザ側のJavaScript（`innerHTML` への代入）なので、直すのもそのコードです。",
      },
      {
        q: "`#<script>alert(1)</script>` は動かないのに、`#<img src=x onerror=alert(1)>` は動くのはなぜ？",
        a: "`innerHTML` で挿入した `<script>` 要素は、仕様上実行されないからです。いっぽう `<img>` は挿入されると画像を読みに行き、失敗すると `onerror` の中身が実行されます。`<script>` が動かないからといって安全だとは言えません。",
      },
      {
        q: "戻り先の検証は、`javascript:` で始まるかを調べるより、`new URL()` で解析して許可リストで決めるほうがよいのはなぜ？",
        a: "`JaVaScRiPt:` のような大文字小文字の混在や、先頭の空白、途中のタブや改行などで、文字列の判定をすり抜けられるからです。`new URL()` でブラウザと同じ規則で解析してから、`http:` と `https:` だけを許可し、さらに同じオリジンに限れば、想定外の形式をまとめて拒否できます。",
      },
    ],
  },
};
