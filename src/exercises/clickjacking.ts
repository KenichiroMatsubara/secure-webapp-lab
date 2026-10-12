import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * クリックジャッキング。
 *
 * 「プロフィールを公開する」ボタンのある設定ページを、攻撃者のページが透明な iframe で重ねる。
 *  - 脆弱版: どのサイトの iframe にも埋め込める（exercise の allowFramingOfVuln: true で、ガードも frame-ancestors を外す）
 *  - 修正版: frame-ancestors 'none' と X-Frame-Options: DENY で、ブラウザが埋め込みを拒否する
 *
 * ログインの手続きは省略し、学習者（lab_id Cookie）をそのまま「ログイン済みのユーザー」として扱う。
 * ただし iframe の中は第三者の文脈なので、ブラウザが第三者 Cookie をブロックすると lab_id も届かない（解説で触れる）。
 */

const ID = "clickjacking";
type Mode = "vuln" | "fixed";
type Ctx = Context<AppEnv>;

// iframe の表示領域（攻撃者ページ側）と、その中での「公開する」ボタンの位置。
// 設定ページはボタンを position: fixed で左下に置くので、ページの長さやフォントに関係なく、この数値で位置が決まる
const FRAME = { w: 560, h: 400 };
const BTN = { left: 20, bottom: 24, w: 280, h: 56 };
const BAIT_TOP = FRAME.h - BTN.bottom - BTN.h; // おとりのボタンの上端

async function isPublic(c: Ctx, mode: Mode): Promise<boolean> {
  const row = await c.var.db.first<{ is_public: number }>("SELECT is_public FROM clickjacking_state WHERE mode = ?", [
    mode,
  ]);
  return row?.is_public === 1;
}

function crossSiteNotice(c: Ctx): string {
  return c.var.crossSiteCookies
    ? ""
    : `<div class="notice notice--warn"><strong>この環境ではクロスサイトの再現ができません。</strong>
http で localhost 以外にアクセスしているため、学習者を見分ける <code>lab_id</code> Cookie が <code>SameSite=Lax</code> で発行されます。
攻撃者ページの iframe の中では Cookie が届かず、別の学習者として扱われるので、状態が共有されません。<code>http://localhost:8787</code> か https でアクセスしてください。</div>`;
}

/** 設定ページ（脆弱版・修正版で同じ見た目）。公開ボタンは左下に固定して、攻撃者ページの位置合わせを決め打ちにできるようにする */
function settingsPage(c: Ctx, mode: Mode, pub: boolean): string {
  const head = `<style>
.ex-main h1{font-size:1.25rem;margin:.1em 0 .3em}
.ex-main p{margin:.4em 0}
.ex-main{padding-bottom:${BTN.bottom + BTN.h + 24}px}
.cj-action{position:fixed;left:${BTN.left}px;bottom:${BTN.bottom}px;width:${BTN.w}px;height:${BTN.h}px;margin:0}
.cj-action button{width:100%;height:100%;font-size:1.05rem}
</style>`;
  const body = `<h1>アカウント設定</h1>
${crossSiteNotice(c)}
<p>ログイン中: <strong>alice</strong>（演習用のダミー。ログインの手続きは省略しています）</p>
<div class="result">
  <p>プロフィールの状態: <strong id="state">${pub ? "公開中" : "非公開"}</strong></p>
  <p>公開すると、あなたのプロフィールが誰にでも見えるようになります。</p>
</div>
<form method="post" action="/x/${ID}/${mode}/toggle-public" class="cj-action">
  <button type="submit">${pub ? "非公開に戻す" : "プロフィールを公開する"}</button>
</form>`;
  return exercisePage({ id: ID, mode, title: "アカウント設定", body, head });
}

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.get("/", async (c) => {
  const pub = await isPublic(c, "vuln");
  return c.html(settingsPage(c, "vuln", pub)); // [!] 埋め込みを拒否するヘッダー（frame-ancestors / X-Frame-Options）を付けていない
});

vuln.post("/toggle-public", async (c) => {
  await c.var.db.run("UPDATE clickjacking_state SET is_public = 1 - is_public WHERE mode = 'vuln'");
  return c.redirect(`/x/${ID}/vuln/`, 303);
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

// このページを、他のサイト（自分以外のオリジン）の iframe などに埋め込ませない
fixed.use("*", async (c, next) => {
  await next();
  c.res.headers.set("Content-Security-Policy", "frame-ancestors 'none'"); // 本命: 誰にも埋め込ませない
  c.res.headers.set("X-Frame-Options", "DENY"); // 古いブラウザ向けの併記
});

fixed.get("/", async (c) => {
  const pub = await isPublic(c, "fixed");
  return c.html(settingsPage(c, "fixed", pub));
});

fixed.post("/toggle-public", async (c) => {
  await c.var.db.run("UPDATE clickjacking_state SET is_public = 1 - is_public WHERE mode = 'fixed'");
  return c.redirect(`/x/${ID}/fixed/`, 303);
});
//#endregion

// ---- 攻撃者サイト役（/attacker/clickjacking）: 透明な iframe で公開ボタンを覆う ----
const attacker = new Hono<AppEnv>();

attacker.get("/", async (c) => {
  const rows = await c.var.db.all<{ mode: string; is_public: number }>(
    "SELECT mode, is_public FROM clickjacking_state ORDER BY mode DESC",
  );
  const css = `#victim {
  position: absolute; left: 0; top: 0;
  width: ${FRAME.w}px; height: ${FRAME.h}px;
  border: 0; opacity: 0; z-index: 2;   /* 透明にして、おとりの上に重ねる */
}
.bait-btn {
  position: absolute; left: ${BTN.left}px; top: ${BAIT_TOP}px;
  width: ${BTN.w}px; height: ${BTN.h}px;   /* 本物の公開ボタンと同じ位置・大きさ */
}`;

  const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>キャンペーンページ（模擬の攻撃者ページ）</title><link rel="stylesheet" href="/assets/lab.css">
<style>
.stage{position:relative;width:${FRAME.w}px;height:${FRAME.h}px;outline:1px dashed #888;background:#fff;margin:12px 0}
.bait{position:absolute;left:0;top:0;width:${FRAME.w}px;height:${FRAME.h}px;padding:20px 24px;color:#222;background:linear-gradient(135deg,#fff7e0,#ffe3e3)}
.bait h2{margin:0 0 .3em;border:0;font-size:1.3rem;color:#c2255c}
.bait p{margin:.3em 0;color:#333}
.bait-btn{position:absolute;left:${BTN.left}px;top:${BAIT_TOP}px;width:${BTN.w}px;height:${BTN.h}px;line-height:${BTN.h}px;text-align:center;background:#e8590c;color:#fff;border-radius:8px;font-weight:700;cursor:pointer}
#victim{position:absolute;left:0;top:0;width:${FRAME.w}px;height:${FRAME.h}px;border:0;z-index:2;opacity:.35;background:transparent}
.controls{display:flex;gap:10px 14px;align-items:center;flex-wrap:wrap;margin:10px 0}
.controls a{text-decoration:none}
.scroll-x{overflow-x:auto}
</style></head>
<body class="ex ex--guard"><main class="ex-main">
<div class="notice notice--warn">これは<strong>攻撃者側</strong>を演じる模擬ページです。ボタンは<strong>あなたが押したときだけ</strong>動き、実際には外部へ何も送られず、すべてこのラボの中で完結します。</div>
${crossSiteNotice(c)}
<h1>① おとりのページ</h1>
<p>下の枠は、攻撃者のキャンペーンページです。オレンジ色の「景品をもらう」ボタンの<strong>真上</strong>に、<strong>透明にした設定ページ</strong>（iframe）が重なっています。クリックは、一番手前にある iframe の中の本物のボタンに届きます。</p>
<div class="controls">
  <span>重ねるページ:</span>
  <a class="btn" href="/x/${ID}/vuln/" target="victim">脆弱版</a>
  <a class="btn btn--ghost" href="/x/${ID}/fixed/" target="victim">修正版</a>
  <span>透明度</span>
  <input type="range" id="op" min="0" max="100" value="35" aria-label="iframe の透明度">
  <span id="opv">35%</span>
  <button type="button" id="hide" class="ghost">完全に透明にする</button>
</div>
<div class="scroll-x"><div class="stage">
  <div class="bait">
    <h2>🎁 秋のプレゼントキャンペーン</h2>
    <p>アンケートにご協力いただいた方の中から、抽選で豪華景品をプレゼント！</p>
    <p>今すぐ下のボタンをクリックして、景品をもらいましょう。</p>
    <div class="bait-btn">ここをクリックして景品をもらう</div>
  </div>
  <iframe id="victim" name="victim" src="/x/${ID}/vuln/" scrolling="no" title="重ねている設定ページ"></iframe>
</div></div>
<p>透明度のスライダーで、重なっている設定ページを見えるようにできます。攻撃のときは<strong>完全に透明（0%）</strong>にします。</p>
<pre class="code"><code>${escapeHtml(css)}</code></pre>

<h2>② ラボ用の確認（攻撃者には見えない情報）</h2>
<p>プロフィールの公開状態です。脆弱版を重ねて「景品をもらう」を押すと、あなたは何も操作していないのに「公開」に変わります。</p>
${table(
  ["画面", "プロフィールの状態"],
  rows.map((r) => [r.mode === "vuln" ? "脆弱版" : "修正版", r.is_public ? "公開中" : "非公開"]),
)}
<p><a href="/attacker/${ID}/">状態を更新</a> / <a href="/x/${ID}">← 解説へ戻る</a></p>
</main>
<script>
(function () {
  var f = document.getElementById("victim");
  var s = document.getElementById("op");
  var v = document.getElementById("opv");
  function apply() { f.style.opacity = String(s.value / 100); v.textContent = s.value + "%"; }
  s.addEventListener("input", apply);
  document.getElementById("hide").addEventListener("click", function () { s.value = 0; apply(); });
  apply();
})();
</script>
</body></html>`;
  return c.html(html);
});

export const exercise: Exercise = {
  id: ID,
  title: "クリックジャッキング",
  summary: "透明にした正規サイトのボタンを、別のサイトのボタンの上に重ねて、ユーザー自身に押させる。",
  level: 2,
  book: { chapter: 4, topic: "重要な処理の際に混入する脆弱性（クリックジャッキング）" },
  schema: [`CREATE TABLE clickjacking_state (mode TEXT PRIMARY KEY, is_public INTEGER NOT NULL)`],
  seed: [
    `INSERT INTO clickjacking_state (mode, is_public) VALUES ('vuln', 0)`,
    `INSERT INTO clickjacking_state (mode, is_public) VALUES ('fixed', 0)`,
  ],
  vuln,
  fixed,
  attacker,
  // 脆弱版だけは iframe に埋め込めるようにする（ガードが脆弱版から frame-ancestors を外す）。修正版は埋め込めない
  allowFramingOfVuln: true,
  doc: {
    goals: [
      "クリックジャッキングの仕組み（透明なiframeを重ねて、別のものを押すつもりのクリックを横取りする）を説明できる",
      "frame-ancestors と X-Frame-Options で埋め込みを拒否する方法と、その関係を説明できる",
      "CSRFトークンでは防げない理由と、SameSite Cookie・再認証・確認画面の位置づけを説明できる",
    ],
    background: `
クリックジャッキングは、攻撃者のページの上に**正規サイトのページを透明にした iframe で重ね**、ユーザーに「別のものをクリックしている」と思わせて、正規サイトのボタンを押させる攻撃です。

ユーザーが実際に押すのは、**正規サイトの本物のボタン**です。ブラウザは通常どおり Cookie を付け、正規の画面から正規のリクエストが送られます。そのため、サーバー側から見ると、普通の操作と区別がつきません。CSRFトークンの確認も、そのまま通ってしまいます。

被害の対象は、ボタン1つで完了する操作です（公開設定の変更、いいね・フォロー、購入の確定、設定の切り替えなど）。

この演習では、「プロフィールを公開する」ボタンのある設定ページを、攻撃者のキャンペーンページ（模擬）が重ねます。
`,
    steps: [
      {
        title: "脆弱版の通常の動きを確かめる",
        body: "脆弱版の設定ページを開き、「プロフィールを公開する」を押して「公開中」になることを確かめます。確かめたら「非公開に戻す」を押して、非公開に戻しておきます。ボタンは画面の左下に固定してあります（あとで位置合わせに使います）。",
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "攻撃者のページで、重なりを見る",
        body: "攻撃者のページ（模擬）を開きます。透明度のスライダーが35%の状態で、オレンジ色の「景品をもらう」ボタンの真上に、設定ページの公開ボタンが薄く重なって見えます。おとりのボタンと本物のボタンは、同じ位置・同じ大きさに合わせてあります。\n\n**ブラウザが第三者Cookieをブロックしている場合**、iframeの中は別の学習者として扱われ、状態が変わりません。その場合は、ブロックを外した通常のウィンドウで試してください。",
        open: { label: "攻撃者のページ（模擬）を開く", href: "/attacker/clickjacking/" },
      },
      {
        title: "完全に透明にして、おとりのボタンを押す",
        body: "「完全に透明にする」を押すと、見た目はキャンペーンページだけになります。ここで「ここをクリックして景品をもらう」を押してください。実際にクリックされたのは、透明なiframeの中の公開ボタンです。ページ下の「ラボ用の確認」で「状態を更新」を押すと、脆弱版が「公開中」に変わっています。",
      },
      {
        title: "仕組みを開発者ツールで確かめる",
        body: "スライダーを100%にすると、iframeが本物の設定ページとして一番手前に見えます。開発者ツールで `iframe` 要素を選び、`opacity` と `z-index` を確認します。ページ内のCSS（`position: absolute` と数値の位置合わせ）が、そのまま攻撃の道具になっています。",
      },
      {
        title: "修正版を重ねてみる",
        body: "攻撃者のページの「修正版」ボタンを押して、iframeを修正版に切り替えます。ブラウザは埋め込みを拒否し、iframeは設定ページの代わりにエラー表示（または空白）になります。おとりのボタンを押しても、修正版の状態は変わりません。",
      },
    ],
    cause: `
原因は、**設定ページが「他のサイトの iframe に埋め込まれてもよい」状態で配信されていること**です。ハイライトした行のレスポンスには、埋め込みを制限するヘッダー（\`frame-ancestors\` を含む CSP や \`X-Frame-Options\`）がありません。

ブラウザは、埋め込みを禁止する指示がなければ、どのサイトのページにもそのページを埋め込ませます。攻撃者のページが iframe にして透明にしても、サーバーはそれを知りません。

なお、このラボのガードは、安全のため通常は脆弱版にも \`frame-ancestors\` を付けています。この演習だけは、ガードが脆弱版から外すように設定してあります（\`allowFramingOfVuln\`）。
`,
    fix: `
修正の本命は、**ページごとに「どのサイトに埋め込まれてよいか」を宣言すること**です。

- \`Content-Security-Policy: frame-ancestors 'none'\` … このページを埋め込める親を「なし」にします。自分のサイトだけに許すなら \`'self'\`、提携先に許すなら \`'self' https://partner.example\` のようにオリジンを並べます。
- \`X-Frame-Options: DENY\` … 同じ目的の古いヘッダーです。\`frame-ancestors\` に対応していない古いブラウザのために併記します。

これで、ブラウザが iframe への埋め込みを拒否します。攻撃者のページは、設定ページを重ねる手段そのものを失います。
`,
    verify: [
      "修正版のレスポンスヘッダー（開発者ツールの Network）に、`Content-Security-Policy: frame-ancestors 'none'` と `X-Frame-Options: DENY` が付いている",
      "攻撃者のページで「修正版」を重ねると、iframe が設定ページを表示しない。開発者ツールのコンソールに、フレーム内での表示を拒否した旨のエラーが出る",
      "「ここをクリックして景品をもらう」を押しても、修正版の状態は「非公開」のまま変わらない",
      "修正版のページを直接開けば、これまでどおりボタンで操作できる（埋め込みだけが拒否される）",
    ],
    beyond: `
**frame-ancestors と X-Frame-Options は、同じ目的の新旧2つの仕組みです。** \`frame-ancestors\` は複数のオリジンを書け、CSP の一部として管理できます。\`X-Frame-Options\` は \`DENY\` と \`SAMEORIGIN\` の簡単な指定が中心です。両方が付いているとき、\`frame-ancestors\` に対応したブラウザは \`frame-ancestors\` を優先します。新しい仕組みを本命にして、古いヘッダーを併記しておくのが無難です。

**SameSite Cookie が緩和することもあります。** 別のサイトに埋め込まれた iframe からのリクエストには、\`SameSite=Lax\` や \`Strict\` の Cookie が付かないため、iframe の中は「未ログイン」の画面になり、攻撃が成立しません。ただし、\`SameSite=None\` の Cookie や、同じサイトの別サブドメインから埋め込まれた場合には効きません。これを本命にはせず、埋め込み拒否の保険として考えます。

**重要な操作は、ボタン1回で完了させない設計にします。** 現在のパスワードの再入力や、確認画面での明示的な承認を挟めば、透明なボタンを1回押させるだけでは完了しません。入力欄に文字を打たせる、ドラッグさせるなど複数の操作を誘導するのは難しいからです。

**JavaScript による「フレームの中なら自分で抜け出す」処理（フレームバスター）は頼りになりません。** 攻撃者は、iframe の \`sandbox\` 属性などで、そのスクリプトを無効にできます。

**CSRFトークンはクリックジャッキングを防ぎません。** ユーザー自身が正規の画面でトークン付きのフォームを送るためです。CSRFの演習とあわせて、別々の対策が必要であることを確かめてください。なお、この演習の設定ページには、CSRF対策を入れていません。
`,
    quiz: [
      {
        q: "frame-ancestors と X-Frame-Options は、どういう関係？",
        a: "どちらも「このページを他のページに埋め込んでよいか」を指示するものです。frame-ancestors が新しい仕組みで、複数のオリジンを指定でき、対応ブラウザでは X-Frame-Options より優先されます。X-Frame-Options は古いブラウザ向けに併記します。",
      },
      {
        q: "CSRFトークンを入れているサイトでも、クリックジャッキングが成立するのはなぜ？",
        a: "押されるのは正規のページ上の正規のボタンで、トークンも正規のフォームに入ったまま送られるからです。サーバーは普通の操作と区別できません。埋め込み自体を拒否するか、操作を再認証などで守る必要があります。",
      },
      {
        q: "SameSite=Lax の Cookie にしておけば、クリックジャッキングは防げる？",
        a: "完全には防げません。別サイトの iframe の中ではLaxのCookieが付かず、未ログインの画面になるので多くの場合は止まります。しかし、Cookieが SameSite=None の場合や、同一サイト（別サブドメイン）から埋め込まれる場合は効きません。frame-ancestors で埋め込みを拒否するのが本命です。",
      },
    ],
  },
};
