import { Hono } from "hono";
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * CSRF（クロスサイト・リクエスト・フォージェリ）。
 *
 * ログイン → マイページでメールアドレスを変更する、という小さなアプリ。
 *  - 脆弱版: Cookie だけで「本人の操作」とみなす。Cookie は SameSite=None なので他サイトからの POST にも付く
 *  - 修正版: セッションに紐づく CSRF トークン + Origin 検証 + SameSite=Lax
 * 攻撃者ページ（/attacker/csrf/）は CSP sandbox で Origin: null のクロスサイトになり、ボタンを押すと脆弱版へ POST する。
 */

const ID = "csrf";
type Mode = "vuln" | "fixed";
type Ctx = Context<AppEnv>;

const HINT_USER = "alice";
const HINT_PASS = "alice-pass";
const ATTACKER_EMAIL = "attacker@evil.example";
const SID_RE = /^[0-9a-f]{32}$/;

function randomHex(bytes: number): string {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

interface Sess {
  sid: string;
  username: string;
  csrf_token: string | null;
}

/** Cookie のセッションIDからセッションを引く（脆弱版と修正版は mode で分けているので、お互いの Cookie は使えない） */
async function findSession(c: Ctx, mode: Mode, cookieName: string): Promise<Sess | null> {
  const sid = getCookie(c, cookieName);
  if (!sid || !SID_RE.test(sid)) return null;
  return c.var.db.first<Sess>("SELECT sid, username, csrf_token FROM csrf_sessions WHERE sid = ? AND mode = ?", [
    sid,
    mode,
  ]);
}

/** ログインフォームの値を確かめ、成功したらユーザー名を返す（パスワードの保存方法は別の演習で扱うので、ここでは素朴に比べる） */
async function checkLogin(c: Ctx, mode: Mode): Promise<string | null> {
  const form = await c.req.parseBody();
  const row = await c.var.db.first<{ username: string }>(
    "SELECT username FROM csrf_users WHERE mode = ? AND username = ? AND password = ?",
    [mode, String(form["username"] ?? ""), String(form["password"] ?? "")],
  );
  return row ? row.username : null;
}

async function emailOf(c: Ctx, mode: Mode, username: string): Promise<string> {
  const row = await c.var.db.first<{ email: string }>("SELECT email FROM csrf_users WHERE mode = ? AND username = ?", [
    mode,
    username,
  ]);
  return row?.email ?? "";
}

function validEmail(s: string): boolean {
  return s.length > 0 && s.length <= 100 && /^[^\s@<>"']+@[^\s@<>"']+$/.test(s);
}

// ---- 画面（脆弱版・修正版で共通の部分） ----
function crossSiteNotice(c: Ctx, mode: Mode): string {
  if (mode !== "vuln" || c.var.crossSiteCookies) return "";
  return `<div class="notice notice--warn"><strong>この環境ではクロスサイトの再現ができません。</strong>
http で localhost 以外のホストにアクセスしているため、<code>SameSite=None; Secure</code> の Cookie を使えず、脆弱版の Cookie も <code>SameSite=Lax</code> で発行しています。
攻撃者ページからの送信には Cookie が付かないので、攻撃は「未ログイン扱い」で止まります。<code>http://localhost:8787</code> か https でアクセスしてください。</div>`;
}

function loginView(c: Ctx, mode: Mode, error = ""): string {
  const base = `/x/${ID}/${mode}`;
  const body = `<h1>会員サイト（ログイン）</h1>
${crossSiteNotice(c, mode)}
${error ? `<p class="ng">${escapeHtml(error)}</p>` : ""}
<form method="post" action="${base}/login">
  <label for="u">ユーザー名</label><input id="u" name="username" value="${HINT_USER}" autocomplete="off">
  <label for="p">パスワード</label><input id="p" type="password" name="password" autocomplete="off">
  <p><button type="submit">ログイン</button></p>
</form>
<p>ヒント: ユーザー名 <code>${HINT_USER}</code> / パスワード <code>${HINT_PASS}</code>（演習用のダミーです）</p>`;
  return exercisePage({ id: ID, mode, title: "ログイン", body });
}

function mypageView(c: Ctx, mode: Mode, s: Sess, email: string, form: string, note = ""): string {
  const base = `/x/${ID}/${mode}`;
  const body = `<h1>マイページ</h1>
${crossSiteNotice(c, mode)}
<div class="result">
  <p>ログイン中: <strong>${escapeHtml(s.username)}</strong></p>
  <p>登録メールアドレス: <strong id="current-email">${escapeHtml(email)}</strong></p>
</div>
<h2>メールアドレスの変更</h2>
${note}
${form}
<form method="post" action="${base}/logout" class="actions"><button type="submit" class="ghost">ログアウト</button></form>`;
  return exercisePage({ id: ID, mode, title: "マイページ", body });
}

function notLoggedInView(mode: Mode): string {
  const body = `<h1>401 ログインしていません</h1>
<p class="ng">このリクエストには、ログイン済みであることを示す Cookie が付いていませんでした。</p>
<p>攻撃者ページから送った場合は、<code>SameSite</code> の働きでブラウザが Cookie を付けなかったことを意味します（未ログイン扱いで止まりました）。</p>
<p><a href="/x/${ID}/${mode}/">ログイン画面へ</a></p>`;
  return exercisePage({ id: ID, mode, title: "未ログイン", body });
}

function badEmailView(mode: Mode): string {
  const body = `<h1>400 メールアドレスの形式が正しくありません</h1><p><a href="/x/${ID}/${mode}/">マイページへ戻る</a></p>`;
  return exercisePage({ id: ID, mode, title: "入力エラー", body });
}

//#region vuln
const vuln = new Hono<AppEnv>();
const VULN_BASE = `/x/${ID}/vuln`;
const VULN_COOKIE = "csrf_vuln_sid";

vuln.get("/", async (c) => {
  const s = await findSession(c, "vuln", VULN_COOKIE);
  if (!s) return c.html(loginView(c, "vuln"));
  const email = await emailOf(c, "vuln", s.username);
  const form = `<form method="post" action="${VULN_BASE}/change-email">
  <label for="e">新しいメールアドレス</label><input id="e" type="email" name="email" value="${escapeHtml(email)}" required>
  <p><button type="submit">変更する</button></p>
</form>`;
  return c.html(mypageView(c, "vuln", s, email, form));
});

vuln.post("/login", async (c) => {
  const user = await checkLogin(c, "vuln");
  if (!user) return c.html(loginView(c, "vuln", "ユーザー名またはパスワードが違います"), 401);
  const sid = randomHex(16);
  await c.var.db.run("INSERT INTO csrf_sessions (sid, mode, username, csrf_token) VALUES (?, 'vuln', ?, NULL)", [
    sid,
    user,
  ]);
  const crossSite = c.var.crossSiteCookies;
  setCookie(c, VULN_COOKIE, sid, {
    path: VULN_BASE,
    httpOnly: true,
    maxAge: 3600,
    sameSite: crossSite ? "None" : "Lax", // [!] SameSite=None: 他のサイトのページが始めた POST にも Cookie が付く
    secure: crossSite,
  });
  return c.redirect(`${VULN_BASE}/`, 303);
});

vuln.post("/change-email", async (c) => {
  const s = await findSession(c, "vuln", VULN_COOKIE);
  if (!s) return c.html(notLoggedInView("vuln"), 401);
  const email = String((await c.req.parseBody())["email"] ?? "");
  if (!validEmail(email)) return c.html(badEmailView("vuln"), 400);
  await c.var.db.run("UPDATE csrf_users SET email = ? WHERE mode = 'vuln' AND username = ?", [email, s.username]); // [!] Cookie があるだけで本人の操作とみなす（トークンも Origin の確認もない）
  return c.redirect(`${VULN_BASE}/`, 303);
});

vuln.post("/logout", async (c) => {
  const s = await findSession(c, "vuln", VULN_COOKIE);
  if (s) await c.var.db.run("DELETE FROM csrf_sessions WHERE sid = ?", [s.sid]);
  deleteCookie(c, VULN_COOKIE, { path: VULN_BASE });
  return c.redirect(`${VULN_BASE}/`, 303);
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();
const FIXED_BASE = `/x/${ID}/fixed`;
const FIXED_COOKIE = "csrf_fixed_sid";

// 定数時間比較: 長さが同じなら必ず最後まで比べ、最初の不一致で return しない（応答時間からトークンを推測させない）
function safeEqual(a: string, b: string): boolean {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

function forbiddenView(reason: string, detail: string): string {
  const body = `<h1>403 リクエストを拒否しました</h1>
<p class="ng">${escapeHtml(reason)}</p>
<p>${escapeHtml(detail)}</p>
<p><a href="${FIXED_BASE}/">マイページへ戻る</a></p>`;
  return exercisePage({ id: ID, mode: "fixed", title: "拒否しました", body });
}

// 1枚目: 状態を変えるリクエスト（POST など）は、Origin が「このサイト自身」のときだけ通す
fixed.use("*", async (c, next) => {
  if (c.req.method !== "GET" && c.req.method !== "HEAD") {
    const origin = c.req.header("Origin"); // 他サイトのページからの送信では、別のオリジンか "null" になる
    const self = new URL(c.req.url).origin;
    if (origin !== undefined && origin !== self) {
      const hadCookie = getCookie(c, FIXED_COOKIE) !== undefined;
      return c.html(
        forbiddenView(
          `Origin ヘッダー（${origin}）が、このサイトのオリジン（${self}）と一致しません。`,
          hadCookie
            ? "このリクエストにはセッション Cookie が付いていました。Origin 検証がなければ、トークンの確認まで進んでいました。"
            : "このリクエストにはセッション Cookie が付いていませんでした（SameSite=Lax により、ブラウザが他サイトからの POST には Cookie を付けなかったと考えられます）。",
        ),
        403,
      );
    }
  }
  await next();
});

fixed.get("/", async (c) => {
  const s = await findSession(c, "fixed", FIXED_COOKIE);
  if (!s) return c.html(loginView(c, "fixed"));
  const email = await emailOf(c, "fixed", s.username);
  const form = `<form method="post" action="${FIXED_BASE}/change-email">
  <input type="hidden" name="csrf_token" value="${escapeHtml(s.csrf_token ?? "")}">
  <label for="e">新しいメールアドレス</label><input id="e" type="email" name="email" value="${escapeHtml(email)}" required>
  <p><button type="submit">変更する</button></p>
</form>`;
  const note = `<p class="lede">このフォームには、あなたのセッション専用の <code>csrf_token</code> が hidden 項目として入っています（開発者ツールで確かめられます）。</p>`;
  return c.html(mypageView(c, "fixed", s, email, form, note));
});

fixed.post("/login", async (c) => {
  const user = await checkLogin(c, "fixed");
  if (!user) return c.html(loginView(c, "fixed", "ユーザー名またはパスワードが違います"), 401);
  const sid = randomHex(16);
  const token = randomHex(32); // 256bit の乱数。推測できない
  await c.var.db.run("INSERT INTO csrf_sessions (sid, mode, username, csrf_token) VALUES (?, 'fixed', ?, ?)", [
    sid,
    user,
    token,
  ]);
  setCookie(c, FIXED_COOKIE, sid, {
    path: FIXED_BASE,
    httpOnly: true,
    maxAge: 3600,
    sameSite: "Lax", // 他サイトからの POST には Cookie が付かない（本命ではなく保険）
    secure: c.var.crossSiteCookies,
  });
  return c.redirect(`${FIXED_BASE}/`, 303);
});

fixed.post("/change-email", async (c) => {
  const s = await findSession(c, "fixed", FIXED_COOKIE);
  if (!s) return c.html(notLoggedInView("fixed"), 401);
  const form = await c.req.parseBody();
  // 2枚目: フォームに埋め込んだトークンと、セッションに紐づくトークンが一致するか
  if (!s.csrf_token || !safeEqual(String(form["csrf_token"] ?? ""), s.csrf_token)) {
    return c.html(forbiddenView("CSRFトークンが無いか、一致しません。", "正規のフォームから送られたリクエストではありません。"), 403);
  }
  const email = String(form["email"] ?? "");
  if (!validEmail(email)) return c.html(badEmailView("fixed"), 400);
  await c.var.db.run("UPDATE csrf_users SET email = ? WHERE mode = 'fixed' AND username = ?", [email, s.username]);
  return c.redirect(`${FIXED_BASE}/`, 303);
});

fixed.post("/logout", async (c) => {
  const s = await findSession(c, "fixed", FIXED_COOKIE);
  if (s) await c.var.db.run("DELETE FROM csrf_sessions WHERE sid = ?", [s.sid]);
  deleteCookie(c, FIXED_COOKIE, { path: FIXED_BASE });
  return c.redirect(`${FIXED_BASE}/`, 303);
});
//#endregion

// ---- 攻撃者サイト役（/attacker/csrf）: 「懸賞に当選」を装った罠ページ ----
const attacker = new Hono<AppEnv>();

attacker.get("/", async (c) => {
  const rows = await c.var.db.all<{ mode: string; email: string }>(
    "SELECT mode, email FROM csrf_users WHERE username = 'alice' ORDER BY mode DESC",
  );
  const snippet = `<form method="post" action="/x/${ID}/vuln/change-email">
  <input type="hidden" name="email" value="${ATTACKER_EMAIL}">
  <button type="submit">賞品を受け取る</button>
</form>`;
  const crossNote = c.var.crossSiteCookies
    ? ""
    : `<div class="notice notice--warn">この環境では脆弱版の Cookie が <code>SameSite=Lax</code> のため、ボタンを押しても「未ログイン扱い」で止まります（クロスサイトの再現には localhost か https が必要です）。</div>`;

  const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="robots" content="noindex">
<title>懸賞サイト（模擬の攻撃者ページ）</title><link rel="stylesheet" href="/assets/lab.css"></head>
<body class="ex ex--guard"><main class="ex-main">
<div class="notice notice--warn">これは<strong>攻撃者側</strong>を演じる模擬ページです。ボタンは<strong>あなたが押したときだけ</strong>送信され、実際には外部へ何も送られず、すべてこのラボの中で完結します。</div>
${crossNote}
<h1>🎉 懸賞に当選しました！</h1>
<div class="result">
  <p>おめでとうございます。抽選の結果、あなたは当選者に選ばれました。下のボタンを押して賞品を受け取ってください。</p>
  <form method="post" action="/x/${ID}/vuln/change-email">
    <input type="hidden" name="email" value="${ATTACKER_EMAIL}">
    <button type="submit">🎁 賞品を受け取る</button>
  </form>
</div>
<p>このボタンの正体は、hidden 項目だけで作ったフォームです。送信先は<strong>脆弱版のメール変更</strong>（<code>/x/${ID}/vuln/change-email</code>）で、新しいメールアドレスは攻撃者のものに固定されています。</p>
<pre class="code"><code>${escapeHtml(snippet)}</code></pre>
<p>このページは別オリジン（<code>Origin: null</code>）として動いています。ブラウザは、脆弱版の Cookie が <code>SameSite=None</code> なので、このページからの POST にもあなたの Cookie を付けます。</p>

<h2>同じ罠を修正版に仕掛けると</h2>
<div class="result">
  <p>こちらは<strong>修正版</strong>のメール変更へ、同じ手口で送るボタンです。攻撃者は被害者の CSRF トークンを知らないため、トークンを付けられません。</p>
  <form method="post" action="/x/${ID}/fixed/change-email">
    <input type="hidden" name="email" value="${ATTACKER_EMAIL}">
    <button type="submit" class="ghost">🎁 賞品を受け取る（修正版へ送る）</button>
  </form>
</div>

<h2>ラボ用の確認（攻撃者には見えない情報）</h2>
<p>あなたのアカウントの現在のメールアドレスです。攻撃が成立すると <code>${ATTACKER_EMAIL}</code> に変わります。</p>
${table(
  ["画面", "alice のメールアドレス"],
  rows.map((r) => [r.mode === "vuln" ? "脆弱版" : "修正版", r.email]),
)}
<p><a href="/attacker/${ID}/">この表を更新</a> / <a href="/x/${ID}">← 解説へ戻る</a></p>
</main></body></html>`;
  return c.html(html);
});

export const exercise: Exercise = {
  id: ID,
  title: "CSRF",
  summary: "他のサイトに置かれたボタンを押しただけで、ログイン中の自分のメールアドレスが書き換えられる。",
  level: 2,
  book: { chapter: 4, topic: "重要な処理の際に混入する脆弱性（CSRF）" },
  schema: [
    `CREATE TABLE csrf_users (
       mode TEXT NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL, email TEXT NOT NULL,
       PRIMARY KEY (mode, username)
     )`,
    `CREATE TABLE csrf_sessions (sid TEXT PRIMARY KEY, mode TEXT NOT NULL, username TEXT NOT NULL, csrf_token TEXT)`,
  ],
  seed: [
    `INSERT INTO csrf_users (mode, username, password, email) VALUES ('vuln', 'alice', 'alice-pass', 'alice@example.com')`,
    `INSERT INTO csrf_users (mode, username, password, email) VALUES ('fixed', 'alice', 'alice-pass', 'alice@example.com')`,
  ],
  vuln,
  fixed,
  attacker,
  doc: {
    goals: [
      "CSRFが成立する条件（Cookieだけで本人の操作と判断している／攻撃者がリクエストの形を知っている）を説明できる",
      "攻撃者のページから送ったPOSTに、被害者のCookieが付いて届く様子を開発者ツールで確かめられる",
      "CSRFトークン、Origin検証、SameSite Cookie、再認証の役割を区別し、組み合わせる理由を説明できる",
    ],
    background: `
CSRF（クロスサイト・リクエスト・フォージェリ）は、ログイン中のユーザーのブラウザを使って、**本人が意図していないリクエストを正規のサイトへ送らせる**攻撃です。

ブラウザは、リクエストの送り先サイトの Cookie を、そのリクエストを始めたページがどのサイトであっても自動で付けます（SameSite の制限がない限り）。サーバーが「正しい Cookie が付いている＝本人が操作した」と考えると、攻撃者のページに置いたフォームを押させるだけで、メールアドレスの変更、購入、送金などの重要な処理が実行されてしまいます。

攻撃者は、被害者のパスワードも Cookie の値も知る必要がありません。知っておくのは「リクエストの形」（URL、メソッド、パラメータ名）だけです。

この演習では、会員サイトのメールアドレス変更が標的です。攻撃者のページ（模擬）は別オリジンとして動き、ボタンを押すと脆弱版へ POST します。
`,
    steps: [
      {
        title: "脆弱版にログインして、通常の動きを確かめる",
        body: "脆弱版を開き、`alice` / `alice-pass`（ダミー）でログインします。マイページに登録メールアドレスが出るので、フォームで一度変更してみて、通信が `POST /change-email`（パラメータは `email` だけ）であることを開発者ツールの Network で確かめます。最後に `alice@example.com` に戻しておきます。\n\n**http で localhost 以外にアクセスしている場合**、このラボは脆弱版の Cookie を SameSite=Lax で発行するため、手順3以降の攻撃は再現できません（画面に注意書きが出ます）。",
        payloads: [{ label: "メールアドレス（変更の確認用）", value: "bob@example.com" }],
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "ログインしたまま、攻撃者のページを開く",
        body: "脆弱版からログアウトせずに、攻撃者のページ（模擬）を開きます。「懸賞に当選しました」という誘いの文面が出ます。これは別のサイトに置かれたページで、被害者がこれを開くことが攻撃の前提です。",
        open: { label: "攻撃者のページ（模擬）を開く", href: "/attacker/csrf/" },
      },
      {
        title: "「賞品を受け取る」を押す",
        body: "ボタンを押すと、脆弱版の `/change-email` に `email=attacker@evil.example` がPOSTされ、そのまま脆弱版のマイページに移ります。登録メールアドレスが攻撃者のものに書き換わっていれば成功です。あなたは変更フォームを一度も操作していません。",
        payloads: [{ label: "攻撃者が送るパラメータ", value: "email=attacker@evil.example" }],
      },
      {
        title: "なぜ通ったのかをヘッダーで確かめる",
        body: "手順2〜3をもう一度行い、開発者ツールの Network で `change-email` のリクエストを見ます。`Origin: null`（攻撃者ページは別オリジン）にもかかわらず、`Cookie` に脆弱版のセッションが付いています。サーバーはこの Cookie だけを見て本人の操作だと判断しています。\n\nログアウトしてから押すと、Cookie が無いので「未ログイン」として止まります。CSRFは、ログイン中だからこそ成立する攻撃です。",
      },
      {
        title: "同じ罠を修正版に仕掛ける",
        body: "修正版に `alice` でログインし、攻撃者のページの下段にある「修正版へ送る」ボタンを押します。攻撃者は被害者の CSRF トークンを知らないので、トークンの無いリクエストになります。また、`Origin: null` が理由で、トークンの確認より前に拒否されます。メールアドレスは変わりません。",
        open: { label: "修正版を開く", href: "fixed/" },
      },
    ],
    cause: `
原因は2つが重なっていることです。

- 変更を受け付ける処理が、**セッション Cookie が有効かどうかだけ**を見ています。「このリクエストは、自分のサイトの画面から本人が送ったものか」を確かめる材料（トークンや Origin）が何もありません。
- Cookie が \`SameSite=None\` なので、**他のサイトのページが始めた POST にもブラウザが Cookie を付けます**。

ハイライトした2行がそれぞれ対応しています。1つ目が Cookie の属性、2つ目が検証の欠落です。
`,
    fix: `
修正の本命は、**「このリクエストは自分が配ったフォームから来た」ことを、サーバーが確認できるようにする**ことです。

- **CSRFトークン**: ログイン時に推測できない乱数（256bit）を作ってセッションに紐づけ、フォームの hidden 項目に入れます。送信されたトークンを、セッションのトークンと**定数時間で**比べます。攻撃者のページは、同一オリジンポリシーのため被害者の画面を読めず、トークンを知りません。
- **Origin ヘッダーの検証**: 状態を変えるリクエストでは、\`Origin\` があり、かつ自分のオリジンと違う（\`null\` を含む）なら拒否します。トークンが何らかの形で漏れたときの2枚目の壁です。
- **SameSite=Lax の Cookie**: 他サイトからの POST に Cookie を付けさせません。ブラウザの機能に頼る保険であり、これだけを本命にはしません。

あわせて、Cookie は \`HttpOnly\` のままです。
`,
    verify: [
      "修正版にログインして攻撃者ページの「修正版へ送る」を押す。403 になり、メールアドレスは変わらない（Origin が null のため、トークン確認の前に拒否される）",
      "修正版のマイページで、開発者ツールから hidden の `csrf_token` を消して（または書き換えて）変更を送る。403 になる",
      "開発者ツールの Application → Cookies で、修正版の Cookie が `SameSite=Lax` と `HttpOnly` であることを確かめる",
      "ログインし直すと `csrf_token` が別の値になる。トークンはセッションごとの乱数である",
      "正規の操作（修正版のマイページのフォームからの変更）は、これまでどおり成功する",
    ],
    beyond: `
**SameSite は強力な保険ですが、万能ではありません。** Lax でも、リンクや画面遷移による「他サイトからのトップレベルのGET」には Cookie が付きます。**GET で状態を変えない**（変更は POST などで受ける）設計が前提です。また、同じサイトの別サブドメインからのリクエストは「同一サイト」として扱われ、SameSite では防げません。ブラウザの既定値に頼らず、\`SameSite\` は明示しましょう。

**重要な操作では、再認証を挟みます。** メールアドレスやパスワードの変更、送金などでは、現在のパスワードの再入力を求めます。攻撃者は被害者のパスワードを知らないため、トークンが漏れても、SameSite が効かなくても、CSRFは成立しません。確認画面を挟む設計も同じ発想で、特に「ユーザーが意図して操作したか」を確かめる効果があります。

**トークンはURLに載せません。** Referer や履歴、ログからトークンが漏れます。フォームの hidden 項目か、リクエストヘッダーで運びます。

**XSS があるとCSRF対策は無力になります。** 同じオリジンのスクリプトは、画面のトークンを読めてしまうためです。関連する演習として、同じく「正規の画面を悪用する」**クリックジャッキング**もあわせて試してください（こちらはトークンがあっても成立します）。
`,
    quiz: [
      {
        q: "攻撃者は被害者の Cookie の値を知らないのに、なぜ CSRF が成立するの？",
        a: "Cookie の値を攻撃者が書く必要がないからです。ブラウザが、送り先サイトの Cookie を自動で付けてくれます。攻撃者は、URL・メソッド・パラメータというリクエストの形を用意するだけで足ります。",
      },
      {
        q: "修正版で、攻撃者は CSRF トークンを偽造できないのはなぜ？",
        a: "トークンは、被害者のブラウザが正規サイトから受け取ったHTMLの中にだけあり、別オリジンの攻撃者ページは同一オリジンポリシーによって読めないからです。256bit の乱数なので推測もできません。ただし、サイト内に XSS があるとこの前提が崩れます。",
      },
      {
        q: "メールアドレスの変更を `GET /change-email?email=...` で受けると、SameSite=Lax でも守れないのはなぜ？",
        a: "Lax は、他サイトからのリンク遷移など、トップレベルの GET ナビゲーションには Cookie を付けるからです。攻撃者はリンクを踏ませるだけでGETを発行できます。状態を変える処理は GET で受けないのが原則です。",
      },
    ],
  },
};
