import { Hono } from "hono";
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * セッション固定化。
 *
 * 1台のブラウザで「攻撃者」と「被害者」を演じられるよう、同じページに「攻撃者コンソール」を置いている。
 *  ① 攻撃者が新しいセッションID（未ログイン）を手に入れる
 *  ② そのIDを仕込んだ罠のURL（?sid=…）を作る
 *  ③ 被害者としてそのURLを開き、ログインする
 *  ④ 攻撃者が、Cookie を使わず「そのIDだけ」でセッションを引き、被害者の画面を見る
 * 脆弱版は URL の sid を受け取り、ログイン時にIDを作り直さない。修正版はログイン時に古いセッションを捨てて新しいIDを発行する。
 */

const ID = "session-fixation";
type Mode = "vuln" | "fixed";
type Ctx = Context<AppEnv>;

const HINT_USER = "alice";
const HINT_PASS = "alice-pass";
const SID_RE = /^[0-9a-f]{32}$/;

interface SfSession {
  sid: string;
  username: string | null;
}

/** セッションID: 暗号論的乱数 128bit（推測できない）。固定化は「推測」ではなく「押し付け」の攻撃なので、IDの強さとは別の問題 */
function newSid(): string {
  return [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function findSession(c: Ctx, mode: Mode, sid: string | undefined | null): Promise<SfSession | null> {
  if (!sid || !SID_RE.test(sid)) return null;
  return c.var.db.first<SfSession>("SELECT sid, username FROM session_fixation_sessions WHERE sid = ? AND mode = ?", [sid, mode]);
}

async function createSession(c: Ctx, mode: Mode, username: string | null = null): Promise<SfSession> {
  const sid = newSid();
  await c.var.db.run("INSERT INTO session_fixation_sessions (sid, mode, username, created_at) VALUES (?, ?, ?, ?)", [
    sid,
    mode,
    username,
    new Date().toISOString(),
  ]);
  return { sid, username };
}

/** ログインフォームの値を確かめ、成功したらユーザー名を返す */
async function checkLogin(c: Ctx): Promise<string | null> {
  const form = await c.req.parseBody();
  const row = await c.var.db.first<{ username: string }>(
    "SELECT username FROM session_fixation_users WHERE username = ? AND password = ?",
    [String(form["username"] ?? ""), String(form["password"] ?? "")],
  );
  return row ? row.username : null;
}

// ---- 画面（脆弱版・修正版で共通） ----
const PROFILES: Record<string, { name: string; email: string; points: string }> = {
  alice: { name: "アリス・サンプル", email: "alice@example.com", points: "12,345 pt" },
};

function accountHtml(username: string): string {
  const p = PROFILES[username] ?? { name: "-", email: "-", points: "-" };
  return `<div class="result">
  <p>ユーザー: <strong>${escapeHtml(username)}</strong></p>
  <p>氏名: ${escapeHtml(p.name)}（ダミー）</p>
  <p>メールアドレス: ${escapeHtml(p.email)}</p>
  <p>ポイント残高: ${escapeHtml(p.points)}</p>
</div>`;
}

async function homePage(c: Ctx, mode: Mode, s: SfSession, error = ""): Promise<string> {
  const base = `/x/${ID}/${mode}`;
  const origin = new URL(c.req.url).origin;
  const atk = await c.var.db.first<{ sid: string }>("SELECT sid FROM session_fixation_attacker WHERE mode = ?", [mode]);
  const urlSid = c.req.query("sid");

  let urlNote = "";
  if (urlSid && mode === "vuln" && urlSid === s.sid) {
    urlNote = `<div class="notice notice--warn">URL の <code>sid</code> パラメータで渡された値を、このブラウザのセッションIDとして採用しました。</div>`;
  } else if (urlSid && mode === "fixed") {
    urlNote = `<div class="notice">URL に <code>sid</code> パラメータが付いていましたが、修正版は URL のセッションIDを<strong>無視</strong>します（Cookie だけを見ます）。</div>`;
  }

  const victim = s.username
    ? `<p>ログイン中: <strong>${escapeHtml(s.username)}</strong>（<a href="${base}/me">マイページを見る</a>）</p>
<form method="post" action="${base}/logout"><button type="submit" class="ghost">ログアウト</button></form>`
    : `${error ? `<p class="ng">${escapeHtml(error)}</p>` : ""}<form method="post" action="${base}/login">
  <label for="u">ユーザー名</label><input id="u" name="username" value="${HINT_USER}" autocomplete="off">
  <label for="p">パスワード</label><input id="p" type="password" name="password" autocomplete="off">
  <p><button type="submit">ログイン</button></p>
</form>
<p>ヒント: ユーザー名 <code>${HINT_USER}</code> / パスワード <code>${HINT_PASS}</code>（演習用のダミーです）</p>`;

  const trap = atk ? `${base}/?sid=${atk.sid}` : "";
  const body = `<h1>会員サイト</h1>
${urlNote}
<h2>被害者のブラウザ</h2>
<p>このブラウザ（被害者）の Cookie のセッションID: <code id="browser-sid">${s.sid}</code></p>
${victim}

<h2 id="attacker">攻撃者コンソール</h2>
<div class="notice notice--warn">1台のブラウザで体験できるよう、<strong>攻撃者の操作</strong>もこのページに置いています。
攻撃者は被害者のブラウザの Cookie を読めない想定なので、ここのボタンは、あなたのブラウザの Cookie を<strong>使いません</strong>。</div>
<div class="result">
  <form method="post" action="${base}/attacker-new-sid" class="actions"><button type="submit">① 攻撃者として新しいSIDを取得</button></form>
  <p>手に入れた SID: ${atk ? `<code id="attacker-sid">${atk.sid}</code>` : "（まだ取得していません）"}</p>
</div>
<div class="result">
  <p><strong>② 罠のURL</strong>（攻撃者がメールなどで被害者に送る）</p>
  ${atk ? `<p><code id="trap-url">${escapeHtml(origin + trap)}</code></p>` : "<p>（① のあとに表示されます）</p>"}
</div>
<div class="result">
  <p><strong>③ 被害者として罠のURLを開く</strong>（開いたら、上のフォームでログインします）</p>
  ${atk ? `<p><a class="btn" href="${escapeHtml(trap)}">被害者として罠のURLを開く</a></p>` : "<p>（① のあとに表示されます）</p>"}
</div>
<div class="result">
  <p><strong>④ 攻撃者として、そのSIDで見える画面を表示する</strong>（Cookie は使わず、SID だけで引きます）</p>
  <form method="get" action="${base}/attacker-view" class="actions">
    <input name="sid" value="${atk ? atk.sid : ""}" size="36" aria-label="SID" autocomplete="off">
    <button type="submit">このSIDで見える画面を表示</button>
  </form>
</div>`;
  return exercisePage({ id: ID, mode, title: "会員サイト", body });
}

function mePage(mode: Mode, s: SfSession): string {
  const base = `/x/${ID}/${mode}`;
  const body = `<h1>マイページ</h1>
<p>このブラウザの Cookie のセッションID: <code id="browser-sid">${s.sid}</code></p>
${s.username ? accountHtml(s.username) : ""}
<form method="post" action="${base}/logout" class="actions"><button type="submit" class="ghost">ログアウト</button></form>
<p><a href="${base}/#attacker">攻撃者コンソールへ</a></p>`;
  return exercisePage({ id: ID, mode, title: "マイページ", body });
}

/** ① 攻撃者が新しいSIDを手に入れる（サーバーに「未ログインのセッション」を作らせるだけ。被害者のブラウザの Cookie には触れない） */
async function issueAttackerSid(c: Ctx, mode: Mode) {
  const s = await createSession(c, mode);
  await c.var.db.run(
    "INSERT INTO session_fixation_attacker (mode, sid) VALUES (?, ?) ON CONFLICT(mode) DO UPDATE SET sid = excluded.sid",
    [mode, s.sid],
  );
  return c.redirect(`/x/${ID}/${mode}/#attacker`, 303);
}

/** ④ 攻撃者の視点: Cookie は一切見ない。URL で渡された SID だけでセッションを引き、マイページ相当を出す */
async function attackerView(c: Ctx, mode: Mode) {
  const sid = c.req.query("sid") ?? "";
  const s = await findSession(c, mode, sid);
  let result: string;
  if (!s) {
    result = `<p class="ok">この SID のセッションは存在しません（破棄されたか、発行されていない値です）。攻撃者には何も見えません。</p>`;
  } else if (!s.username) {
    result = `<p class="ok">この SID は<strong>未ログイン</strong>のセッションです。ログイン後の情報は見えません。</p>
<p>被害者のログイン時にセッションIDが作り直されていれば、攻撃者が持つ SID は、ログイン後の画面につながりません。</p>`;
  } else {
    result = `<p class="ng">被害者のアカウント情報が見えてしまいました（セッションの乗っ取りが成立）。</p>${accountHtml(s.username)}`;
  }
  const body = `<h1>攻撃者の画面</h1>
<p>攻撃者の視点です。Cookie は使わず、次の SID だけでセッションを引いています。</p>
<pre class="code"><code>SID: ${escapeHtml(sid)}</code></pre>
${result}
<p><a href="/x/${ID}/${mode}/#attacker">← 攻撃者コンソールへ戻る</a></p>`;
  return c.html(exercisePage({ id: ID, mode, title: "攻撃者の画面", body }));
}

//#region vuln
const vuln = new Hono<AppEnv>();
const VULN_COOKIE = "sf_vuln_sid";

// 現在のセッションを決める。無ければ（未ログインのまま）新しく作る
async function vulnSession(c: Ctx): Promise<SfSession> {
  const fromUrl = c.req.query("sid"); // [!] URL のパラメータからもセッションIDを受け取る（Cookie より優先）
  let s = await findSession(c, "vuln", fromUrl || getCookie(c, VULN_COOKIE));
  if (!s) s = await createSession(c, "vuln");
  setCookie(c, VULN_COOKIE, s.sid, { path: `/x/${ID}/vuln` }); // [!] URL で渡された値をそのまま Cookie に採用する。HttpOnly も SameSite もない
  return s;
}

vuln.get("/", async (c) => c.html(await homePage(c, "vuln", await vulnSession(c))));

vuln.post("/login", async (c) => {
  const s = await vulnSession(c);
  const user = await checkLogin(c);
  if (!user) return c.html(await homePage(c, "vuln", s, "ユーザー名またはパスワードが違います"), 401);
  await c.var.db.run("UPDATE session_fixation_sessions SET username = ? WHERE sid = ?", [user, s.sid]); // [!] ログイン前と同じセッションIDに、ユーザーを紐づけるだけ（IDを作り直さない）
  return c.redirect(`/x/${ID}/vuln/me`, 303);
});

vuln.get("/me", async (c) => {
  const s = await vulnSession(c);
  if (!s.username) return c.redirect(`/x/${ID}/vuln/`, 303);
  return c.html(mePage("vuln", s));
});

vuln.post("/logout", (c) => {
  deleteCookie(c, VULN_COOKIE, { path: `/x/${ID}/vuln` }); // [!] ブラウザの Cookie を消すだけ。サーバー側のセッションは「ログイン済み」のまま残る
  return c.redirect(`/x/${ID}/vuln/`, 303);
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();
const FIXED_COOKIE = "sf_fixed_sid";

function issueCookie(c: Ctx, sid: string): void {
  setCookie(c, FIXED_COOKIE, sid, {
    path: `/x/${ID}/fixed`,
    httpOnly: true, // JavaScript から読めない
    sameSite: "Lax", // 他サイトからの POST などには付かない
    secure: new URL(c.req.url).protocol === "https:",
  });
}

// 現在のセッションを決める。Cookie だけを見る（URL の sid は無視する）
async function fixedSession(c: Ctx): Promise<SfSession> {
  const s = await findSession(c, "fixed", getCookie(c, FIXED_COOKIE));
  if (s) return s;
  const fresh = await createSession(c, "fixed");
  issueCookie(c, fresh.sid);
  return fresh;
}

fixed.get("/", async (c) => c.html(await homePage(c, "fixed", await fixedSession(c))));

fixed.post("/login", async (c) => {
  const user = await checkLogin(c);
  if (!user) return c.html(await homePage(c, "fixed", await fixedSession(c), "ユーザー名またはパスワードが違います"), 401);
  const old = getCookie(c, FIXED_COOKIE);
  if (old) await c.var.db.run("DELETE FROM session_fixation_sessions WHERE sid = ? AND mode = 'fixed'", [old]); // 古いセッションを捨てる
  const fresh = await createSession(c, "fixed", user); // ログイン済みの情報は、新しいSIDにだけ紐づける
  issueCookie(c, fresh.sid);
  return c.redirect(`/x/${ID}/fixed/me`, 303);
});

fixed.get("/me", async (c) => {
  const s = await fixedSession(c);
  if (!s.username) return c.redirect(`/x/${ID}/fixed/`, 303);
  return c.html(mePage("fixed", s));
});

fixed.post("/logout", async (c) => {
  const sid = getCookie(c, FIXED_COOKIE);
  if (sid) await c.var.db.run("DELETE FROM session_fixation_sessions WHERE sid = ? AND mode = 'fixed'", [sid]); // サーバー側のセッションも破棄する
  deleteCookie(c, FIXED_COOKIE, { path: `/x/${ID}/fixed` });
  return c.redirect(`/x/${ID}/fixed/`, 303);
});
//#endregion

// 攻撃者コンソールの操作（脆弱版・修正版で同じもの）
for (const [mode, app] of [
  ["vuln", vuln],
  ["fixed", fixed],
] as const) {
  app.post("/attacker-new-sid", (c) => issueAttackerSid(c, mode));
  app.get("/attacker-view", (c) => attackerView(c, mode));
}

export const exercise: Exercise = {
  id: ID,
  title: "セッション固定化",
  summary: "攻撃者が用意したセッションIDを被害者に使わせると、被害者のログイン後に、そのIDで本人になりすませる。",
  level: 2,
  book: { chapter: 4, topic: "セッション管理の不備" },
  schema: [
    `CREATE TABLE session_fixation_users (username TEXT PRIMARY KEY, password TEXT NOT NULL)`,
    `CREATE TABLE session_fixation_sessions (sid TEXT PRIMARY KEY, mode TEXT NOT NULL, username TEXT, created_at TEXT NOT NULL)`,
    `CREATE TABLE session_fixation_attacker (mode TEXT PRIMARY KEY, sid TEXT NOT NULL)`,
  ],
  seed: [`INSERT INTO session_fixation_users (username, password) VALUES ('alice', 'alice-pass')`],
  vuln,
  fixed,
  doc: {
    goals: [
      "セッション固定化が成立する2つの条件（IDを押し付けられる／ログイン前後でIDが変わらない）を説明できる",
      "セッションハイジャック（IDを盗む）との違いを説明できる",
      "ログイン成功時にセッションIDを作り直す理由と、URLでIDを受け取らない理由を説明できる",
    ],
    background: `
セッション固定化は、**攻撃者が用意したセッションIDを被害者に使わせ**、被害者がログインしたあとに、そのIDで被害者になりすます攻撃です。

セッションIDを盗むセッションハイジャックと違い、攻撃者はIDを「盗む」必要がありません。サーバーから自分で新しいID（まだ誰もログインしていない状態）をもらい、それを被害者のブラウザに持たせるだけです。被害者がそのIDのままログインすると、サーバー側の同じセッションに「ログイン済み」の情報が書き込まれ、攻撃者が手元に持つIDが、そのまま被害者の権限を持つ鍵になります。

成立する条件は次の2つです。

- 攻撃者が決めたIDを、被害者のブラウザに持たせる手段がある（URLのパラメータ、別のサブドメインからのCookie書き込みなど）
- ログインの前後で、セッションIDが変わらない

この演習の脆弱版は、古い実装に見られた「URLのパラメータでセッションIDを受け取る」作りと、ログイン時にIDを変えない作りの両方を持っています。1台のブラウザで体験できるよう、攻撃者の操作は同じページの「攻撃者コンソール」に置いています。
`,
    steps: [
      {
        title: "ログインの前後でセッションIDを観察する",
        body: "脆弱版を開き、ページに表示される「CookieのセッションID」を覚えておきます。`alice` / `alice-pass`（ダミー）でログインして、マイページに表示されるIDを見比べてください。**ログインの前後で同じ**のはずです。ここが後の攻撃の前提になります。",
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "① 攻撃者として、新しいSIDを手に入れる",
        body: "ここから攻撃者の立場です。攻撃者コンソールの「① 攻撃者として新しいSIDを取得」を押します。サーバーが未ログインのセッションを作り、そのSIDが表示されます。続けて、そのSIDを仕込んだ「② 罠のURL」が表示されます。攻撃者はこのURLをメールなどで被害者に送ります。",
        open: { label: "脆弱版の攻撃者コンソールへ", href: "vuln/#attacker" },
      },
      {
        title: "③ 被害者として罠のURLを開き、ログインする",
        body: "被害者の立場に切り替え、「被害者として罠のURLを開く」を押します。ページ上の「CookieのセッションID」が、**攻撃者のSIDと同じ値に変わった**ことを確かめてください。このまま `alice` でログインします。ログインしても、IDは変わりません。",
        payloads: [
          { label: "ユーザー名", value: "alice" },
          { label: "パスワード", value: "alice-pass" },
        ],
      },
      {
        title: "④ 攻撃者として、そのSIDで見える画面を表示する",
        body: "再び攻撃者の立場です。「④ このSIDで見える画面を表示」を押します。この画面は、**Cookieを使わずSIDだけ**でセッションを引いています。被害者（alice）のアカウント情報が見えれば、なりすましの成立です。攻撃者は、被害者のパスワードを一切知りません。",
      },
      {
        title: "ログアウトしても残ることを確かめる",
        body: "被害者としてログアウトし、④をもう一度試します。脆弱版のログアウトは、ブラウザのCookieを消すだけで、サーバー側のセッションを破棄しません。そのため、攻撃者のSIDは**ログアウト後も**有効なままです。",
      },
    ],
    cause: `
セッション管理の基本が4か所で抜けています。ハイライトした行を、上から順に見てください。

- 1行目: URLの \`sid\` パラメータを、セッションIDとして受け取っています。攻撃者が決めたIDを被害者に持たせる入口になります。
- 2行目: 受け取ったIDを、そのままCookieに採用します。さらに \`HttpOnly\` も \`SameSite\` も付けていません。
- 3行目: ログインに成功しても、**ログイン前と同じセッションID**に、ユーザーを紐づけるだけです。攻撃者の手元のIDが、ログインの瞬間に被害者の鍵に変わります。
- 4行目: ログアウトで、ブラウザ側のCookieを消すだけです。サーバー側のセッションは「ログイン済み」のまま残ります。

なお、IDの生成自体は、脆弱版も修正版も同じ暗号論的乱数（128bit）です。固定化は、IDが推測されやすいから起きるのではありません。
`,
    fix: `
修正の本命は、**ログイン成功の時点で、セッションIDを作り直す**ことです。古いセッションをサーバー側で捨て、新しいIDを発行して、ログイン済みの情報は新しいIDにだけ紐づけます。攻撃者が持っているIDは、ログイン前の匿名のセッションを指したままで、ログイン後の情報にはつながりません。

あわせて、次の3点も入れています。

- URLのパラメータではセッションIDを受け取らず、**Cookieだけ**を見ます
- Cookieに \`HttpOnly\` と \`SameSite=Lax\` を付けます（https のときは \`Secure\` も）
- ログアウトで、**サーバー側のセッションも破棄**します
`,
    verify: [
      "修正版で①〜④を同じ手順で行う。罠のURLを開いても、ページの「CookieのセッションID」は攻撃者のSIDに変わらない（URLの sid を無視した旨の表示が出る）",
      "修正版でログインすると、ログイン前後で「CookieのセッションID」が変わる",
      "④を押しても、「未ログインのセッション」と表示され、被害者のアカウント情報は見えない",
      "ログイン後のセッションIDをコピーして、④のSID欄に貼って表示する。ログアウトしたあとに同じ操作をすると「セッションは存在しません」になる",
      "開発者ツールの Application → Cookies で、修正版の Cookie に `HttpOnly` と `SameSite=Lax` が付いている",
    ],
    beyond: `
**IDの再発行は、ログインだけではありません。** 権限が変わる場面（管理者への昇格、パスワード変更、再認証）でも作り直します。多くのフレームワークには、セッションIDを再発行するための機能があるので、ログイン処理で呼び忘れないことが大切です。

**URLにセッションIDを載せないでください。** 固定化の入口になるだけでなく、Referer、ブラウザの履歴、サーバーのログからIDが漏れます。外部へのリンクで Referer がどう送られるかは、オープンリダイレクトの演習とあわせて考えてみましょう。

**Cookieを攻撃者に書き込まれる経路にも注意します。** 同じ親ドメインの別のサブドメインや、暗号化されていない通信は、Cookieを上書きする入口になります。\`__Host-\` プレフィックスと \`Secure\` を付けた Cookie は、そうした上書きを受け付けにくくします。

**有効期限も設計します。** 一定時間操作がなければ無効にする、ログインしてからの絶対的な上限を決める、といった期限があれば、押し付けられたIDの寿命を短くできます。
`,
    quiz: [
      {
        q: "セッション固定化とセッションハイジャックは、どこが違う？",
        a: "ハイジャックは、被害者のセッションIDを盗んだり推測したりして使う攻撃です。固定化は、攻撃者が先に用意したIDを被害者に使わせ、被害者がログインするのを待つ攻撃です。後者では、IDを盗む必要がありません。",
      },
      {
        q: "セッションIDが十分な長さの乱数なら、固定化は防げる？",
        a: "防げません。固定化は推測ではなく、攻撃者がサーバーから正規にもらったIDを押し付ける攻撃だからです。IDの強さとは別に、ログイン時の再発行が必要です。",
      },
      {
        q: "URLの sid を無視するだけでは、なぜ不十分？",
        a: "攻撃者がCookieを仕込める経路（XSS、別サブドメインからの書き込み、暗号化されていない通信の改ざんなど）が残るからです。どんな経路でIDを押し付けられても無効になるよう、ログイン成功時にIDを作り直すのが本命です。",
      },
    ],
  },
};
