import { Hono } from "hono";
import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * 認可不備（IDOR）。小さな注文管理サイトで、3 種類の「認可の穴」を突く。
 *
 *  1. 水平権限昇格 … 注文IDを書き換えると他人の注文が見える（持ち主を確認していない）
 *  2. 垂直権限昇格 … 管理者かどうかを、利用者が書き換えられる Cookie で判定している
 *  3. 隠しフィールド … 「誰の注文か」をフォームの hidden に持たせ、サーバーがそれを信じる
 *
 * 修正版は、持ち主を SQL の条件に入れ、ロールをサーバー側のセッション（DB）から判定し、
 * 認可失敗・ログイン・重要操作を監査ログ（authz_audit）に残す。脆弱版は何も記録しない。
 * 結果の表示は常に escapeHtml / table を通す（この演習の主題は XSS ではない）。
 */

const ID = "authz";
type Mode = "vuln" | "fixed";
type Ctx = Context<AppEnv>;
const base = (mode: Mode) => `/x/${ID}/${mode}`;
const SID = { vuln: "authz_vuln_sid", fixed: "authz_fixed_sid" } as const;

interface User {
  id: number;
  username: string;
  role: string;
}
interface Order {
  id: number;
  user_id: number;
  item: string;
  price: number;
  address: string;
}

// ---- 共通の部品（脆弱版・修正版で同じもの。差分に出ないよう region の外に置く） ----

/** 数字だけの ID を数値にする。それ以外は 0（どの注文にも一致しない） */
const toId = (s: string) => (/^[0-9]{1,9}$/.test(s) ? Number(s) : 0);

const isHttps = (c: Ctx) => new URL(c.req.url).protocol === "https:";

const flashOf = (c: Ctx) => (c.req.query("ok") ? "ok" : c.req.query("ng") ? "ng" : "");

/** セッションCookie → サーバー側の authz_sessions → ユーザー（ロールはDBの値） */
async function currentUser(c: Ctx, mode: Mode): Promise<User | null> {
  const sid = getCookie(c, SID[mode]);
  if (!sid) return null;
  return c.var.db.first<User>(
    `SELECT u.id, u.username, u.role
       FROM authz_sessions s JOIN authz_users u ON u.id = s.user_id
      WHERE s.sid = ? AND s.mode = ?`,
    [sid, mode],
  );
}

async function startSession(c: Ctx, mode: Mode, userId: number): Promise<string> {
  const sid = crypto.randomUUID();
  await c.var.db.run("INSERT INTO authz_sessions (sid, user_id, mode) VALUES (?, ?, ?)", [sid, userId, mode]);
  return sid;
}

/** ログに入れる文字列から制御文字（改行など）を落とし、長さを制限する。ログの偽造・肥大化を防ぐ */
function clean(s: string, max: number): string {
  return s.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, max);
}

/** 監査ログに 1 行追記する。パスワードやセッションIDは入れない */
async function audit(c: Ctx, user: string, action: string, detail: string): Promise<void> {
  await c.var.db.run("INSERT INTO authz_audit (mode, at, user, action, detail) VALUES ('fixed', ?, ?, ?, ?)", [
    new Date().toISOString(),
    clean(user, 40),
    action,
    clean(detail, 200),
  ]);
}

function shop(mode: Mode, user: User | null, title: string, body: string): string {
  const b = base(mode);
  const nav = user
    ? `<div class="actions">
  <span>ログイン中: <strong>${escapeHtml(user.username)}</strong></span>
  <a href="${b}/">トップ</a><a href="${b}/orders">自分の注文</a><a href="${b}/admin">管理画面</a>${mode === "fixed" ? `<a href="${b}/audit">監査ログ</a>` : ""}
  <form method="post" action="${b}/logout"><button class="ghost" type="submit">ログアウト</button></form>
</div>`
    : `<div class="actions"><span>未ログイン</span><a href="${b}/">ログイン</a></div>`;
  return exercisePage({ id: ID, mode, title, body: `${nav}\n<h1>${escapeHtml(title)}</h1>\n${body}` });
}

function loginPage(mode: Mode, message = ""): string {
  const b = base(mode);
  const msg = message ? `<p class="ng">${escapeHtml(message)}</p>` : "";
  const body = `${msg}<form method="post" action="${b}/login">
  <p><label>ユーザー名 <input name="username" autocomplete="off"></label></p>
  <p><label>パスワード <input type="password" name="password" autocomplete="off"></label></p>
  <p><button type="submit">ログイン</button></p>
</form>
<h2>テスト用アカウント</h2>
${table(
  ["ユーザー名", "パスワード", "ロール"],
  [
    ["alice", "alice-pass", "user"],
    ["bob", "bob-pass", "user"],
    ["admin", "admin-pass", "admin"],
  ],
)}`;
  return shop(mode, null, "注文管理サイト", body);
}

function dashboard(mode: Mode, user: User): string {
  const b = base(mode);
  const memo =
    mode === "fixed"
      ? `<p>認可の失敗やログイン、重要な操作は <a href="${b}/audit">監査ログ</a> に記録されます。</p>`
      : `<div class="notice notice--warn">この版には監査ログがありません。誰が・いつ・何をしたかは、あとから調べられません。</div>`;
  const body = `<p>ようこそ、<strong>${escapeHtml(user.username)}</strong> さん。</p>
<ul>
  <li><a href="${b}/orders">自分の注文を見る</a></li>
  <li><a href="${b}/admin">管理画面（管理者向け）</a></li>
</ul>
${memo}`;
  return shop(mode, user, "注文管理サイト", body);
}

function ordersPage(mode: Mode, user: User, orders: Order[]): string {
  const b = base(mode);
  const rows = orders
    .map(
      (o) =>
        `<tr><td><a href="${b}/orders/${o.id}">#${o.id}</a></td><td>${escapeHtml(o.item)}</td><td>${o.price}</td><td>${escapeHtml(o.address)}</td></tr>`,
    )
    .join("");
  const list = orders.length
    ? `<table class="data"><thead><tr><th>注文ID</th><th>品名</th><th>価格(円)</th><th>配送先</th></tr></thead><tbody>${rows}</tbody></table>`
    : "<p>注文はありません。</p>";
  return shop(mode, user, "自分の注文", list);
}

/** hidden は <form> の先頭に差し込む HTML（脆弱版だけが、ここに隠しフィールドを入れる） */
function orderPage(mode: Mode, user: User, order: Order, hidden: string, flash: string): string {
  const b = base(mode);
  const msg =
    flash === "ok"
      ? `<p class="ok">配送先を更新しました。</p>`
      : flash === "ng"
        ? `<p class="ng">配送先を更新できませんでした。</p>`
        : "";
  const body = `${msg}${table(
    ["注文ID", "注文者ID", "品名", "価格(円)", "配送先"],
    [[order.id, order.user_id, order.item, order.price, order.address]],
  )}
<h2>配送先の変更</h2>
<form method="post" action="${b}/orders/${order.id}/address">
  ${hidden}
  <p><label>新しい配送先 <input name="address" value="${escapeHtml(order.address)}" size="44"></label></p>
  <p><button type="submit">変更する</button></p>
</form>`;
  return shop(mode, user, `注文 #${order.id}`, body);
}

async function adminPage(c: Ctx, mode: Mode, user: User | null): Promise<string> {
  const b = base(mode);
  const users = await c.var.db.all("SELECT id, username, role FROM authz_users ORDER BY id");
  const orders = await c.var.db.all<Order>("SELECT * FROM authz_orders ORDER BY id");
  const rows = orders
    .map(
      (o) =>
        `<tr><td>${o.id}</td><td>${o.user_id}</td><td>${escapeHtml(o.item)}</td><td>${o.price}</td><td>${escapeHtml(o.address)}</td>
<td><form method="post" action="${b}/admin/orders/${o.id}/cancel"><button class="ghost" type="submit">キャンセル</button></form></td></tr>`,
    )
    .join("");
  const body = `<h2>ユーザー一覧</h2>
${table(
  ["ID", "ユーザー名", "ロール"],
  users.map((u) => [u.id, u.username, u.role]),
)}
<h2>全注文</h2>
<table class="data"><thead><tr><th>注文ID</th><th>注文者ID</th><th>品名</th><th>価格(円)</th><th>配送先</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  return shop(mode, user, "管理画面", body);
}

const denied = (mode: Mode, user: User | null) =>
  shop(mode, user, "権限がありません", "<p class=\"ng\">この操作には管理者の権限が必要です。</p>");
const notFound = (mode: Mode, user: User | null) =>
  shop(mode, user, "見つかりません", "<p>指定された注文は見つかりませんでした。</p>");

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.post("/login", async (c) => {
  const form = await c.req.parseBody();
  const username = String(form.username ?? "");
  const password = String(form.password ?? "");
  const user = await c.var.db.first<User & { password: string }>(
    "SELECT id, username, role, password FROM authz_users WHERE username = ?",
    [username],
  );
  if (!user || user.password !== password) {
    return c.html(loginPage("vuln", "ユーザー名またはパスワードが違います"), 401);
  }
  const sid = await startSession(c, "vuln", user.id);
  setCookie(c, SID.vuln, sid, { path: base("vuln"), httpOnly: true, sameSite: "Lax", secure: isHttps(c) });
  setCookie(c, "role", user.role, { path: base("vuln") }); // [!] 権限（ロール）を、利用者が書き換えられる普通のCookie（HttpOnlyなし）に入れている
  return c.redirect(`${base("vuln")}/`, 303);
});

vuln.get("/orders/:id", async (c) => {
  const user = await currentUser(c, "vuln");
  if (!user) return c.redirect(`${base("vuln")}/`, 303);
  const id = toId(c.req.param("id"));
  const order = await c.var.db.first<Order>("SELECT * FROM authz_orders WHERE id = ?", [id]); // [!] 「ログインしているか」しか見ず、注文の持ち主を条件に入れていない
  if (!order) return c.html(notFound("vuln", user), 404);
  const hidden = `<input type="hidden" name="user_id" value="${user.id}">`; // [!] 「誰の操作か」を、利用者が書き換えられる隠しフィールドに持たせている
  return c.html(orderPage("vuln", user, order, hidden, flashOf(c)));
});

vuln.post("/orders/:id/address", async (c) => {
  const user = await currentUser(c, "vuln");
  if (!user) return c.redirect(`${base("vuln")}/`, 303);
  const form = await c.req.parseBody();
  const orderId = toId(c.req.param("id"));
  const ownerId = toId(String(form.user_id ?? "")); // [!] 持ち主の判定に、リクエストで送られてきた値を使っている
  const address = String(form.address ?? "").trim().slice(0, 100);
  const { changes } = await c.var.db.run("UPDATE authz_orders SET address = ? WHERE id = ? AND user_id = ?", [
    address,
    orderId,
    ownerId,
  ]);
  return c.redirect(`${base("vuln")}/orders/${orderId}?${changes ? "ok=1" : "ng=1"}`, 303);
});

vuln.get("/admin", async (c) => {
  const user = await currentUser(c, "vuln");
  if (getCookie(c, "role") !== "admin") return c.html(denied("vuln", user), 403); // [!] 管理者かどうかを、Cookieの値だけで判定している
  return c.html(await adminPage(c, "vuln", user));
});

vuln.post("/admin/orders/:id/cancel", async (c) => {
  const user = await currentUser(c, "vuln");
  if (getCookie(c, "role") !== "admin") return c.html(denied("vuln", user), 403); // [!] 同じ理由で、Cookieだけを信じている
  await c.var.db.run("DELETE FROM authz_orders WHERE id = ?", [toId(c.req.param("id"))]);
  return c.redirect(`${base("vuln")}/admin`, 303);
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

fixed.post("/login", async (c) => {
  const form = await c.req.parseBody();
  const username = String(form.username ?? "");
  const password = String(form.password ?? "");
  const user = await c.var.db.first<User & { password: string }>(
    "SELECT id, username, role, password FROM authz_users WHERE username = ?",
    [username],
  );
  if (!user || user.password !== password) {
    // 画面には理由を出さず、ログには理由を残す
    await audit(c, username, "login_failure", user ? "パスワードが一致しない" : "存在しないユーザー名");
    return c.html(loginPage("fixed", "ユーザー名またはパスワードが違います"), 401);
  }
  const sid = await startSession(c, "fixed", user.id);
  setCookie(c, SID.fixed, sid, { path: base("fixed"), httpOnly: true, sameSite: "Lax", secure: isHttps(c) });
  await audit(c, user.username, "login_success", "ログイン");
  return c.redirect(`${base("fixed")}/`, 303);
});

fixed.get("/orders/:id", async (c) => {
  const user = await currentUser(c, "fixed");
  if (!user) return c.redirect(`${base("fixed")}/`, 303);
  const id = toId(c.req.param("id"));
  const order = await c.var.db.first<Order>("SELECT * FROM authz_orders WHERE id = ? AND user_id = ?", [id, user.id]);
  if (!order) {
    await audit(c, user.username, "authz_denied", `GET /orders/${c.req.param("id")}`);
    return c.html(notFound("fixed", user), 404); // 他人の注文と「存在しない注文」を区別させない
  }
  return c.html(orderPage("fixed", user, order, "", flashOf(c)));
});

fixed.post("/orders/:id/address", async (c) => {
  const user = await currentUser(c, "fixed");
  if (!user) return c.redirect(`${base("fixed")}/`, 303);
  const form = await c.req.parseBody();
  const orderId = toId(c.req.param("id"));
  const address = String(form.address ?? "").trim().slice(0, 100);
  const { changes } = await c.var.db.run("UPDATE authz_orders SET address = ? WHERE id = ? AND user_id = ?", [
    address,
    orderId,
    user.id,
  ]);
  if (!changes) {
    await audit(c, user.username, "authz_denied", `POST /orders/${c.req.param("id")}/address`);
    return c.html(notFound("fixed", user), 404);
  }
  await audit(c, user.username, "order_address_changed", `注文 #${orderId} の配送先を変更`);
  return c.redirect(`${base("fixed")}/orders/${orderId}?ok=1`, 303);
});

fixed.get("/admin", async (c) => {
  const user = await currentUser(c, "fixed");
  if (user?.role !== "admin") {
    await audit(c, user?.username ?? "(anonymous)", "authz_denied", "GET /admin");
    return c.html(denied("fixed", user), 403);
  }
  return c.html(await adminPage(c, "fixed", user));
});

fixed.post("/admin/orders/:id/cancel", async (c) => {
  const user = await currentUser(c, "fixed");
  const orderId = toId(c.req.param("id"));
  if (user?.role !== "admin") {
    await audit(c, user?.username ?? "(anonymous)", "authz_denied", `POST /admin/orders/${c.req.param("id")}/cancel`);
    return c.html(denied("fixed", user), 403);
  }
  const { changes } = await c.var.db.run("DELETE FROM authz_orders WHERE id = ?", [orderId]);
  await audit(c, user.username, "admin_cancel_order", `注文 #${orderId} をキャンセル（${changes} 件）`);
  return c.redirect(`${base("fixed")}/admin`, 303);
});

// 自分に関する監査ログ（管理者は全員分）。画面から編集・削除する手段は作らない
fixed.get("/audit", async (c) => {
  const user = await currentUser(c, "fixed");
  if (!user) return c.redirect(`${base("fixed")}/`, 303);
  const rows =
    user.role === "admin"
      ? await c.var.db.all("SELECT at, user, action, detail FROM authz_audit WHERE mode = 'fixed' ORDER BY id DESC LIMIT 100")
      : await c.var.db.all(
          "SELECT at, user, action, detail FROM authz_audit WHERE mode = 'fixed' AND user = ? ORDER BY id DESC LIMIT 100",
          [user.username],
        );
  const scope = user.role === "admin" ? "全員分" : `<code>${escapeHtml(user.username)}</code> に関する分`;
  const body = `<p>直近 100 件の記録です（${scope}）。記録は追記だけで、この画面から編集・削除はできません。</p>
${rows.length ? table(["日時 (UTC)", "ユーザー", "種別", "詳細"], rows.map((r) => [r.at, r.user, r.action, r.detail])) : "<p>まだ記録はありません。</p>"}`;
  return c.html(shop("fixed", user, "監査ログ", body));
});
//#endregion

// ---- 共通のルート（ログイン画面・自分の注文一覧・ログアウト） ----
for (const [app, mode] of [
  [vuln, "vuln"],
  [fixed, "fixed"],
] as const) {
  app.get("/", async (c) => {
    const user = await currentUser(c, mode);
    return c.html(user ? dashboard(mode, user) : loginPage(mode));
  });

  app.get("/orders", async (c) => {
    const user = await currentUser(c, mode);
    if (!user) return c.redirect(`${base(mode)}/`, 303);
    const orders = await c.var.db.all<Order>("SELECT * FROM authz_orders WHERE user_id = ? ORDER BY id", [user.id]);
    return c.html(ordersPage(mode, user, orders));
  });

  app.post("/logout", async (c) => {
    const sid = getCookie(c, SID[mode]);
    if (sid) await c.var.db.run("DELETE FROM authz_sessions WHERE sid = ? AND mode = ?", [sid, mode]);
    deleteCookie(c, SID[mode], { path: base(mode) });
    if (mode === "vuln") deleteCookie(c, "role", { path: base(mode) });
    return c.redirect(`${base(mode)}/`, 303);
  });
}

// 解説の「貼り付けて試す」用
const SNIPPET_HIDDEN = "document.querySelector('[name=user_id]').value = 2";
const SNIPPET_ROLE = "document.cookie = 'role=admin; path=/x/authz/vuln'";

export const exercise: Exercise = {
  id: ID,
  title: "認可不備（IDOR）",
  summary: "ログインさえしていれば他人の注文が見える、Cookie の書き換えで管理者になれる。認可チェックの抜けと、ログの大切さを学ぶ。",
  level: 1,
  book: { chapter: 5, topic: "認可（と、ログ出力）" },
  schema: [
    `CREATE TABLE authz_users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, role TEXT NOT NULL)`,
    `CREATE TABLE authz_sessions (sid TEXT PRIMARY KEY, user_id INTEGER NOT NULL, mode TEXT NOT NULL)`,
    `CREATE TABLE authz_orders (
       id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, item TEXT NOT NULL, price INTEGER NOT NULL, address TEXT NOT NULL
     )`,
    `CREATE TABLE authz_audit (
       id INTEGER PRIMARY KEY AUTOINCREMENT, mode TEXT NOT NULL, at TEXT NOT NULL,
       user TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL
     )`,
  ],
  seed: [
    // パスワードは平文のダミー値。保存方法はこの演習の主題ではない（password-storage 演習で扱う）
    `INSERT INTO authz_users (id, username, password, role) VALUES
       (1, 'alice', 'alice-pass', 'user'),
       (2, 'bob',   'bob-pass',   'user'),
       (3, 'admin', 'admin-pass', 'admin')`,
    // 連番ID。alice と bob の注文が混ざっている（alice は 1・2・4・7、bob は 3・5・6・8）
    `INSERT INTO authz_orders (id, user_id, item, price, address) VALUES
       (1, 1, 'ワイヤレスマウス',     2480,  '東京都千代田区サンプル町1-2-3 テストビル101'),
       (2, 1, 'メカニカルキーボード', 12800, '東京都千代田区サンプル町1-2-3 テストビル101'),
       (3, 2, 'モニターアーム',       8900,  '大阪府大阪市ダミー区4-5-6 サンプルハイツ202'),
       (4, 1, 'USBハブ',              3200,  '東京都千代田区サンプル町1-2-3 テストビル101'),
       (5, 2, 'ノートPCスタンド',     3600,  '大阪府大阪市ダミー区4-5-6 サンプルハイツ202'),
       (6, 2, 'ウェブカメラ',         5400,  '大阪府大阪市ダミー区4-5-6 サンプルハイツ202'),
       (7, 1, 'デスクライト',         4500,  '東京都千代田区サンプル町1-2-3 テストビル101'),
       (8, 2, 'ヘッドセット',         7800,  '大阪府大阪市ダミー区4-5-6 サンプルハイツ202')`,
  ],
  vuln,
  fixed,
  doc: {
    goals: [
      "認証（ログインしている）と認可（この操作をしてよい）が別のものであることを、実際に破って説明できる",
      "水平権限昇格（他人のデータ）・垂直権限昇格（管理者の機能）・隠しフィールドの改ざんが、どれも「クライアントから来た値を信じる」ことから起きると説明できる",
      "認可の本命は「サーバー側で、リソースごとに毎回確かめる」ことで、推測されにくいIDは保険にすぎないと説明できる",
      "認可の失敗やログイン、重要な操作を監査ログに残す意味と、残し方の注意を説明できる",
    ],
    background: `
**認証**は「あなたは誰か」を確かめること、**認可**は「あなたはこれをしてよいか」を確かめることです。ログインできたことは、あらゆる操作を許されたことを意味しません。認可の確認が抜けていると、ログインさえしていれば、他人のデータを見たり、管理者の機能を使ったりできてしまいます。

この演習の注文管理サイトでは、次の3つの穴を突きます。

- **水平権限昇格** … 同じ権限の別の利用者のデータに手が届く。注文IDのような、連番で推測しやすい識別子が足がかりになる（IDOR: 安全でない直接オブジェクト参照）
- **垂直権限昇格** … 一般の利用者が、管理者の機能に手が届く
- **隠しフィールドの改ざん** … フォームに隠して送らせた値を、利用者が書き換える

もう一つの主題が**ログ**です。脆弱版は何も記録しないので、攻撃されても気づけず、被害の範囲も調べられません。修正版は、認可の失敗・ログイン・重要な操作を監査ログに残します。
`,
    steps: [
      {
        title: "alice でログインして、自分の注文を見る",
        body: "脆弱版のトップで、alice としてログインします。「自分の注文」には #1、#2、#4、#7 の4件が並びます。1件を開き、URL が `/orders/1` のように**連番の数字**になっていること、そして一覧に #3、#5、#6、#8 がないことに気づいてください。欠けている番号は、ほかの誰かの注文です。",
        payloads: [
          { label: "ユーザー名", value: "alice" },
          { label: "パスワード", value: "alice-pass" },
        ],
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "水平権限昇格: 注文IDを書き換えて、他人の注文を見る",
        body: "アドレスバーの注文IDを、alice の一覧にない `3` に書き換えます。bob の注文と配送先の住所が表示されます。#5、#6、#8 も同じです。サーバーは「ログインしているか」しか確かめておらず、「この注文は誰のものか」を確かめていません。ログインしていなければ、ログイン画面に戻されます。",
        payloads: [{ label: "アドレスバーのパス", value: "/x/authz/vuln/orders/3" }],
        open: { label: "注文 #3 を開く", href: "vuln/orders/3" },
      },
      {
        title: "隠しフィールドを書き換えて、他人の配送先を変える",
        body: "注文 #3 の「配送先の変更」フォームには、画面に出ない `user_id` の隠しフィールドがあり、alice の ID（1）が入っています。サーバーはこの値を「注文の持ち主」として使います。次のコードを開発者ツールのコンソールに貼ると 2（bob）に書き換わるので、配送先を変えて「変更する」を押します。bob の配送先を、alice が書き換えられます。開発者ツールの要素の検査で `value` を直接書き換えても同じです。",
        payloads: [{ label: "コンソールに貼る", value: SNIPPET_HIDDEN }],
        open: { label: "注文 #3 のフォームを開く", href: "vuln/orders/3" },
      },
      {
        title: "垂直権限昇格: Cookie を書き換えて、管理者になる",
        body: "alice のまま、アドレスバーで `/x/authz/vuln/admin` を開くと、権限がないと拒否されます。ところが、ログイン時に `role=user` という普通のCookie（開発者ツールで見える・書き換えられる）が発行されています。管理者かどうかの判定はこのCookieの値だけなので、`role=admin` に書き換えて開き直すと、全ユーザーと全注文が見える管理画面に入れます。",
        payloads: [
          { label: "コンソールに貼る", value: SNIPPET_ROLE },
          { label: "書き換えたあとに開くパス", value: "/x/authz/vuln/admin" },
        ],
        open: { label: "脆弱版のトップを開く", href: "vuln/" },
      },
      {
        title: "管理者の操作をして、痕跡が残らないことを確かめる",
        body: "書き換えたCookieのまま、管理画面で適当な注文の「キャンセル」を押します。bob でログインし直すと、その注文が消えています。ここで、「誰が・いつ・何をしたか」を調べる方法を探してみてください。脆弱版には監査ログがないので、調べる手段がありません。ユーザーから「注文が勝手に消えた」と問い合わせが来ても、原因を追えないということです。",
        open: { label: "脆弱版のトップを開く", href: "vuln/" },
      },
    ],
    cause: `
原因は、**サーバーが認可を確かめず、クライアントから来た値を信じていること**です。ハイライトした行が問題です。

- 注文の表示: 検索条件が \`id = ?\` だけで、注文の持ち主（\`user_id\`）を条件に入れていません。ログインしている誰でも、IDを変えれば誰の注文でも見られます（水平権限昇格）。
- 隠しフィールド: フォームの hidden の \`user_id\` を「持ち主」として UPDATE の条件に使っています。hidden は画面に出ないだけで、利用者が自由に書き換えられます。「持ち主の確認をした」つもりで、実際は攻撃者が持ち主を名乗れます。
- ロール: 管理者かどうかを \`role\` Cookie の値だけで判定しています。Cookie は利用者のブラウザにあるもので、開発者ツールで書き換えられます（垂直権限昇格）。
- ログ: 認可の失敗も、ログインの成否も、管理者の操作も、どこにも記録していません。

どれも「ブラウザから送られてくる値（URL、フォーム、Cookie）は、利用者が自由に作れる」という前提が抜けています。
`,
    fix: `
修正の本命は、**誰が何をしようとしているかを、サーバーが自分で持っている情報だけで確かめる**ことです。

- 持ち主の確認: 注文の取得も更新も、\`WHERE id = ? AND user_id = ?\` とし、\`user_id\` には**セッションから引いたログイン中のユーザー**を渡します。他人の注文は「該当なし」になります。画面には 404 を返し、「存在しない注文」と区別できないようにして、注文の存在すら教えません。
- 隠しフィールド: 修正版のフォームには \`user_id\` を入れません。送られてきても読みません。
- ロール: ロールは Cookie に入れず、サーバー側のセッション（DB）から引きます。\`role\` Cookie を作って送っても、参照されません。
- 監査ログ: ログインの成功・失敗、認可の失敗、配送先の変更、管理者のキャンセルを \`authz_audit\` に記録します。\`/audit\` で自分に関する記録を確認できます。
`,
    verify: [
      "修正版で alice としてログインし、注文 #3 を開く。404 になる。存在しない #999 を開いたときと同じ画面で、他人の注文かどうかは分からない",
      "alice の注文 #1 の画面で、開発者ツールでフォームの `action` を `/x/authz/fixed/orders/3/address` に書き換えて、配送先を送る。404 になり、bob の配送先は変わらない（hidden の `user_id` を足しても無視される）",
      "alice のまま、`document.cookie = 'role=admin; path=/x/authz/fixed'` を実行して `/x/authz/fixed/admin` を開く。403 のままで入れない（ロールはCookieではなくサーバーのセッションから判定している）",
      "「監査ログ」を開く。さきほどの試みが `authz_denied` として、時刻とユーザー名つきで記録されている。ログインの成功・失敗、配送先の変更も並ぶ",
      "admin でログインして「監査ログ」を開くと全員分が見える。管理画面で注文をキャンセルすると `admin_cancel_order` が記録される",
    ],
    beyond: `
**推測されにくいID（UUID など）にしても、認可チェックの代わりにはなりません。** IDが推測しづらいのは多層防御としては有効で、連番を総当たりされるリスクを下げます。ただし、URL はブラウザの履歴、アクセスログ、共有されたリンク、Referer などから漏れます。IDを知っている人が、持ち主かどうかは別の話です。認可チェックは、IDの形式に関係なく必ず入れます。

**認可の確認は、機能（画面）ごとではなく、リソースごとに毎回行います。** 「管理画面のメニューを出さない」「一覧に他人の分を出さない」だけでは、URL を直接叩かれると破られます。データ取得の SQL に持ち主の条件を入れてしまう書き方は、確認の書き忘れを減らす確実な方法です。権限の判断は、1か所の関数にまとめるのも有効です。

**他人のリソースは 403 ではなく 404 を返すと、存在の手がかりを減らせます。** 一方、管理画面のように「存在は誰でも知っている」機能は 403 で構いません。どちらにするかは、存在を隠す価値があるかで決めます。

**ログに何を残すかは設計事項です。** 認証の成功・失敗、認可の失敗、重要な操作（権限や配送先の変更、削除）は、あとから調査できるよう必ず残します。逆に、パスワード、セッションID、個人情報の全文は残さないようにします。入力値をログに入れるなら、改行などの制御文字を落とし、長さを制限して、ログ自体の偽造を防ぎます。実務では、ログを別の場所に集めて改ざんできないようにし、認可失敗が急に増えたら通知するなど、見る仕組みまで作って初めて役に立ちます。この演習の監査ログは、説明のためにアプリと同じ DB に入れています。

**関連する演習:** 認可の失敗が連続するログインは、ブルートフォースの兆候です（「ブルートフォース」の演習）。POST でデータを変える画面の保護は「CSRF」の演習で扱います。
`,
    quiz: [
      {
        q: "注文IDを連番ではなく UUID にすれば、認可チェックは要らなくなる？",
        a: "要ります。UUID は総当たりを難しくしますが、URL の漏えい（履歴・ログ・共有リンク・Referer）で他人に知られる可能性は残ります。IDを知っていることと、その注文の持ち主であることは別なので、サーバーで持ち主を毎回確かめるのが本命です。UUID は保険です。",
      },
      {
        q: "修正版で他人の注文に 403 ではなく 404 を返すのはなぜ？",
        a: "403 を返すと「その注文は存在するが、あなたには見せない」と教えることになり、IDの存在確認（列挙）に使われます。404 なら、他人の注文と存在しない注文が区別できません。管理画面のように存在を隠す意味がない機能は 403 で構いません。",
      },
      {
        q: "`role` Cookie に HttpOnly を付ければ、垂直権限昇格は防げる？",
        a: "防げません。HttpOnly は、ページ内の JavaScript から Cookie を読めなくするものです。利用者自身が開発者ツールやプロキシで値を書き換えることは止められません。ロールのような判断材料は、クライアントに持たせず、サーバー側のセッション（または改ざんを検出できる署名つきの値）から判定します。",
      },
    ],
  },
};
