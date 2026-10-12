import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { hashPassword, iterationsFromEnv, verifyPassword } from "../lab/crypto";
import { escapeHtml, exercisePage, table } from "../lab/html";
import { advanceSimClock, formatOffset, simClockSchema, simNow } from "../lab/simclock";
import type { Exercise } from "../lab/types";
import { TOP_PASSWORDS } from "../lab/wordlist";

/**
 * ブルートフォース攻撃（認証の作り方）。
 *
 *  - 脆弱版: 回数制限なし／ユーザーの有無でメッセージが違う（ユーザー列挙）／失敗を記録しない
 *  - 修正版: 失敗の回数を数え、段階的な待機（バックオフ）と一時ロック／どの失敗も同じメッセージ／
 *           存在しないユーザーでも同じ重さの検証をする／すべての試行を bruteforce_log に記録する
 *  - 攻撃ツール（擬似）は同一オリジンの /sim.js（クライアント JS）。1 試行 = 1 リクエストで、対象はこのラボのダミーアカウントだけ
 *
 * CPU 時間の注意: ログイン 1 回につき PBKDF2 は 1 回だけ（存在しないユーザーでも 1 回）。
 */

const ID = "bruteforce";
type Mode = "vuln" | "fixed";

const CLOCK = "bruteforce_clock";
const clock = simClockSchema(CLOCK);

// ダミーのアカウント。alice は辞書の 16 番目の弱いパスワード、bob は辞書にない長いパスワード
const SEEDS = [
  { username: "alice", password: "letmein" },
  { username: "bob", password: "Zk7-mango-plume-42" },
];

// 列挙の攻撃ツールが試すユーザー名（よくある名前）
const NAMES = [
  "admin", "root", "test", "user", "guest", "info", "support", "webmaster", "alice", "bob",
  "carol", "dave", "eve", "mallory", "staff", "sales", "demo", "operator", "manager", "tanaka",
];

interface UserRow {
  username: string;
  stored: string;
}

const findUser = (c: Context<AppEnv>, mode: Mode, username: string) =>
  c.var.db.first<UserRow>("SELECT username, stored FROM bruteforce_users WHERE mode = ? AND username = ?", [
    mode,
    username,
  ]);

/** 表が空なら、ダミーのアカウントを入れる（ハッシュ計算が非同期なので seed SQL では入れない） */
async function ensureSeeded(c: Context<AppEnv>, mode: Mode): Promise<void> {
  const row = await c.var.db.first<{ n: number }>("SELECT COUNT(*) AS n FROM bruteforce_users WHERE mode = ?", [mode]);
  if (row && Number(row.n) > 0) return;
  const iterations = iterationsFromEnv(c.env.PBKDF2_ITERATIONS);
  for (const s of SEEDS) {
    await c.var.db.run("INSERT OR IGNORE INTO bruteforce_users (mode, username, stored) VALUES (?, ?, ?)", [
      mode,
      s.username,
      await hashPassword(s.password, iterations),
    ]);
  }
}

// ---- リクエストの読み取りと応答（JSON と HTML の両方を返せる） ----

async function readLogin(c: Context<AppEnv>): Promise<{ username: string; password: string }> {
  let src: Record<string, unknown> = {};
  try {
    const body = (c.req.header("Content-Type") ?? "").includes("json") ? await c.req.json() : await c.req.parseBody();
    if (body && typeof body === "object") src = body as Record<string, unknown>;
  } catch {
    src = {};
  }
  return { username: String(src["username"] ?? "").slice(0, 64), password: String(src["password"] ?? "").slice(0, 200) };
}

const wantsJson = (c: Context<AppEnv>) =>
  (c.req.header("Accept") ?? "").includes("application/json") || (c.req.header("Content-Type") ?? "").includes("json");

type Status = "ok" | "fail" | "wait" | "locked";
interface Reply {
  status: Status;
  http: 200 | 401 | 429;
  message: string;
  /** 待機・ロックのときに、あと何秒で再試行できるか */
  retryAfter?: number;
}

// 注意: Hono では、ハンドラーが生の Response を返すと、ミドルウェアが c.header()/setCookie() で積んだヘッダー
// （学習者を識別する lab_id Cookie など）が捨てられる。必ず c.body() / c.html() / c.json() で返すこと
function reply(c: Context<AppEnv>, mode: Mode, r: Reply) {
  const headers: Record<string, string> = {};
  if (r.retryAfter) headers["Retry-After"] = String(r.retryAfter);
  if (wantsJson(c)) {
    const json = { ok: r.status === "ok", status: r.status, message: r.message, retryAfter: r.retryAfter };
    return c.body(JSON.stringify(json), r.http, { ...headers, "Content-Type": "application/json; charset=UTF-8" });
  }
  const body = `<h1>ログイン結果</h1>
<p class="${r.status === "ok" ? "ok" : "ng"}">${escapeHtml(r.message)}</p>
<p><a href="/x/${ID}/${mode}/">← ログイン画面へ戻る</a></p>`;
  return c.body(exercisePage({ id: ID, mode, title: "ログイン結果", body }), r.http, {
    ...headers,
    "Content-Type": "text/html; charset=UTF-8",
  });
}

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.post("/login", async (c) => {
  await ensureSeeded(c, "vuln");
  const { username, password } = await readLogin(c);
  const user = await findUser(c, "vuln", username);
  if (!user) {
    return reply(c, "vuln", { status: "fail", http: 401, message: "ユーザーが存在しません" }); // [!] ユーザーの有無がメッセージで分かる（ユーザー列挙）。ハッシュの検証も省くので応答も速い
  }
  if (!(await verifyPassword(password, user.stored))) {
    return reply(c, "vuln", { status: "fail", http: 401, message: "パスワードが違います" }); // [!] 失敗を数えず、記録せず、回数も制限しない（総当たりし放題）
  }
  return reply(c, "vuln", { status: "ok", http: 200, message: `${user.username} としてログインしました` });
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

// 段階的な待機（指数バックオフ）と一時ロックの設計
const BACKOFF_FROM = 3; // 3 回目の失敗から待たせる（1 秒、2 秒、…）
const LOCK_AFTER = 5; // 5 回失敗したら一時ロック
const LOCK_MS = 60_000; // 体験用に 60 秒（本番は数分〜数十分）

// 「いま制限中か」の確認と「失敗として数える」更新を 1 文で行う（同時リクエストですり抜けられないように）。
// 先に失敗として数えて次の制限時刻を決めておき、成功したら元に戻す。制限中なら何も更新せず、行を返さない
const ACQUIRE_SQL = `INSERT INTO bruteforce_throttle (username, failed_count, locked_until) VALUES (?1, 1, 0)
ON CONFLICT(username) DO UPDATE SET
  failed_count = failed_count + 1,
  locked_until = CASE
    WHEN failed_count + 1 >= ${LOCK_AFTER} THEN ?2 + ${LOCK_MS}
    WHEN failed_count + 1 >= ${BACKOFF_FROM} THEN ?2 + (1000 << (failed_count + 1 - ${BACKOFF_FROM}))
    ELSE 0 END
WHERE locked_until <= ?2
RETURNING failed_count, locked_until`;

fixed.post("/login", async (c) => {
  await ensureSeeded(c, "fixed");
  const { username, password } = await readLogin(c);
  const name = username.trim().toLowerCase(); // 制限の単位は正規化したユーザー名（大文字小文字でカウンタを迂回させない）
  const now = await simNow(c.var.db, CLOCK);

  // 1) 制限中なら、パスワードを検証せずに断る。カウンタは存在しないユーザー名にも同じように持つ
  const slot = await c.var.db.first<{ failed_count: number }>(ACQUIRE_SQL, [name, now]);
  if (!slot) {
    const t = await c.var.db.first<{ failed_count: number; locked_until: number }>(
      "SELECT failed_count, locked_until FROM bruteforce_throttle WHERE username = ?",
      [name],
    );
    const status: Status = Number(t?.failed_count) >= LOCK_AFTER ? "locked" : "wait";
    const retryAfter = Math.max(1, Math.ceil((Number(t?.locked_until) - now) / 1000));
    await logAttempt(c, now, name, status);
    return reply(c, "fixed", { status, http: 429, message: "ログインの試行が多すぎます。しばらくしてからやり直してください。", retryAfter });
  }

  // 2) 存在しないユーザーでも同じ重さの検証をして、応答時間の差から存在を見抜かれないようにする
  const user = await findUser(c, "fixed", name);
  const ok = await verifyPassword(password, user?.stored ?? dummyHash(iterationsFromEnv(c.env.PBKDF2_ITERATIONS)));

  if (!user || !ok) {
    await logAttempt(c, now, name, "fail");
    return reply(c, "fixed", { status: "fail", http: 401, message: "ユーザー名またはパスワードが違います" }); // どちらが違っても同じ文言
  }

  // 3) 成功したら失敗の数を戻す
  await c.var.db.run("UPDATE bruteforce_throttle SET failed_count = 0, locked_until = 0 WHERE username = ?", [name]);
  await logAttempt(c, now, name, "ok");
  return reply(c, "fixed", { status: "ok", http: 200, message: `${user.username} としてログインしました` });
});
//#endregion

/** 存在しないユーザー用の検証対象（反復回数だけ本物と同じ。必ず不一致になる） */
const dummyHash = (iterations: number) => `pbkdf2$${iterations}$${"00".repeat(16)}$${"00".repeat(32)}`;

/** 試行の記録（修正版だけ）。パスワードは記録しない。古い記録は 300 件を超えたら捨てる */
async function logAttempt(c: Context<AppEnv>, at: number, username: string, outcome: Status): Promise<void> {
  await c.var.db.run("INSERT INTO bruteforce_log (at, username, outcome) VALUES (?, ?, ?)", [at, username, outcome]);
  await c.var.db.run("DELETE FROM bruteforce_log WHERE id <= (SELECT MAX(id) FROM bruteforce_log) - 300");
}

// ---- 攻撃ツール（擬似）: ブラウザで動くクライアント JS。/sim.js として同一オリジンから配る ----
// 1 試行 = 1 リクエスト。送り先はこのラボの /login だけで、対象はダミーアカウントだけ
const SIM_JS = `(function () {
  "use strict";
  var root = document.getElementById("sim");
  if (!root) return;
  var endpoint = root.getAttribute("data-endpoint");
  var clockUrl = root.getAttribute("data-clock");
  var WORDS = ${JSON.stringify(TOP_PASSWORDS)};
  var NAMES = ${JSON.stringify(NAMES)};
  var LABEL = { ok: "成功", fail: "失敗", wait: "待機を要求された", locked: "ロックされた", error: "エラー" };
  var el = function (id) { return document.getElementById(id); };
  var body = el("sim-body"), summary = el("sim-summary"), result = el("sim-result");
  var startBtn = el("sim-start"), stopBtn = el("sim-stop");
  var stopped = false;
  var n, counts, virtualWait, t0;

  function reset() {
    n = 0; counts = { ok: 0, fail: 0, wait: 0, locked: 0, error: 0 }; virtualWait = 0; t0 = performance.now();
    body.textContent = ""; result.textContent = ""; result.className = "";
  }

  function showSummary() {
    var sec = ((performance.now() - t0) / 1000).toFixed(1);
    summary.textContent = "試行 " + n + " 回 / 成功 " + counts.ok + " / 失敗 " + counts.fail +
      " / 待機 " + counts.wait + " / ロック " + counts.locked +
      " / 実時間 " + sec + " 秒" + (virtualWait ? " / 模擬時計で待った時間 " + virtualWait + " 秒" : "");
  }

  function addRow(cells, cls) {
    var tr = document.createElement("tr");
    if (cls) tr.className = cls;
    cells.forEach(function (text) {
      var td = document.createElement("td");
      td.textContent = String(text);
      tr.appendChild(td);
    });
    body.appendChild(tr);
    tr.scrollIntoView({ block: "nearest" });
  }

  async function attempt(user, pass) {
    var started = performance.now();
    var res, data = {};
    try {
      res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ username: user, password: pass })
      });
      data = await res.json();
    } catch (e) {
      data = { status: "error", message: "通信エラー" };
    }
    var status = data.status || "error";
    n++; counts[status] = (counts[status] || 0) + 1;
    var r = { http: res ? res.status : 0, ms: Math.round(performance.now() - started), status: status,
      message: data.message || "", retryAfter: data.retryAfter || 0 };
    addRow([n, user + " / " + pass, r.http, LABEL[status] || status, r.message, r.ms], "sim-" + status);
    showSummary();
    return r;
  }

  async function advance(seconds) {
    virtualWait += seconds;
    await fetch(clockUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
      body: "seconds=" + encodeURIComponent(seconds)
    });
  }

  async function runPassword(user, waitMode) {
    for (var i = 0; i < WORDS.length && !stopped; i++) {
      var r;
      for (var retry = 0; retry < 5; retry++) {
        r = await attempt(user, WORDS[i]);
        if ((r.status === "wait" || r.status === "locked") && waitMode && !stopped) {
          await advance(r.retryAfter || 1);
          continue;
        }
        break;
      }
      if (r.status === "ok") {
        result.className = "ng";
        result.textContent = "突破されました: " + user + " のパスワードは「" + WORDS[i] + "」です（辞書の " + (i + 1) + " 語目）。";
        return;
      }
    }
    result.className = "ok";
    result.textContent = stopped ? "停止しました。" : "辞書の " + WORDS.length + " 語を試しましたが、突破できませんでした。";
  }

  async function runEnum() {
    var groups = {};
    for (var i = 0; i < NAMES.length && !stopped; i++) {
      var r = await attempt(NAMES[i], "wrong-password-xyz");
      if (r.status === "wait" || r.status === "locked") continue;
      (groups[r.message] = groups[r.message] || []).push(NAMES[i]);
    }
    var keys = Object.keys(groups);
    if (keys.length < 2) {
      result.className = "ok";
      result.textContent = "どのユーザー名にも同じ応答が返りました。存在するアカウントは判別できません。";
      return;
    }
    keys.sort(function (a, b) { return groups[b].length - groups[a].length; });
    var found = [];
    keys.slice(1).forEach(function (k) { found = found.concat(groups[k]); });
    result.className = "ng";
    result.textContent = "応答の違いから、存在するアカウントを見つけました: " + found.join(", ") + "（「" + keys[0] + "」と返ってくるものは存在しない）";
  }

  startBtn.addEventListener("click", async function () {
    var mode = document.querySelector("input[name=simmode]:checked").value;
    var user = el("sim-user").value || "alice";
    var waitBox = el("sim-wait");
    stopped = false; reset();
    startBtn.disabled = true; stopBtn.disabled = false;
    try {
      if (mode === "enum") await runEnum();
      else await runPassword(user, !!(waitBox && waitBox.checked));
    } finally {
      startBtn.disabled = false; stopBtn.disabled = true; showSummary();
    }
  });
  stopBtn.addEventListener("click", function () { stopped = true; });
})();
`;

// ---- 画面（共通） ----

const OUTCOME_LABEL: Record<string, string> = {
  ok: "成功",
  fail: "失敗",
  wait: "拒否（連続失敗による待機）",
  locked: "拒否（ロック中）",
};

const SIM_STYLE = `<style>
.mono td{font-family:var(--mono);word-break:break-all}
#sim-body tr.sim-ok td{background:var(--vuln-bg)}
#sim-body tr.sim-wait td,#sim-body tr.sim-locked td{background:var(--hl)}
.sim-scroll{max-height:340px;overflow:auto}
</style>`;

function home(mode: Mode) {
  return async (c: Context<AppEnv>) => {
    await ensureSeeded(c, mode);
    const isFixed = mode === "fixed";
    const offset = isFixed
      ? Number((await c.var.db.first<{ offset_ms: number }>(`SELECT offset_ms FROM ${CLOCK} WHERE id = 1`))?.offset_ms ?? 0)
      : 0;
    const waitOption = isFixed
      ? `<label><input type="checkbox" id="sim-wait"> 制限されたら、模擬時計を進めて待ってから再試行する（粘り強い攻撃者）</label>`
      : "";
    const clockPanel = isFixed
      ? `<h2>模擬時計</h2>
<p>ロックや待機を本当に待たなくて済むよう、このラボの時計を進められます。いまの状態: <strong>${escapeHtml(formatOffset(offset))}</strong></p>
<form method="post" action="/x/${ID}/fixed/clock/advance" class="actions">
  <input type="hidden" name="seconds" value="60"><button class="ghost">60 秒進める</button>
</form>`
      : "";
    const body = `<h1>ログイン（模擬）</h1>
<p>ダミーのアカウント <code>alice</code> と <code>bob</code> があります（パスワードは非公開です）。</p>
<form method="post" action="/x/${ID}/${mode}/login">
  <label for="u">ユーザー名</label><input id="u" name="username" required maxlength="64" autocomplete="off">
  <label for="p">パスワード</label><input id="p" type="password" name="password" required maxlength="200" autocomplete="off">
  <p><button>ログイン</button></p>
</form>
<p><a href="/x/${ID}/${mode}/log">ログイン試行のログを見る</a></p>
<h2>攻撃ツール（擬似）</h2>
<div class="notice notice--warn">このラボの<strong>ダミーアカウントだけ</strong>を対象にした、擬似の攻撃ツールです。辞書の語を 1 つずつ、1 回ずつこのページのログインへ送り、結果をリアルタイムに表示します。</div>
<div id="sim" data-endpoint="/x/${ID}/${mode}/login" data-clock="/x/${ID}/${mode}/clock/advance">
  <fieldset><legend>モード</legend>
    <label><input type="radio" name="simmode" value="password" checked> パスワード辞書攻撃（よくあるパスワード ${TOP_PASSWORDS.length} 語）</label>
    <label><input type="radio" name="simmode" value="enum"> ユーザー名の列挙（存在するアカウントを探す。${NAMES.length} 個の名前を 1 回ずつ試す）</label>
  </fieldset>
  <label for="sim-user">標的のユーザー名（辞書攻撃のとき）</label><input id="sim-user" value="alice" maxlength="64">
  ${waitOption}
  <p><button type="button" id="sim-start">攻撃を開始</button> <button type="button" id="sim-stop" class="ghost" disabled>停止</button></p>
  <p id="sim-summary" aria-live="polite">待機中</p>
  <p id="sim-result" aria-live="polite"></p>
  <div class="sim-scroll mono"><table class="data"><thead><tr><th>#</th><th>試した ユーザー名 / パスワード</th><th>HTTP</th><th>結果</th><th>サーバーの応答</th><th>応答時間(ms)</th></tr></thead>
  <tbody id="sim-body"></tbody></table></div>
</div>
${clockPanel}`;
    return c.html(
      exercisePage({
        id: ID,
        mode,
        title: "ログイン",
        body,
        head: `${SIM_STYLE}<script src="/x/${ID}/${mode}/sim.js" defer></script>`,
      }),
    );
  };
}

const simJs = (c: Context<AppEnv>) => c.body(SIM_JS, 200, { "Content-Type": "text/javascript; charset=UTF-8" });

/** ログイン試行のログ。脆弱版は何も記録していない。修正版は bruteforce_log を見せる */
function logPage(mode: Mode) {
  return async (c: Context<AppEnv>) => {
    await ensureSeeded(c, mode);
    let body: string;
    if (mode === "vuln") {
      body = `<h1>ログイン試行のログ</h1>
<p class="ng">何も記録されていません。このアプリはログインの失敗を記録していないので、総当たり攻撃を受けても<strong>気づけません</strong>。</p>`;
    } else {
      const rows = await c.var.db.all<{ at: number; username: string; outcome: string }>(
        "SELECT at, username, outcome FROM bruteforce_log ORDER BY id DESC LIMIT 60",
      );
      const sums = await c.var.db.all<{ username: string; fail: number; blocked: number; ok: number }>(
        `SELECT username,
           SUM(outcome = 'fail') AS fail, SUM(outcome IN ('wait','locked')) AS blocked, SUM(outcome = 'ok') AS ok
         FROM bruteforce_log GROUP BY username ORDER BY fail DESC, blocked DESC LIMIT 10`,
      );
      const time = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 19) + " UTC";
      body = `<h1>ログイン試行のログ</h1>
<p>すべての試行（成功・失敗・拒否）を <code>bruteforce_log</code> 表に記録しています。パスワードは記録しません。同じユーザー名への失敗が続いていれば、攻撃の兆候として検知・通知できます。</p>
<h2>ユーザー名ごとの集計</h2>
${rows.length ? table(["ユーザー名", "失敗", "拒否", "成功"], sums.map((s) => [s.username, Number(s.fail), Number(s.blocked), Number(s.ok)])) : "<p>まだ試行がありません。</p>"}
<h2>新しい順（最大 60 件）</h2>
${rows.length ? table(["時刻（模擬時計）", "ユーザー名", "結果"], rows.map((r) => [time(Number(r.at)), r.username, OUTCOME_LABEL[r.outcome] ?? r.outcome])) : ""}`;
    }
    return c.html(
      exercisePage({
        id: ID,
        mode,
        title: "ログイン試行のログ",
        body: `${body}\n<p><a href="/x/${ID}/${mode}/">← ログイン画面へ</a></p>`,
      }),
    );
  };
}

vuln.get("/", home("vuln"));
fixed.get("/", home("fixed"));
vuln.get("/sim.js", simJs);
fixed.get("/sim.js", simJs);
vuln.get("/log", logPage("vuln"));
fixed.get("/log", logPage("fixed"));

// 模擬時計を進める（修正版だけ。時間に依存する挙動を、待たずに体験・テストするため）。自分の DB の中だけに効く
fixed.post("/clock/advance", async (c) => {
  const form = await c.req.parseBody();
  await advanceSimClock(c.var.db, CLOCK, Number(form["seconds"]) * 1000);
  if ((c.req.header("Accept") ?? "").includes("application/json")) return c.json({ ok: true });
  return c.redirect(`/x/${ID}/fixed/`, 303);
});

export const exercise: Exercise = {
  id: ID,
  title: "ブルートフォース攻撃",
  summary: "ログインに回数制限がないと、辞書を使った総当たりでパスワードを破られ、メッセージの違いから存在するアカウントも見抜かれる。",
  level: 2,
  book: { chapter: 5, topic: "認証（ログイン機能・総当たり攻撃対策）" },
  schema: [
    `CREATE TABLE bruteforce_users (
       mode TEXT NOT NULL,
       username TEXT NOT NULL,
       stored TEXT NOT NULL,
       PRIMARY KEY (mode, username)
     )`,
    // 修正版だけが使う。ユーザー名ごとの失敗回数と、いつまで制限するか（存在しないユーザー名にも同じように持つ）
    `CREATE TABLE bruteforce_throttle (
       username TEXT PRIMARY KEY,
       failed_count INTEGER NOT NULL DEFAULT 0,
       locked_until INTEGER NOT NULL DEFAULT 0
     )`,
    // 修正版だけが使う。ログイン試行のログ
    `CREATE TABLE bruteforce_log (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       at INTEGER NOT NULL,
       username TEXT NOT NULL,
       outcome TEXT NOT NULL
     )`,
    ...clock.schema,
  ],
  seed: clock.seed,
  vuln,
  fixed,
  doc: {
    goals: [
      "回数制限のないログインが、辞書を使った総当たりでどれくらい簡単に破られるかを体験する",
      "メッセージ・応答時間の違いから、存在するアカウントが見抜かれる仕組み（ユーザー列挙）を説明できる",
      "失敗回数の記録・段階的な待機・一時ロック・ログという組み合わせと、それぞれの弱点（ロックを悪用した妨害）を説明できる",
    ],
    background: `
ブルートフォース攻撃（総当たり）は、パスワードの候補を片っぱしからログイン画面に送り、当たるまで試す攻撃です。実際には完全な総当たりより、**よく使われるパスワードの辞書**を使うことが多く、弱いパスワードのアカウントは数十回の試行で破られます。

ログインの作り方によっては、攻撃者の仕事がさらに楽になります。「ユーザーが存在しません」と「パスワードが違います」を出し分けていると、攻撃者はまず**存在するアカウントの一覧**を作り、そこだけに集中できます。メッセージが同じでも、存在しないときだけ処理が速い（パスワードの検証を省く）と、応答時間の差から同じことができます。

さらに、失敗を記録していなければ、攻撃を受けていても運営側は気づけません。
`,
    steps: [
      {
        title: "メッセージの違いを確かめる",
        body: "脆弱版のログイン画面で、まず存在するユーザーに間違ったパスワードを、次に存在しないユーザー名を入れてみます。表示されるメッセージを比べてください。",
        payloads: [
          { label: "1 回目", value: "alice / wrong-password" },
          { label: "2 回目", value: "nobody / wrong-password" },
        ],
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "ユーザー名を列挙する",
        body: "ページ下の攻撃ツールで「ユーザー名の列挙」を選び、攻撃を開始します。20 個の名前を 1 回ずつ試し、応答が違う名前＝存在するアカウントを見つけます。各行の応答時間（ms）にも、存在するユーザーとの差が出ていないか見てみましょう。",
        open: { label: "攻撃ツールのある脆弱版を開く", href: "vuln/" },
      },
      {
        title: "辞書攻撃でパスワードを破る",
        body: "「パスワード辞書攻撃」を選び、標的を `alice` にして開始します。1 回の失敗も止められず、辞書の何語目で破れるか、何秒かかったかが表示されます。同じ辞書で `bob` も試し、破れない理由を考えてみましょう。",
        payloads: [
          { label: "標的", value: "alice" },
          { label: "もう一人", value: "bob" },
        ],
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "ログを探す",
        body: "攻撃の直後に、脆弱版の「ログイン試行のログ」を開きます。数十回の失敗が、まったく記録されていません。",
        open: { label: "脆弱版のログを開く", href: "vuln/log" },
      },
      {
        title: "修正版で同じ攻撃を試す（即時連打）",
        body: "修正版で、まず列挙を実行します。どの名前にも同じ応答が返り、アカウントの有無が分かりません。次に `alice` への辞書攻撃を「即時連打」で実行します。3 回目の失敗から「待機」を要求され、続けて試してもすべて拒否されます。",
        open: { label: "修正版を開く", href: "fixed/" },
      },
      {
        title: "粘り強い攻撃者と、ログ",
        body: "修正版のチェックボックス「制限されたら、模擬時計を進めて待ってから再試行する」を入れて辞書攻撃をやり直します（先に「60 秒進める」を押して、前回の制限を解いておきます）。攻撃は最終的に成功しますが、模擬時計で 10 分あまりかかります。ロックは攻撃を遅らせるだけで、弱いパスワードそのものは守れません。最後に、修正版のログを開き、攻撃の痕跡が残っていることを確かめます。",
        open: { label: "修正版のログを開く", href: "fixed/log" },
      },
    ],
    cause: `
脆弱版のログイン処理には、問題が 3 つあります（ハイライトした行）。

- **ユーザー列挙**: 存在しないユーザーには「ユーザーが存在しません」を返し、パスワードの検証も省きます。メッセージも応答時間も、アカウントの有無を教えてしまいます。
- **試行回数の制限がない**: 何回失敗しても同じ速さで次を試せます。辞書の語を 1 つずつ送るだけで、弱いパスワードは破られます。
- **失敗を記録しない**: 失敗を数えも残しもしないので、攻撃の最中にも、あとからも気づけません。
`,
    fix: `
修正版は、次の 4 点を組み合わせています。

1. **失敗の回数を数え、段階的に制限する。** 3 回目の失敗から 1 秒、2 秒…と待たせ（指数バックオフ）、5 回失敗したら 60 秒ロックします。制限中は、パスワードの正誤を検証せずに断ります（正しいパスワードを送っても通りません）。「制限中か」の確認と「失敗として数える」更新は、同時リクエストですり抜けられないよう、SQL 1 文で行っています。
2. **どの失敗も同じメッセージにする。** 存在しないユーザーも、パスワードが違うユーザーも、「ユーザー名またはパスワードが違います」です。失敗の数は存在しないユーザー名にも同じように持つので、「ロックされた＝存在する」とも推測できません。
3. **存在しないユーザーでも同じ重さの検証をする。** ダミーのハッシュに対して PBKDF2 を 1 回計算し、応答時間を揃えます。
4. **すべての試行をログに残す。** 成功・失敗・拒否を \`bruteforce_log\` に記録します（パスワードは記録しない）。

アカウントロックは諸刃の剣で、攻撃者が他人のアカウントにわざと失敗を重ねれば、本人がログインできなくなります（ロックを使った妨害）。そのため、ロックだけに頼らず、短い待機から段階的に伸ばすバックオフを併用しています。
`,
    verify: [
      "修正版の列挙で、全ユーザー名に同じ応答が返り、存在するアカウントを判別できない",
      "修正版で `alice` に即時連打すると、3 回目の失敗以降は「待機」や「ロック」で拒否され、辞書の最後まで到達しても破れない",
      "ロック中は、正しいパスワードを送ってもログインできない（制限が検証より先に効く）",
      "「60 秒進める」で模擬時計を進めると、ロックが解け、再び試行できる",
      "修正版のログに、成功・失敗・拒否が時刻つきで残り、パスワードは含まれていない",
    ],
    beyond: `
**アカウント単位の制限には限界があります。** 同じ IP から多数のアカウントに 1〜2 回ずつ試す**パスワードスプレー**（弱い共通のパスワードを広く試す）や、他サイトから漏えいした ID とパスワードの組を使う**クレデンシャルスタッフィング**（パスワードの使い回しを狙う）は、1 つのアカウントの失敗回数が閾値に届かないため、アカウントロックでは防げません。どちらも、IP・端末・時間帯など別の軸での制限と、使い回しを防ぐ仕組みが必要です。

**実務で足す対策。**
- **IP とアカウントの両方でレート制限する。** Cloudflare なら、アプリの前段に WAF のレート制限ルールを置けます。人間かどうかの確認（Cloudflare Turnstile など）を、失敗が続いたときだけ出す方法もあります。
- **多要素認証（MFA）を用意する。** パスワードが破られても、ログインを許しません。パスキーも有力な選択肢です。
- **ログを検知につなげる。** 失敗の急増を通知し、本人にも「ログインに失敗しました」と知らせます。ログにパスワードを残してはいけません。

**ロック設計の細部。** ロックを「いつ解くか」（時間経過か、メールの本人確認か）、失敗カウンタを時間とともに減らすか、ロックの通知、同時リクエストでカウンタをすり抜けられないか、全角・半角や大文字・小文字の違いで別アカウント扱いになっていないか、などを詰める必要があります。

**ユーザー列挙は、ログイン以外の画面にも潜んでいます。** 会員登録（「すでに使われています」）、パスワードリセット（「登録されていません」）も同じです。次の演習「パスワードリセット」で扱います。
`,
    quiz: [
      {
        q: "アカウントロックだけで総当たり対策は十分？ どんな問題が残る？",
        a: "十分ではありません。攻撃者が他人のアカウントにわざと失敗を重ねると、本人がログインできなくなります（ロックを使った妨害）。また、1 つのアカウントへの失敗が少ないパスワードスプレーやクレデンシャルスタッフィングには効きません。バックオフ、IP などの別軸のレート制限、MFA、ログによる検知を組み合わせます。",
      },
      {
        q: "存在しないユーザーのときも、わざとパスワードの検証（ダミーのハッシュ計算）をするのはなぜ？",
        a: "存在するときだけハッシュの計算に時間がかかると、メッセージを同じにしても、応答時間の差からアカウントの有無を見抜かれます。ダミーの検証で処理時間を揃えて、これを防ぎます。",
      },
      {
        q: "修正版で攻撃者が「待ってから再試行」して最終的にパスワードを当てた。これは対策の失敗？",
        a: "ロックは攻撃を遅らせて検知の時間を稼ぐ仕組みで、弱いパスワードそのものを強くするものではありません。破られる前にログから攻撃に気づく、MFA で二段目の壁を作る、弱いパスワードを登録時に弾く（パスワードの保存の演習のポリシー）、といった対策を重ねる必要があります。",
      },
    ],
  },
};
