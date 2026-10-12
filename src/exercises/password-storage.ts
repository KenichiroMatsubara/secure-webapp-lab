import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { hashPassword, iterationsFromEnv, measureMs, parseStoredHash, pbkdf2Hash, sha256Hex } from "../lab/crypto";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";
import { COMMON_PASSWORDS } from "../lab/wordlist";

/**
 * パスワードの保存。
 *
 *  - 脆弱版: ソルトなしの SHA-256 で保存（＋ 旧システムから移行した「平文」のユーザーが 1 人）
 *  - 修正版: ランダムなソルト＋ストレッチング（PBKDF2、反復回数は PBKDF2_ITERATIONS）で保存
 *  - /dump  … DB が漏えいした状態の模擬（stored 列をそのまま見せる）
 *  - /crack … 攻撃者の辞書攻撃の模擬。脆弱版は事前計算表を引くだけ、修正版はコストの見積もりだけを出す
 *
 * CPU 時間の注意: 1 リクエストで PBKDF2 を回すのは最大 2 回まで（初期ユーザーの投入は何回かに分ける）。
 */

const ID = "password-storage";
type Mode = "vuln" | "fixed";

const USERNAME_RE = /^[A-Za-z0-9_]{1,24}$/;
const MIN_LENGTH = 8;
const MAX_LENGTH = 128;
const MAX_USERS = 12;
/** 初期ユーザーの投入で 1 リクエストあたりに回す PBKDF2 の上限（無料プランの CPU 10ms 制限への配慮） */
const SEED_PBKDF2_BUDGET = 2;
/** 辞書に載っている語（修正版の「漏えいリストとの照合」の模擬に使う） */
const COMMON_SET = new Set(COMMON_PASSWORDS);

interface SeedUser {
  username: string;
  password: string;
  /** 平文のまま保存する（旧システムから移行した、さらに悪い例。脆弱版だけ） */
  plain?: boolean;
}

// 初期ユーザー（ダミー）。alice と dave は同じパスワード。carol は辞書にない長いパスフレーズ
const SEEDS: Record<Mode, SeedUser[]> = {
  vuln: [
    { username: "alice", password: "sunshine" },
    { username: "bob", password: "Password1" },
    { username: "carol", password: "correct horse battery staple" },
    { username: "dave", password: "sunshine" },
    { username: "legacy_user", password: "welcome1", plain: true },
  ],
  fixed: [
    { username: "alice", password: "sunshine" },
    { username: "dave", password: "sunshine" },
    { username: "bob", password: "Password1" },
    { username: "carol", password: "correct horse battery staple" },
  ],
};

interface UserRow {
  username: string;
  stored: string;
}

function usersOf(c: Context<AppEnv>, mode: Mode): Promise<UserRow[]> {
  return c.var.db.all<UserRow>("SELECT username, stored FROM password_storage_users WHERE mode = ? ORDER BY rowid", [
    mode,
  ]);
}

/**
 * 初期ユーザーを「足りない分だけ」投入する。ハッシュ計算が非同期なので seed SQL ではなくここで入れる。
 * 修正版は PBKDF2 が重いので 1 回に SEED_PBKDF2_BUDGET 人まで。残りは次のアクセスで入る（false を返す）。
 */
async function ensureSeeded(c: Context<AppEnv>, mode: Mode): Promise<boolean> {
  const have = new Set((await usersOf(c, mode)).map((r) => r.username));
  const iterations = iterationsFromEnv(c.env.PBKDF2_ITERATIONS);
  let budget = SEED_PBKDF2_BUDGET;
  for (const u of SEEDS[mode]) {
    if (have.has(u.username)) continue;
    let stored: string;
    if (u.plain) {
      stored = u.password;
    } else if (mode === "vuln") {
      stored = await sha256Hex(u.password);
    } else {
      if (budget-- <= 0) return false;
      stored = await hashPassword(u.password, iterations);
    }
    await c.var.db.run("INSERT OR IGNORE INTO password_storage_users (mode, username, stored) VALUES (?, ?, ?)", [
      mode,
      u.username,
      stored,
    ]);
  }
  return true;
}

type Result = "ok" | "dup" | "bad" | "weak" | "common" | "full";

const MESSAGES: Record<Result, [cls: string, text: string]> = {
  ok: ["ok", "登録しました。「DB 漏えいの模擬」で、保存された値を見てみましょう。"],
  dup: ["ng", "そのユーザー名はすでに使われています。"],
  bad: ["ng", "ユーザー名は英数字とアンダースコアで 1〜24 文字、パスワードは空でないものを入力してください。"],
  weak: ["ng", `パスワードは ${MIN_LENGTH} 文字以上 ${MAX_LENGTH} 文字以下にしてください（長さを重視するポリシー）。`],
  common: ["ng", "よくあるパスワード（漏えいリストに載っているもの）は使えません。別の言葉を選んでください。"],
  full: ["ng", `登録できるユーザーは ${MAX_USERS} 人までです。「すべての演習データを初期状態に戻す」でリセットできます。`],
};

const back = (c: Context<AppEnv>, mode: Mode, r: Result) => c.redirect(`/x/${ID}/${mode}/?r=${r}`, 303);

/** 登録の共通部分（ユーザー数の上限と重複を調べて保存する） */
async function save(c: Context<AppEnv>, mode: Mode, username: string, stored: string) {
  const users = await usersOf(c, mode);
  if (users.length >= MAX_USERS) return back(c, mode, "full");
  const { changes } = await c.var.db.run(
    "INSERT OR IGNORE INTO password_storage_users (mode, username, stored) VALUES (?, ?, ?)",
    [mode, username, stored],
  );
  return back(c, mode, changes ? "ok" : "dup");
}

async function readCredentials(c: Context<AppEnv>): Promise<{ username: string; password: string }> {
  const form = await c.req.parseBody();
  return { username: String(form["username"] ?? ""), password: String(form["password"] ?? "") };
}

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.post("/register", async (c) => {
  const { username, password } = await readCredentials(c);
  if (!USERNAME_RE.test(username) || !password) return back(c, "vuln", "bad"); // [!] パスワードの長さも強さも検査しない
  const stored = await sha256Hex(password); // [!] ソルトなしの高速ハッシュ。同じパスワードは必ず同じ値になり、事前計算表で一瞬で逆引きされる
  return save(c, "vuln", username, stored);
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

fixed.post("/register", async (c) => {
  const { username, password } = await readCredentials(c);
  if (!USERNAME_RE.test(username) || !password) return back(c, "fixed", "bad");
  // パスワードポリシー: 複雑さのルールより「長さ」と「漏えいリストに載っていないこと」を見る
  if (password.length < MIN_LENGTH || password.length > MAX_LENGTH) return back(c, "fixed", "weak");
  if (COMMON_SET.has(password) || COMMON_SET.has(password.toLowerCase())) return back(c, "fixed", "common");
  const stored = await hashPassword(password, iterationsFromEnv(c.env.PBKDF2_ITERATIONS)); // ユーザーごとのランダムなソルト＋反復（ストレッチング）
  return save(c, "fixed", username, stored);
});
//#endregion

// ---- 共通の画面（保存方法そのものではないので region の外） ----

const MONO_STYLE = `<style>.mono td{font-family:var(--mono);word-break:break-all}</style>`;

type Kind = "plain" | "sha256" | "pbkdf2";
function kindOf(stored: string): Kind {
  if (/^[0-9a-f]{64}$/.test(stored)) return "sha256";
  if (stored.startsWith("pbkdf2$")) return "pbkdf2";
  return "plain";
}

const KIND_LABEL: Record<Kind, string> = {
  plain: "平文（ハッシュですらない）",
  sha256: "ソルトなしの SHA-256",
  pbkdf2: "PBKDF2（ソルト付き）",
};

function seedNotice(complete: boolean): { head: string; html: string } {
  if (complete) return { head: "", html: "" };
  return {
    head: `<meta http-equiv="refresh" content="1">`,
    html: `<div class="notice">初期ユーザーを準備しています（ハッシュ計算を数回に分けています）。自動で再読み込みします。</div>`,
  };
}

function page(mode: Mode, title: string, body: string, head = "") {
  return exercisePage({ id: ID, mode, title, body, head: MONO_STYLE + head });
}

function home(mode: Mode) {
  return async (c: Context<AppEnv>) => {
    const complete = await ensureSeeded(c, mode);
    const users = await usersOf(c, mode);
    const r = c.req.query("r") as Result | undefined;
    const msg = r && Object.hasOwn(MESSAGES, r) ? MESSAGES[r] : undefined;
    const sn = seedNotice(complete);
    const how =
      mode === "vuln"
        ? "<code>SHA-256(パスワード)</code>（ソルトなし）"
        : `<code>PBKDF2-HMAC-SHA-256</code>（ランダムなソルト 16 バイト、反復 ${iterationsFromEnv(c.env.PBKDF2_ITERATIONS)} 回）`;
    const body = `<h1>会員登録（模擬）</h1>
<p>このアプリはパスワードを ${how} で保存します。ダミーのパスワードだけを入力してください。</p>
${sn.html}${msg ? `<p class="${msg[0]}">${escapeHtml(msg[1])}</p>` : ""}
<form method="post" action="/x/${ID}/${mode}/register">
  <label for="u">ユーザー名</label><input id="u" name="username" required maxlength="24" autocomplete="off">
  <label for="p">パスワード</label><input id="p" type="password" name="password" required maxlength="200" autocomplete="new-password">
  <p><button>登録</button></p>
</form>
<h2>登録済みのユーザー</h2>
${table(["ユーザー名"], users.map((u) => [u.username]))}
<h2>DB が漏えいしたら（攻撃者を演じるページ）</h2>
<ul>
  <li><a href="/x/${ID}/${mode}/dump">① DB 漏えいの模擬</a> … 表の中身（stored 列）をそのまま見る</li>
  <li><a href="/x/${ID}/${mode}/crack">② 攻撃者の辞書攻撃</a> … 漏えいした値からパスワードを割り出す</li>
</ul>`;
    return c.html(page(mode, "会員登録", body, sn.head));
  };
}

function dump(mode: Mode) {
  return async (c: Context<AppEnv>) => {
    const complete = await ensureSeeded(c, mode);
    const users = await usersOf(c, mode);
    const sn = seedNotice(complete);
    const rows = users.map((u) => {
      const same = users.filter((o) => o.stored === u.stored && o.username !== u.username).map((o) => o.username);
      const notes = [
        kindOf(u.stored) === "plain" ? KIND_LABEL.plain : "",
        same.length ? `${same.join(", ")} と同じ値` : "",
      ].filter(Boolean);
      return [u.username, u.stored, notes.join(" / ")];
    });
    const body = `<div class="notice notice--warn">ここは<strong>攻撃者側</strong>の視点です。SQL インジェクションやバックアップの流出などで、
<code>password_storage_users</code> 表がそのまま盗まれた状態を演じています（ラボの外へは何も送られません）。</div>
<h1>DB 漏えいの模擬</h1>
${sn.html}
<div class="mono">${table(["ユーザー名", "stored（保存されている値）", "気づくこと"], rows)}</div>
<p>同じ値が並んでいるユーザーはいませんか？ 値の見た目から、保存方法が分かりますか？</p>
<p><a href="/x/${ID}/${mode}/crack">② 攻撃者の辞書攻撃へ →</a> / <a href="/x/${ID}/${mode}/">← 会員登録へ</a></p>`;
    return c.html(page(mode, "DB 漏えいの模擬", body, sn.head));
  };
}

// 事前計算表（辞書の各語の SHA-256 → 語）。辞書は定数なので、一度作れば全員で使い回せる
let precomputed: Promise<Map<string, string>> | undefined;
function precomputedTable(): Promise<Map<string, string>> {
  precomputed ??= Promise.all(COMMON_PASSWORDS.map(async (w) => [await sha256Hex(w), w] as const)).then(
    (pairs) => new Map(pairs),
  );
  return precomputed;
}

function formatDuration(ms: number): string {
  const s = ms / 1000;
  if (s < 1) return "1 秒未満";
  if (s < 90) return `約 ${Math.round(s)} 秒`;
  if (s < 5400) return `約 ${Math.round(s / 60)} 分`;
  if (s < 129600) return `約 ${Math.round(s / 3600)} 時間`;
  return `約 ${Math.round(s / 86400)} 日`;
}

async function crackVuln(c: Context<AppEnv>) {
  const complete = await ensureSeeded(c, "vuln");
  const users = await usersOf(c, "vuln");
  const lookup = await precomputedTable();
  const sn = seedNotice(complete);

  const results = users.map((u) => {
    const kind = kindOf(u.stored);
    if (kind === "plain") return { u, text: `${u.stored}（平文なので、そのまま読める）`, cracked: true };
    const word = lookup.get(u.stored);
    return word
      ? { u, text: word, cracked: true }
      : { u, text: "辞書にない（この表では割り出せない）", cracked: false };
  });
  const cracked = results.filter((r) => r.cracked).length;
  const sample = [...lookup].slice(0, 6).map(([h, w]) => [`${h.slice(0, 20)}…`, w]);

  const body = `<div class="notice notice--warn">ここは<strong>攻撃者側</strong>の視点です。漏えいした表の値だけを使い、ダミーのユーザーを対象に辞書攻撃を演じます。</div>
<h1>攻撃者の辞書攻撃（脆弱版）</h1>
${sn.html}
<h2>① 事前計算表を作る</h2>
<p>よくあるパスワード ${COMMON_PASSWORDS.length} 語それぞれの SHA-256 を、先に計算して表にしておきます。ソルトがないので、この表は<strong>誰のパスワードにも使えます</strong>。</p>
<div class="mono">${table(["SHA-256（先頭 20 文字）", "元の語"], sample)}</div>
<p>…（全 ${lookup.size} 行）</p>
<h2>② 漏えいした値を表で引く</h2>
<div class="mono">${table(
    ["ユーザー名", "stored", "割り出したパスワード"],
    results.map((r) => [r.u.username, r.u.stored, r.text]),
  )}</div>
<p class="${cracked ? "ng" : "ok"}">${users.length} 人中 ${cracked} 人のパスワードが判明しました。使った計算は「表を引く」だけです。</p>
<ul>
  <li>ユーザーが増えても、表は作り直しません。1 人あたりのコストは <strong>ほぼゼロ</strong>です。</li>
  <li>同じパスワードを使う alice と dave は、同じ値なので<strong>まとめて</strong>判明します。</li>
  <li>辞書にない長いパスフレーズ（carol）は、この表では割り出せません。ただし、高速なハッシュは総当たりでも次々と試せてしまいます。</li>
</ul>
<p><a href="/x/${ID}/vuln/dump">← DB 漏えいの模擬</a> / <a href="/x/${ID}/vuln/">会員登録へ</a></p>`;
  return c.html(page("vuln", "攻撃者の辞書攻撃", body, sn.head));
}

async function crackFixed(c: Context<AppEnv>) {
  const complete = await ensureSeeded(c, "fixed");
  const users = await usersOf(c, "fixed");
  const iterations = iterationsFromEnv(c.env.PBKDF2_ITERATIONS);
  const sn = seedNotice(complete);

  // 1 ハッシュの所要時間を、このリクエストで「1 回だけ」測る。
  // Workers のタイマーは I/O のたびにしか進まないので、前後に DB 呼び出しを挟み、その往復分を差し引く
  const io = () => c.var.db.first("SELECT 1");
  const baseline = await measureMs(async () => {}, io);
  const withHash = await measureMs(() => pbkdf2Hash("benchmark", new Uint8Array(16), iterations), io);
  const perHashMs = Math.max(withHash - baseline, 1); // 1 ms 未満は 1 ms として切り上げる

  const words = COMMON_PASSWORDS.length;
  const scenarios: [string, number][] = [
    [`いまの設定（反復 ${iterations} 回）`, iterations],
    ["Workers で指定できる上限（反復 100000 回）", 100_000],
    ["推奨水準の目安（反復 600000 回。Workers の標準機能だけでは設定できない）", 600_000],
  ];
  const costRows = scenarios.map(([label, it]) => {
    const per = (perHashMs * it) / iterations;
    return [label, `${per.toFixed(1)} ms`, formatDuration(per * words * users.length)];
  });
  const saltRows = users.map((u) => {
    const p = parseStoredHash(u.stored);
    return [
      u.username,
      p ? `${p.saltHex.slice(0, 12)}…` : "（PBKDF2 形式ではない）",
      p ? String(p.iterations) : "-",
      "できない（ソルトが違うので、共通の表が使えない）",
    ];
  });

  const body = `<div class="notice notice--warn">ここは<strong>攻撃者側</strong>の視点です。修正版では実際の総当たりは行わず、かかるコストの見積もりだけを出します。</div>
<h1>攻撃者の辞書攻撃（修正版）</h1>
${sn.html}
<h2>① 事前計算表は使えるか</h2>
<div class="mono">${table(["ユーザー名", "ソルト（先頭 12 文字）", "反復回数", "事前計算表で逆引き"], saltRows)}</div>
<p>初期ユーザーの alice と dave は同じパスワードですが、ソルトが違うので保存された値はまったく別物です。攻撃者は<strong>ユーザーごとに</strong>、辞書の全語を計算し直さなければなりません。</p>
<h2>② 全員分の辞書攻撃にかかるコストの見積もり</h2>
<p>このサーバーで PBKDF2 を 1 回計算した実測は <strong>約 ${perHashMs} ms</strong> です（目安。1 ms 未満は切り上げ、DB の往復分は差し引いています）。</p>
<div class="mono">${table(["設定", "1 候補あたり", `辞書 ${words} 語 × ${users.length} ユーザーの合計`], costRows)}</div>
<ul>
  <li>脆弱版の「表を引くだけ」と比べて、攻撃者の仕事量は <strong>語数 × ユーザー数 × 反復回数</strong> に比例して増えます。</li>
  <li>この時間は「素直な実装を 1 台で動かした」場合の目安です。攻撃者は GPU などで桁違いに速く回せるので、守りの上限ではなく<strong>相対的な目安</strong>として見てください。</li>
</ul>
<p><a href="/x/${ID}/fixed/dump">← DB 漏えいの模擬</a> / <a href="/x/${ID}/fixed/">会員登録へ</a></p>`;
  return c.html(page("fixed", "攻撃者の辞書攻撃", body, sn.head));
}

vuln.get("/", home("vuln"));
fixed.get("/", home("fixed"));
vuln.get("/dump", dump("vuln"));
fixed.get("/dump", dump("fixed"));
vuln.get("/crack", crackVuln);
fixed.get("/crack", crackFixed);

export const exercise: Exercise = {
  id: ID,
  title: "パスワードの保存",
  summary: "ソルトなしのハッシュで保存すると、DB が漏れた瞬間に辞書攻撃で一斉にパスワードが割り出される。",
  level: 1,
  book: { chapter: 5, topic: "認証（パスワードの保存方法）" },
  schema: [
    `CREATE TABLE password_storage_users (
       mode TEXT NOT NULL,
       username TEXT NOT NULL,
       stored TEXT NOT NULL,
       PRIMARY KEY (mode, username)
     )`,
  ],
  vuln,
  fixed,
  doc: {
    goals: [
      "「ハッシュ化して保存した」だけでは足りない理由（高速なハッシュ・ソルトなし）を、実際の攻撃で説明できる",
      "ソルトとストレッチングが、それぞれ何を防ぐ仕組みなのかを区別できる",
      "Cloudflare Workers で使える PBKDF2 の限界を知り、実運用での選択肢（Argon2 / scrypt / 外部 IdP）を挙げられる",
    ],
    background: `
パスワードを平文で保存すると、データベースが漏れた瞬間に全ユーザーのパスワードがそのまま見えてしまいます。そこで「元に戻せない変換（ハッシュ）」をかけて保存するのが基本ですが、**ハッシュにしただけでは、まだ守れていません。**

SHA-256 のような汎用のハッシュは、大量のデータを速く処理するために作られています。速いということは、攻撃者が候補を次々と試せるということでもあります。さらにソルトがないと、「パスワード → ハッシュ」の対応表を先に作っておくだけで、どのユーザーにも使い回せます。同じパスワードを使っているユーザーは、保存された値も同じになるので、一目で見分けられてしまいます。

本当に守りたいのは「DB が漏れた後」の世界です。漏えいを前提に、**割り出すのに時間とお金がかかる形**で保存しておくことが、この演習のテーマです。
`,
    steps: [
      {
        title: "同じパスワードのユーザーを 2 人登録する",
        body: "脆弱版の会員登録で、ユーザーを 2 人作ります。パスワードはどちらも同じ言葉にします（ダミーのものを使ってください）。",
        payloads: [
          { label: "1 人目", value: "tester1 / sunshine" },
          { label: "2 人目", value: "tester2 / sunshine" },
        ],
        open: { label: "脆弱版を開く", href: "vuln/" },
      },
      {
        title: "DB 漏えいの模擬で、保存された値を見る",
        body: "漏えいした表の stored 列を見ます。tester1 と tester2、そして初期ユーザーの alice と dave に、同じ値が並んでいるはずです。さらに legacy_user は、ハッシュですらなく平文のまま保存されています。",
        open: { label: "DB 漏えいの模擬を開く", href: "vuln/dump" },
      },
      {
        title: "辞書攻撃で、パスワードを一斉に割り出す",
        body: "攻撃者の辞書攻撃のページを開きます。辞書の各語のハッシュを先に表にしておき、漏えいした値を引くだけで、辞書にあるパスワードがまとめて判明します。ユーザーが何人いても、表は作り直しません。",
        open: { label: "辞書攻撃を開く", href: "vuln/crack" },
      },
      {
        title: "自分のブラウザで検算する",
        body: "ブラウザの開発者ツールのコンソールで、`sunshine` の SHA-256 を計算します。出力が、漏えいした値と一致することを確かめます。「ハッシュは元に戻せない」けれど、「候補から計算して照合する」ことは誰にでもできます。",
        payloads: [
          {
            label: "コンソールに貼る",
            value:
              "crypto.subtle.digest('SHA-256', new TextEncoder().encode('sunshine')).then(b => console.log([...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('')))",
          },
        ],
      },
      {
        title: "修正版で同じことを試す",
        body: "修正版で、同じ条件の 2 人（`tester1` と `tester2`）を登録します。ただしパスワードは辞書にない 8 文字以上のものにします（`sunshine` はよくあるパスワードなので登録できません）。漏えいの模擬で、同じパスワードなのに値が別物になっていることを確かめます。",
        payloads: [
          { label: "1 人目", value: "tester1 / violet-bicycle-2049" },
          { label: "2 人目", value: "tester2 / violet-bicycle-2049" },
        ],
        open: { label: "修正版を開く", href: "fixed/" },
      },
      {
        title: "攻撃のコストを見積もる",
        body: "修正版の辞書攻撃のページを開きます。事前計算表が使えず、ユーザーごとに辞書の全語を計算し直す必要があること、1 回の計算にかかる時間と、全員分の見積もり時間を確かめます。反復回数が増えると、見積もりがどう変わるかにも注目してください。",
        open: { label: "修正版の辞書攻撃を開く", href: "fixed/crack" },
      },
    ],
    cause: `
原因は、保存時のハッシュの作り方にあります。ハイライトした行が問題です。

- 1行目: パスワードの長さも質も検査していません。1 文字のパスワードでも受け付けてしまいます。
- 2行目: ソルトなしの SHA-256 で保存しています。「速い」うえに「同じ入力なら必ず同じ出力」なので、(1) 事前計算した表を全ユーザーに使い回せる、(2) 同じパスワードのユーザーが一目で分かる、(3) 総当たりも高速に回せる、という弱点がそろいます。

さらに、旧システムから移行した legacy_user のように平文で残っている値があると、他の対策が正しくても、そこから全てが崩れます。
`,
    fix: `
パスワードは、**ソルト**と**ストレッチング**を備えた、パスワード保存用のアルゴリズムで保存します。この修正版では、Cloudflare Workers の WebCrypto で使える PBKDF2 を使いました。

- **ソルト**: ユーザーごとにランダムな値を混ぜてから計算します。同じパスワードでも結果が別物になり、共通の事前計算表が使えなくなります。ソルトは秘密にする必要はなく、ハッシュと一緒に保存します。
- **ストレッチング**: 計算を何千回も繰り返し、1 回あたりのコストをわざと大きくします。正規のログインは 1 回計算すればよいので影響は小さく、攻撃者の候補ごとのコストは反復回数ぶん増えます。
- 値には \`pbkdf2$反復回数$ソルト$ハッシュ\` の形式で、反復回数とソルトを一緒に記録します。あとで反復回数を増やしても、古いユーザーの検証が壊れません。

あわせて、パスワードポリシーを「長さ（8 文字以上）」と「よくあるパスワード（漏えいリスト）でないこと」に絞りました。保存の強さと、そもそも推測されにくいパスワードを選ばせることは、別々の対策です。
`,
    verify: [
      "修正版で同じパスワードの 2 人を登録し、漏えいの模擬で stored の値がまったく別物になっていることを確かめる",
      "修正版の stored が `pbkdf2$反復回数$ソルト$ハッシュ` の形式で、ソルトと反復回数が値の中に入っていることを確かめる",
      "修正版の辞書攻撃のページで、「事前計算表で逆引き: できない」と、全員分のコスト見積もりが出ることを確かめる",
      "修正版で `sunshine`（短い・よくあるパスワード）を登録しようとすると、ポリシーで拒否されることを確かめる",
      "どちらの画面にも、入力したパスワードがそのまま表示されないことを確かめる",
    ],
    beyond: `
**MD5 や SHA-1 を使った古いシステム。** かつて MD5 や SHA-1 で保存するシステムが広く使われました。どちらも今は「速すぎる」うえに衝突耐性の面でも弱いため、パスワード保存には使えません。WebCrypto には MD5 そのものがありませんが、既存システムの移行時にはよく出会います。移行は、ログインに成功した瞬間（平文のパスワードが手元にあるとき）に新方式で作り直して保存し直す方法が現実的です。

**ペッパー。** ペッパーは、DB とは別の場所（環境変数やシークレット管理）に置いた秘密の値を、ハッシュの計算に混ぜる方法です。DB だけが漏れた場合には効きますが、アプリのサーバーごと侵害されると意味がありません。ソルトの代わりにはならず、あくまで補助です。

**Workers で使える PBKDF2 の限界。** WebCrypto が提供するパスワード向けのアルゴリズムは PBKDF2 だけで、Cloudflare Workers では反復回数の上限が 100000 回です。OWASP が示す推奨の反復回数は、PBKDF2-HMAC-SHA-256 でこれよりずっと大きい値（数十万回の水準。版によって変わるので最新の資料を確認してください）です。さらに無料プランは CPU 時間が 1 リクエスト 10ms 程度なので、このラボでも既定は 10000 回に抑えています。実運用では、メモリを大量に使い GPU に強い **Argon2** や **scrypt** の WASM 実装を（CPU 制限を確認のうえ）使うか、パスワードを自前で持たずに **外部の IdP** へ任せることを検討してください。

**パスワードポリシー。** 「大文字・小文字・記号を必ず混ぜる」ような複雑さのルールより、**長さ**を重視し、**漏えいしたパスワードのリストと照合**して弾くほうが、効果が高いとされています。定期的な変更の強制は、かえって単純なパスワードを招きます。

**パスワードを見せない・残さない。** 入力欄は \`type="password"\`、確認画面や完了画面にパスワードを再表示しない、リクエストボディや例外をログ・エラー通知に丸ごと出力しない、URL に載せない、などを徹底します。

関連する演習: [ブルートフォース攻撃] ではログイン画面そのものへの総当たり、[パスワードリセット] ではパスワードを忘れたときの経路を扱います。
`,
    quiz: [
      {
        q: "SHA-256 はまだ安全なハッシュ関数なのに、パスワードの保存に使ってはいけないのはなぜ？",
        a: "SHA-256 自体が壊れているわけではなく、「速く計算できること」が問題だからです。攻撃者は候補を毎秒大量に試せます。さらにソルトがなければ事前計算表を全員に使い回せます。パスワード保存には、ソルトとストレッチングを備えた専用のアルゴリズムを使います。",
      },
      {
        q: "ソルトは秘密にしなければいけない？ ハッシュと同じ列に保存してよい？",
        a: "秘密にする必要はなく、ハッシュと一緒に保存してかまいません。ソルトの役目は「同じパスワードでも結果を別物にして、共通の事前計算表を使えなくする」ことで、秘密であることには依存しないからです。秘密の値を DB の外に置く方式はペッパーといい、別の補助的な対策です。",
      },
      {
        q: "反復回数を増やすと、正規ユーザーのログインは遅くならない？ 攻撃者にはどう効く？",
        a: "ログインでは 1 回計算するだけなので、体感できるほどの遅さにはなりません。一方、攻撃者は候補の数だけ計算が必要なので、総コストが反復回数に比例して増えます。ただし、サーバー側の CPU 制限（Workers の無料プランなど）や、同時ログインが多いときの負荷とのバランスを取る必要があります。",
      },
    ],
  },
};
