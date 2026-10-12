import { describe, expect, it } from "vitest";
import { TOP_PASSWORDS } from "../src/lab/wordlist";
import { Browser } from "./helpers";
import { dbOf } from "./pw-helpers";

const V = "/x/bruteforce/vuln";
const F = "/x/bruteforce/fixed";

interface LoginJson {
  ok: boolean;
  status: "ok" | "fail" | "wait" | "locked";
  message: string;
  retryAfter?: number;
}

/** 攻撃ツール（/sim.js）と同じ形で、JSON の 1 試行 = 1 リクエスト */
async function login(b: Browser, base: string, username: string, password: string) {
  const res = await b.request(`${base}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json", "Sec-Fetch-Site": "same-origin" },
    body: JSON.stringify({ username, password }),
  });
  return { http: res.status, retryAfter: res.headers.get("Retry-After"), ...((await res.json()) as LoginJson) };
}

const advance = (b: Browser, seconds: number) =>
  b.request(`${F}/clock/advance`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      "Sec-Fetch-Site": "same-origin",
    },
    body: `seconds=${seconds}`,
  });

/** 失敗 → 待機 → … → ロックまでを、模擬時計を進めながら辿り、各リクエストの結果を並べる */
async function walk(b: Browser, username: string, password: string) {
  const out: string[] = [];
  const step = async () => {
    const r = await login(b, F, username, password);
    out.push(`${r.http}:${r.status}`);
    return r;
  };
  await step(); // 失敗 1
  await step(); // 失敗 2
  await step(); // 失敗 3 → 1 秒待機
  const w1 = await step(); // 待機
  await advance(b, w1.retryAfter ? Number(w1.retryAfter) : 1);
  await step(); // 失敗 4 → 2 秒待機
  const w2 = await step(); // 待機
  await advance(b, w2.retryAfter ? Number(w2.retryAfter) : 2);
  await step(); // 失敗 5 → ロック
  const l = await step(); // ロック
  out.push(`retryAfter>=59:${Number(l.retryAfter) >= 59}`);
  return out;
}

describe("ブルートフォース: 脆弱版", () => {
  it("ユーザーの有無でメッセージが違う（ユーザー列挙）", async () => {
    const b = new Browser();
    const noUser = await login(b, V, "nobody", "x");
    const badPass = await login(b, V, "alice", "x");
    expect(noUser.message).toBe("ユーザーが存在しません");
    expect(badPass.message).toBe("パスワードが違います");
    expect(noUser.http).toBe(401);
    expect(badPass.http).toBe(401);
  });

  it("回数制限がなく、辞書の 16 語目で alice のパスワードを破れる", async () => {
    const b = new Browser();
    let found = -1;
    const statuses = new Set<string>();
    for (let i = 0; i < TOP_PASSWORDS.length; i++) {
      const r = await login(b, V, "alice", TOP_PASSWORDS[i]);
      statuses.add(r.status);
      if (r.ok) {
        found = i + 1;
        expect(TOP_PASSWORDS[i]).toBe("letmein");
        break;
      }
    }
    expect(found).toBe(16);
    expect([...statuses].sort()).toEqual(["fail", "ok"]); // 待機もロックも一度も出ない
  });

  it("辞書にない長いパスワードの bob は、同じ辞書では破れない", async () => {
    const b = new Browser();
    for (const w of TOP_PASSWORDS) expect((await login(b, V, "bob", w)).ok).toBe(false);
  });

  it("失敗は何も記録されない（ログも失敗カウンタもない）", async () => {
    const b = new Browser();
    for (let i = 0; i < 8; i++) await login(b, V, "alice", `wrong${i}`);
    expect(await b.text(`${V}/log`)).toContain("何も記録されていません");
    const db = dbOf(b);
    expect((await db.first<{ n: number }>("SELECT COUNT(*) AS n FROM bruteforce_log"))?.n).toBe(0);
    expect((await db.first<{ n: number }>("SELECT COUNT(*) AS n FROM bruteforce_throttle"))?.n).toBe(0);
  });

  it("HTML のフォームからもログインできる（JSON 以外は HTML で返る）", async () => {
    const b = new Browser();
    const bad = await b.post(`${V}/login`, { username: "alice", password: "nope" });
    expect(bad.status).toBe(401);
    expect(bad.headers.get("Content-Type")).toContain("text/html");
    expect(await bad.text()).toContain("パスワードが違います");
    const ok = await b.post(`${V}/login`, { username: "alice", password: "letmein" });
    expect(ok.status).toBe(200);
    expect(await ok.text()).toContain("alice としてログインしました");
  });
});

describe("ブルートフォース: 修正版", () => {
  it("存在しないユーザーも、パスワード違いも、同じメッセージ・同じステータス", async () => {
    const b = new Browser();
    const noUser = await login(b, F, "nobody", "x");
    const badPass = await login(b, F, "alice", "x");
    expect(noUser.message).toBe(badPass.message);
    expect(noUser.http).toBe(401);
    expect(badPass.http).toBe(401);
    expect(noUser.status).toBe("fail");
    expect(badPass.status).toBe("fail");
  });

  it("連続して失敗すると待機を求められ、5 回失敗でロックされる。ロック中は正しいパスワードでも通らない", async () => {
    const b = new Browser();
    const seq = await walk(b, "alice", "wrong");
    expect(seq).toEqual([
      "401:fail", "401:fail", "401:fail", "429:wait",
      "401:fail", "429:wait",
      "401:fail", "429:locked", "retryAfter>=59:true",
    ]);
    const duringLock = await login(b, F, "alice", "letmein"); // 正しいパスワード
    expect(duringLock.http).toBe(429);
    expect(duringLock.status).toBe("locked");
    expect(duringLock.ok).toBe(false);
  });

  it("模擬時計を進めるとロックが解け、成功すると失敗の数が戻る", async () => {
    const b = new Browser();
    await walk(b, "alice", "wrong");
    await advance(b, 60);
    const ok = await login(b, F, "alice", "letmein");
    expect(ok.http).toBe(200);
    expect(ok.ok).toBe(true);
    // 失敗の数が 0 に戻っているので、また最初から数え直し（すぐ待機にはならない）
    expect((await login(b, F, "alice", "wrong")).http).toBe(401);
    expect((await login(b, F, "alice", "wrong")).http).toBe(401);
  });

  it("存在しないユーザー名にも同じ制限がかかる（ロックの有無で存在を推測できない）", async () => {
    const b = new Browser();
    expect(await walk(b, "alice", "wrong")).toEqual(await walk(b, "nobody", "wrong"));
  });

  it("辞書攻撃を即時連打しても、alice のパスワードには到達できない", async () => {
    const b = new Browser();
    const statuses: string[] = [];
    for (const w of TOP_PASSWORDS) statuses.push((await login(b, F, "alice", w)).status);
    expect(statuses).not.toContain("ok");
    expect(statuses.filter((s) => s === "fail").length).toBeLessThanOrEqual(5);
    expect(statuses).toContain("wait");
  });

  it("粘り強い攻撃者（待って再試行）は最終的に当てるが、模擬時計で 10 分以上かかる", async () => {
    const b = new Browser();
    let waited = 0;
    let found = "";
    outer: for (const w of TOP_PASSWORDS) {
      for (let retry = 0; retry < 5; retry++) {
        const r = await login(b, F, "alice", w);
        if (r.status === "wait" || r.status === "locked") {
          const s = Number(r.retryAfter) || 1;
          waited += s;
          await advance(b, s);
          continue;
        }
        if (r.ok) found = w;
        break;
      }
      if (found) break outer;
    }
    expect(found).toBe("letmein");
    expect(waited).toBeGreaterThanOrEqual(600);
  });

  it("同時に大量に送っても、すり抜けて検証されるのは最初の数回だけ", async () => {
    const b = new Browser();
    await login(b, F, "bob", "warmup-ignored"); // 初期ユーザーの投入と lab_id Cookie を先に済ませる
    const results = await Promise.all(Array.from({ length: 12 }, (_, i) => login(b, F, "alice", `guess-${i}`)));
    expect(results.filter((r) => r.http === 401).length).toBeLessThanOrEqual(3);
    expect(results.filter((r) => r.http === 429).length).toBeGreaterThanOrEqual(9);
  });

  it("すべての試行（成功・失敗・拒否）がログに残り、パスワードは残らない", async () => {
    const b = new Browser();
    await login(b, F, "alice", "secret-attempt-123");
    await login(b, F, "alice", "secret-attempt-456");
    await login(b, F, "alice", "secret-attempt-789"); // 3 回目の失敗 → 待機
    await login(b, F, "alice", "secret-attempt-000"); // 拒否
    await advance(b, 5);
    await login(b, F, "alice", "letmein"); // 成功
    const rows = await dbOf(b).all<{ outcome: string; username: string }>("SELECT outcome, username FROM bruteforce_log ORDER BY id");
    expect(rows.map((r) => r.outcome)).toEqual(["fail", "fail", "fail", "wait", "ok"]);
    const page = await b.text(`${F}/log`);
    expect(page).toContain("拒否（連続失敗による待機）");
    expect(page).toContain("alice");
    expect(page).not.toContain("secret-attempt");
    expect(page).not.toContain("letmein");
    expect(JSON.stringify(await dbOf(b).all("SELECT * FROM bruteforce_log"))).not.toContain("secret-attempt");
  });

  it("ユーザー名の大文字小文字でカウンタを迂回できない", async () => {
    const b = new Browser();
    await login(b, F, "alice", "x");
    await login(b, F, "ALICE", "x");
    const third = await login(b, F, "Alice", "x");
    expect(third.http).toBe(401); // 3 回目の失敗（ここで待機が始まる）
    expect((await login(b, F, "alice", "x")).http).toBe(429);
  });

  it("HTML のフォームからも同じ制限が効く", async () => {
    const b = new Browser();
    const res = await b.post(`${F}/login`, { username: "alice", password: "nope" });
    expect(res.status).toBe(401);
    expect(await res.text()).toContain("ユーザー名またはパスワードが違います");
  });
});

describe("ブルートフォース: 攻撃ツールとページ", () => {
  it("攻撃ツールは同一オリジンの /sim.js で配られ、ページから読み込まれる", async () => {
    const b = new Browser();
    for (const base of [V, F]) {
      const html = await b.text(`${base}/`);
      expect(html).toContain(`<script src="${base}/sim.js" defer></script>`);
      expect(html).toContain('id="sim"');
      const js = await b.get(`${base}/sim.js`);
      expect(js.headers.get("Content-Type")).toContain("javascript");
      const code = await js.text();
      expect(code).toContain('"letmein"');
      expect(code).toContain("data-endpoint");
      expect(code).not.toContain("eval(");
    }
    // 待って再試行するチェックボックスは修正版だけ
    expect(await b.text(`${F}/`)).toContain('id="sim-wait"');
    expect(await b.text(`${V}/`)).not.toContain('id="sim-wait"');
  });

  it("学習者ごとにデータが分かれる（片方のロックは、別のブラウザに影響しない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await walk(a, "alice", "wrong");
    expect((await login(a, F, "alice", "letmein")).http).toBe(429);
    const ok = await login(other, F, "alice", "letmein");
    expect(ok.http).toBe(200);
    expect(await other.text(`${F}/log`)).not.toContain("拒否（ロック中）");
  });

  it("解説ページが表示され、[!] の行がハイライトされる", async () => {
    const b = new Browser();
    const html = await b.text("/x/bruteforce");
    expect(html).toContain("ブルートフォース攻撃");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
  });
});
