import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { LabDO } from "../src/lab/db";
import { Browser } from "./helpers";

// wrangler.jsonc の Durable Object バインディング（テストでは型が生成されないので手で付ける）
const LAB = (env as unknown as { LAB: DurableObjectNamespace<LabDO> }).LAB;

type Mode = "vuln" | "fixed";
const base = (mode: Mode) => `/x/authz/${mode}`;

const PW: Record<string, string> = { alice: "alice-pass", bob: "bob-pass", admin: "admin-pass" };
const BOB_ADDRESS = "大阪府大阪市ダミー区4-5-6 サンプルハイツ202";
const ALICE_ADDRESS = "東京都千代田区サンプル町1-2-3 テストビル101";

async function login(b: Browser, mode: Mode, username: string, password = PW[username]) {
  return b.post(`${base(mode)}/login`, { username, password });
}

/** 指定ユーザーでログイン済みの、新しい学習者のブラウザ */
async function loggedIn(mode: Mode, username: string): Promise<Browser> {
  const b = new Browser();
  const res = await login(b, mode, username);
  expect(res.status).toBe(303);
  return b;
}

/** 同じ学習者（同じDB）の別ユーザー役。lab_id Cookie を共有する */
function sameLearner(b: Browser): Browser {
  const other = new Browser();
  other.jar.set("lab_id", b.cookie("lab_id")!);
  return other;
}

/** 監査ログの生の行（画面に出ないものも含めて確認する） */
async function auditRows(b: Browser): Promise<{ mode: string; user: string; action: string; detail: string }[]> {
  const stub = LAB.get(LAB.idFromName(`c:${b.cookie("lab_id")}`));
  return (await stub.all("SELECT mode, user, action, detail FROM authz_audit ORDER BY id")) as never;
}

describe("認可不備: 脆弱版", () => {
  it("ログインすると、HttpOnly のセッションCookieと、JSから読める role Cookie が発行される", async () => {
    const b = new Browser();
    const res = await login(b, "vuln", "alice");
    expect(res.status).toBe(303);
    const cookies = res.headers.getSetCookie();
    const sid = cookies.find((c) => c.startsWith("authz_vuln_sid="))!;
    expect(sid).toMatch(/HttpOnly/i);
    expect(sid).toMatch(/Path=\/x\/authz\/vuln/i);
    const role = cookies.find((c) => c.startsWith("role="))!;
    expect(role).toContain("role=user");
    expect(role).not.toMatch(/HttpOnly/i);
    expect(role).toMatch(/Path=\/x\/authz\/vuln/i);
  });

  it("ログインに失敗すると 401。未ログインで注文を開くとトップへ戻される", async () => {
    const b = new Browser();
    expect((await login(b, "vuln", "alice", "wrong")).status).toBe(401);
    const res = await b.get(`${base("vuln")}/orders/1`);
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(`${base("vuln")}/`);
  });

  it("自分の注文一覧には自分の分だけ（#1 #2 #4 #7）が並ぶ", async () => {
    const b = await loggedIn("vuln", "alice");
    const html = await b.text(`${base("vuln")}/orders`);
    for (const id of [1, 2, 4, 7]) expect(html).toContain(`/orders/${id}"`);
    for (const id of [3, 5, 6, 8]) expect(html).not.toContain(`/orders/${id}"`);
  });

  it("水平権限昇格: 注文IDを書き換えると、他人（bob）の注文と住所が見える", async () => {
    const b = await loggedIn("vuln", "alice");
    const res = await b.get(`${base("vuln")}/orders/3`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("モニターアーム");
    expect(html).toContain(BOB_ADDRESS);
    // 連番を順に試すだけで、全員の注文が読める
    for (let id = 1; id <= 8; id++) expect((await b.get(`${base("vuln")}/orders/${id}`)).status).toBe(200);
    expect((await b.get(`${base("vuln")}/orders/999`)).status).toBe(404);
  });

  it("隠しフィールド: 自分の user_id のままなら他人の配送先は変わらず、user_id を書き換えると変えられる", async () => {
    const alice = await loggedIn("vuln", "alice");
    // フォームには、ログイン中のユーザーの user_id が hidden で入っている
    expect(await alice.text(`${base("vuln")}/orders/3`)).toContain('<input type="hidden" name="user_id" value="1">');

    // 正直な値（1）では、持ち主の条件に合わず更新されない
    const honest = await alice.post(`${base("vuln")}/orders/3/address`, { user_id: "1", address: "alice が書き換えた" });
    expect(honest.headers.get("location")).toContain("ng=1");

    // hidden を 2（bob）に書き換えると更新できてしまう
    const forged = await alice.post(`${base("vuln")}/orders/3/address`, { user_id: "2", address: "攻撃者が書き換えた住所" });
    expect(forged.headers.get("location")).toContain("ok=1");

    // bob 本人が見ても書き換わっている
    const bob = sameLearner(alice);
    await login(bob, "vuln", "bob");
    const html = await bob.text(`${base("vuln")}/orders/3`);
    expect(html).toContain("攻撃者が書き換えた住所");
    expect(html).not.toContain(BOB_ADDRESS);
  });

  it("垂直権限昇格: role Cookie を admin に書き換えると、一般ユーザーが管理画面に入れる", async () => {
    const b = await loggedIn("vuln", "alice");
    expect((await b.get(`${base("vuln")}/admin`)).status).toBe(403);

    b.jar.set("role", "admin"); // document.cookie = 'role=admin; path=/x/authz/vuln' と同じ
    const res = await b.get(`${base("vuln")}/admin`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("ユーザー一覧");
    expect(html).toContain("bob");
    expect(html).toContain(BOB_ADDRESS);
  });

  it("ログインしていなくても、role=admin の Cookie だけで管理画面に入れる", async () => {
    const b = new Browser();
    b.jar.set("role", "admin");
    expect((await b.get(`${base("vuln")}/admin`)).status).toBe(200);
  });

  it("管理者の操作（注文のキャンセル）も Cookie だけで通り、何も記録されない", async () => {
    const b = await loggedIn("vuln", "alice");
    b.jar.set("role", "admin");
    const res = await b.post(`${base("vuln")}/admin/orders/5/cancel`);
    expect(res.status).toBe(303);
    expect((await b.get(`${base("vuln")}/orders/5`)).status).toBe(404);
    // 脆弱版は、ログインも認可の失敗も管理者の操作も記録しない
    expect(await auditRows(b)).toEqual([]);
  });

  it("role が user のままなら、管理者の操作はできない", async () => {
    const b = await loggedIn("vuln", "alice");
    expect((await b.post(`${base("vuln")}/admin/orders/5/cancel`)).status).toBe(403);
    expect((await b.get(`${base("vuln")}/orders/5`)).status).toBe(200);
  });

  it("ログアウトでセッションが無効になる", async () => {
    const b = await loggedIn("vuln", "alice");
    const sid = b.cookie("authz_vuln_sid")!;
    await b.post(`${base("vuln")}/logout`);
    expect(b.cookie("authz_vuln_sid")).toBeUndefined();
    b.jar.set("authz_vuln_sid", sid); // 盗んだ古いセッションIDを使い回しても通らない
    expect((await b.get(`${base("vuln")}/orders/1`)).status).toBe(303);
  });
});

describe("認可不備: 修正版", () => {
  it("セッションCookieは HttpOnly + SameSite=Lax で、role Cookie は発行されない", async () => {
    const b = new Browser();
    const res = await login(b, "fixed", "alice");
    expect(res.status).toBe(303);
    const cookies = res.headers.getSetCookie();
    const sid = cookies.find((c) => c.startsWith("authz_fixed_sid="))!;
    expect(sid).toMatch(/HttpOnly/i);
    expect(sid).toMatch(/SameSite=Lax/i);
    expect(sid).toMatch(/Path=\/x\/authz\/fixed/i);
    expect(cookies.some((c) => c.startsWith("role="))).toBe(false);
  });

  it("水平権限昇格: 他人の注文は 404。存在しない注文と区別できず、住所も漏れない", async () => {
    const b = await loggedIn("fixed", "alice");
    const other = await b.get(`${base("fixed")}/orders/3`);
    expect(other.status).toBe(404);
    const otherHtml = await other.text();
    expect(otherHtml).not.toContain(BOB_ADDRESS);
    expect(otherHtml).not.toContain("モニターアーム");
    // 存在しない注文と、まったく同じ応答
    const missing = await b.get(`${base("fixed")}/orders/999`);
    expect(missing.status).toBe(404);
    expect(await missing.text()).toBe(otherHtml);
    // 自分の注文は普通に見える
    const mine = await b.get(`${base("fixed")}/orders/1`);
    expect(mine.status).toBe(200);
    expect(await mine.text()).toContain(ALICE_ADDRESS);
    // 連番を総当たりしても、見えるのは自分の 4 件だけ
    const visible: number[] = [];
    for (let id = 1; id <= 8; id++) if ((await b.get(`${base("fixed")}/orders/${id}`)).status === 200) visible.push(id);
    expect(visible).toEqual([1, 2, 4, 7]);
  });

  it("フォームに hidden の user_id は無い。送られてきても無視され、他人の配送先は変えられない", async () => {
    const b = await loggedIn("fixed", "alice");
    expect(await b.text(`${base("fixed")}/orders/1`)).not.toContain('name="user_id"');

    const forged = await b.post(`${base("fixed")}/orders/3/address`, { user_id: "2", address: "攻撃者が書き換えた住所" });
    expect(forged.status).toBe(404);
    const forged2 = await b.post(`${base("fixed")}/orders/3/address`, { user_id: "1", address: "攻撃者が書き換えた住所" });
    expect(forged2.status).toBe(404);

    const bob = sameLearner(b);
    await login(bob, "fixed", "bob");
    const html = await bob.text(`${base("fixed")}/orders/3`);
    expect(html).toContain(BOB_ADDRESS);
    expect(html).not.toContain("攻撃者が書き換えた住所");
  });

  it("正常系: 自分の注文の配送先は変更できる（同じ値でも成功する）", async () => {
    const b = await loggedIn("fixed", "alice");
    const res = await b.post(`${base("fixed")}/orders/1/address`, { address: "東京都港区テスト1-1-1 サンプル棟" });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toContain("ok=1");
    const html = await b.text(`${base("fixed")}/orders/1?ok=1`);
    expect(html).toContain("東京都港区テスト1-1-1 サンプル棟");
    expect(html).toContain("配送先を更新しました");
    const same = await b.post(`${base("fixed")}/orders/1/address`, { address: "東京都港区テスト1-1-1 サンプル棟" });
    expect(same.status).toBe(303);
  });

  it("垂直権限昇格: role Cookie を作っても管理画面に入れない（ロールはDBのセッションから判定）", async () => {
    const b = await loggedIn("fixed", "alice");
    b.jar.set("role", "admin");
    expect((await b.get(`${base("fixed")}/admin`)).status).toBe(403);
    expect((await b.post(`${base("fixed")}/admin/orders/5/cancel`)).status).toBe(403);
    expect((await b.get(`${base("fixed")}/admin`)).headers.get("content-type")).toContain("text/html");
    // 注文は消えていない
    const bob = sameLearner(b);
    await login(bob, "fixed", "bob");
    expect((await bob.get(`${base("fixed")}/orders/5`)).status).toBe(200);
  });

  it("未ログインでも role=admin だけでは入れない。本物の admin は入れてキャンセルもできる", async () => {
    const anon = new Browser();
    anon.jar.set("role", "admin");
    expect((await anon.get(`${base("fixed")}/admin`)).status).toBe(403);

    const admin = await loggedIn("fixed", "admin");
    const res = await admin.get(`${base("fixed")}/admin`);
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("全注文");
    expect((await admin.post(`${base("fixed")}/admin/orders/5/cancel`)).status).toBe(303);
    const bob = sameLearner(admin);
    await login(bob, "fixed", "bob");
    expect((await bob.get(`${base("fixed")}/orders/5`)).status).toBe(404);
  });

  it("脆弱版のセッションIDは、修正版では使えない（セッションはモードごと）", async () => {
    const b = await loggedIn("vuln", "alice");
    b.jar.set("authz_fixed_sid", b.cookie("authz_vuln_sid")!);
    expect((await b.get(`${base("fixed")}/orders/1`)).status).toBe(303);
  });

  it("監査ログ: 認可失敗・ログイン成功/失敗・重要操作が記録される", async () => {
    const alice = new Browser();
    // ログイン失敗（存在するユーザー・存在しないユーザー）
    await login(alice, "fixed", "alice", "wrong-password-123");
    await login(alice, "fixed", "nobody", "x");
    await login(alice, "fixed", "alice");
    // 認可失敗
    await alice.get(`${base("fixed")}/orders/3`);
    await alice.post(`${base("fixed")}/orders/3/address`, { user_id: "2", address: "x" });
    await alice.get(`${base("fixed")}/admin`);
    // 重要操作
    await alice.post(`${base("fixed")}/orders/1/address`, { address: "東京都港区テスト1-1-1 サンプル棟" });

    const rows = await auditRows(alice);
    const has = (user: string, action: string, detail?: string) =>
      rows.some((r) => r.mode === "fixed" && r.user === user && r.action === action && (!detail || r.detail.includes(detail)));
    expect(has("alice", "login_failure", "パスワードが一致しない")).toBe(true);
    expect(has("nobody", "login_failure", "存在しない")).toBe(true);
    expect(has("alice", "login_success")).toBe(true);
    expect(has("alice", "authz_denied", "GET /orders/3")).toBe(true);
    expect(has("alice", "authz_denied", "POST /orders/3/address")).toBe(true);
    expect(has("alice", "authz_denied", "GET /admin")).toBe(true);
    expect(has("alice", "order_address_changed", "注文 #1")).toBe(true);
    // パスワードは記録されない
    expect(JSON.stringify(rows)).not.toContain("wrong-password-123");
    expect(JSON.stringify(rows)).not.toContain("alice-pass");
  });

  it("監査ログ: 管理者のキャンセルと、未ログインの管理画面アクセスが記録される", async () => {
    const admin = await loggedIn("fixed", "admin");
    await admin.post(`${base("fixed")}/admin/orders/5/cancel`);
    const anon = sameLearner(admin);
    await anon.get(`${base("fixed")}/admin`);
    const rows = await auditRows(admin);
    expect(rows.some((r) => r.user === "admin" && r.action === "admin_cancel_order" && r.detail.includes("#5"))).toBe(true);
    expect(rows.some((r) => r.user === "(anonymous)" && r.action === "authz_denied")).toBe(true);
  });

  it("/audit: 一般ユーザーは自分に関する記録だけ、管理者は全員分が見える", async () => {
    const alice = await loggedIn("fixed", "alice");
    await alice.get(`${base("fixed")}/orders/3`);
    const bob = sameLearner(alice);
    await login(bob, "fixed", "bob");
    await bob.get(`${base("fixed")}/orders/1`); // bob が alice の注文を覗こうとした

    const aliceView = await alice.text(`${base("fixed")}/audit`);
    expect(aliceView).toContain("authz_denied");
    expect(aliceView).toContain("GET /orders/3");
    expect(aliceView).not.toContain("GET /orders/1<");
    expect(aliceView).not.toContain("<td>bob</td>");

    const bobView = await bob.text(`${base("fixed")}/audit`);
    expect(bobView).toContain("GET /orders/1");
    expect(bobView).not.toContain("GET /orders/3");

    const admin = sameLearner(alice);
    await login(admin, "fixed", "admin");
    const adminView = await admin.text(`${base("fixed")}/audit`);
    expect(adminView).toContain("全員分");
    expect(adminView).toContain("<td>alice</td>");
    expect(adminView).toContain("<td>bob</td>");
  });

  it("/audit: 未ログインはトップへ戻される。ログに改行などの制御文字は入らない", async () => {
    const b = new Browser();
    expect((await b.get(`${base("fixed")}/audit`)).status).toBe(303);
    await login(b, "fixed", "x\r\n2026-01-01T00:00:00Z admin login_success 偽造", "x");
    const rows = await auditRows(b);
    const forged = rows.find((r) => r.action === "login_failure")!;
    expect(forged.user).not.toMatch(/[\r\n]/);
    expect(forged.user.length).toBeLessThanOrEqual(40);
  });

  it("ログ表示は常にエスケープされる（この演習は XSS ではない）", async () => {
    const b = new Browser();
    await login(b, "fixed", "<script>alert(1)</script>", "x");
    await login(b, "fixed", "admin");
    const html = await b.text(`${base("fixed")}/audit`);
    expect(html).not.toContain("<script>alert(1)");
    expect(html).toContain("&lt;script&gt;alert(1)");
  });
});

describe("認可不備: 共通", () => {
  it("学習者ごとにデータが分かれる（片方の改ざんは、もう片方に見えない）", async () => {
    const a = await loggedIn("vuln", "alice");
    await a.post(`${base("vuln")}/orders/3/address`, { user_id: "2", address: "A の学習者だけに見える住所" });
    expect(await a.text(`${base("vuln")}/orders/3`)).toContain("A の学習者だけに見える住所");

    const other = await loggedIn("vuln", "alice");
    const html = await other.text(`${base("vuln")}/orders/3`);
    expect(html).toContain(BOB_ADDRESS);
    expect(html).not.toContain("A の学習者だけに見える住所");
  });

  it("監査ログも学習者ごとに分かれる", async () => {
    const a = await loggedIn("fixed", "alice");
    await a.get(`${base("fixed")}/orders/3`);
    const other = await loggedIn("fixed", "alice");
    const rows = await auditRows(other);
    expect(rows.filter((r) => r.action === "authz_denied")).toEqual([]);
  });

  it("トップ: 未ログインはログインフォーム、ログイン後は案内（修正版にだけ監査ログへのリンク）", async () => {
    const v = await loggedIn("vuln", "alice");
    const f = await loggedIn("fixed", "alice");
    expect(await new Browser().text(`${base("vuln")}/`)).toContain(`action="${base("vuln")}/login"`);
    const vHtml = await v.text(`${base("vuln")}/`);
    const fHtml = await f.text(`${base("fixed")}/`);
    expect(vHtml).toContain("監査ログがありません");
    expect(vHtml).not.toContain("/audit");
    expect(fHtml).toContain(`${base("fixed")}/audit`);
  });

  it("解説ページ: 原因のコードがハイライトされ、修正の差分が出る", async () => {
    const html = await new Browser().text("/x/authz");
    expect(html).toContain("認可不備");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
