import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

type Mode = "vuln" | "fixed";
const base = (m: Mode) => `/x/session-fixation/${m}`;
const COOKIE = (m: Mode) => `sf_${m}_sid`;

async function login(b: Browser, m: Mode, password = "alice-pass") {
  return b.post(`${base(m)}/login`, { username: "alice", password });
}

/** 攻撃者: ① 新しい SID を手に入れる（被害者のブラウザの Cookie は変わらない） */
async function getAttackerSid(b: Browser, m: Mode): Promise<string> {
  const before = b.cookie(COOKIE(m));
  const res = await b.post(`${base(m)}/attacker-new-sid`);
  expect(res.status).toBe(303);
  expect(b.cookie(COOKIE(m))).toBe(before);
  const home = await b.text(`${base(m)}/`);
  const sid = /id="attacker-sid">([0-9a-f]{32})</.exec(home)?.[1];
  expect(sid).toBeDefined();
  // ② 罠のURL
  expect(home).toContain(`${base(m)}/?sid=${sid}`);
  return sid!;
}

/** ④ 攻撃者の視点: 被害者の Cookie は一切送らず（lab_id だけ = 同じ学習者のDB）、SID だけで引く */
async function attackerView(b: Browser, m: Mode, sid: string): Promise<string> {
  const res = await b.get(`${base(m)}/attacker-view?sid=${sid}`, { Cookie: `lab_id=${b.cookie("lab_id")}` });
  expect(res.headers.getSetCookie().some((c) => c.startsWith("sf_"))).toBe(false); // 攻撃者の画面は Cookie を発行しない
  return res.text();
}

/** ① 〜 ③: 被害者がブラウザ（初訪問済み）で罠のURLを開いてログインするまで */
async function fixateAndLogin(b: Browser, m: Mode) {
  await b.get(`${base(m)}/`); // 被害者のブラウザが、まず普通にサイトを開いている
  const attackerSid = await getAttackerSid(b, m);
  const trap = await b.get(`${base(m)}/?sid=${attackerSid}`); // ③ 罠のURLを開く
  const cookieAfterTrap = b.cookie(COOKIE(m));
  const res = await login(b, m);
  return { attackerSid, trap, cookieAfterTrap, loginRes: res, cookieAfterLogin: b.cookie(COOKIE(m)) };
}

describe("セッション固定化 脆弱版", () => {
  it("通常のログインとマイページ", async () => {
    const b = new Browser();
    await b.get(`${base("vuln")}/`);
    const res = await login(b, "vuln");
    expect(res.status).toBe(303);
    const me = await b.text(`${base("vuln")}/me`);
    expect(me).toContain("アリス・サンプル");
  });

  it("パスワードが違えばログインできない", async () => {
    const b = new Browser();
    const res = await login(b, "vuln", "wrong");
    expect(res.status).toBe(401);
    const me = await b.get(`${base("vuln")}/me`);
    expect(me.status).toBe(303); // 未ログインなのでトップへ
  });

  it("URL の sid が Cookie として採用される", async () => {
    const b = new Browser();
    await b.get(`${base("vuln")}/`);
    const sid = await getAttackerSid(b, "vuln");
    const res = await b.get(`${base("vuln")}/?sid=${sid}`);
    expect(res.headers.getSetCookie().find((c) => c.startsWith("sf_vuln_sid="))).toContain(`sf_vuln_sid=${sid}`);
    expect(await res.text()).toContain("URL の <code>sid</code> パラメータで渡された値を");
    expect(b.cookie("sf_vuln_sid")).toBe(sid);
  });

  it("存在しない sid は採用されない（新しい未ログインのセッションが作られる）", async () => {
    const b = new Browser();
    const fake = "0".repeat(32);
    await b.get(`${base("vuln")}/?sid=${fake}`);
    expect(b.cookie("sf_vuln_sid")).toMatch(/^[0-9a-f]{32}$/);
    expect(b.cookie("sf_vuln_sid")).not.toBe(fake);
  });

  it("攻撃成立: ログインしてもセッションIDが変わらず、攻撃者は SID だけで被害者の画面を見られる", async () => {
    const b = new Browser();
    const { attackerSid, cookieAfterTrap, cookieAfterLogin, loginRes } = await fixateAndLogin(b, "vuln");
    expect(loginRes.status).toBe(303);
    expect(cookieAfterTrap).toBe(attackerSid);
    expect(cookieAfterLogin).toBe(attackerSid); // ログイン後も同じ ID
    const view = await attackerView(b, "vuln", attackerSid);
    expect(view).toContain("被害者のアカウント情報が見えてしまいました");
    expect(view).toContain("アリス・サンプル");
    expect(view).toContain("alice@example.com");
  });

  it("ログイン前の攻撃者の SID では、まだ何も見えない（ログインが引き金）", async () => {
    const b = new Browser();
    await b.get(`${base("vuln")}/`);
    const sid = await getAttackerSid(b, "vuln");
    const view = await attackerView(b, "vuln", sid);
    expect(view).toContain("未ログイン");
    expect(view).not.toContain("アリス・サンプル");
  });

  it("攻撃者の画面は Cookie を使わない（Cookie が付いていても SID を指定しなければ何も見えない）", async () => {
    const b = new Browser();
    await b.get(`${base("vuln")}/`);
    await login(b, "vuln");
    const res = await b.get(`${base("vuln")}/attacker-view`); // 被害者の Cookie 付き・sid なし
    expect(await res.text()).toContain("この SID のセッションは存在しません");
  });

  it("ログアウトしても、サーバー側のセッションは残り、攻撃者はまだ見られる", async () => {
    const b = new Browser();
    const { attackerSid } = await fixateAndLogin(b, "vuln");
    const out = await b.post(`${base("vuln")}/logout`);
    expect(out.status).toBe(303);
    expect(b.cookie("sf_vuln_sid")).toBeUndefined(); // ブラウザの Cookie は消える
    const view = await attackerView(b, "vuln", attackerSid);
    expect(view).toContain("アリス・サンプル");
  });

  it("Cookie に HttpOnly も SameSite も付いていない", async () => {
    const b = new Browser();
    const res = await b.get(`${base("vuln")}/`);
    const line = res.headers.getSetCookie().find((c) => c.startsWith("sf_vuln_sid="))!;
    expect(line).not.toMatch(/HttpOnly/i);
    expect(line).not.toMatch(/SameSite/i);
  });
});

describe("セッション固定化 修正版", () => {
  it("通常のログインとマイページ", async () => {
    const b = new Browser();
    await b.get(`${base("fixed")}/`);
    const res = await login(b, "fixed");
    expect(res.status).toBe(303);
    expect(await b.text(`${base("fixed")}/me`)).toContain("アリス・サンプル");
  });

  it("URL の sid は無視される（Cookie は攻撃者の SID にならない）", async () => {
    const b = new Browser();
    await b.get(`${base("fixed")}/`);
    const sid = await getAttackerSid(b, "fixed");
    const res = await b.get(`${base("fixed")}/?sid=${sid}`);
    expect(await res.text()).toContain("URL のセッションIDを<strong>無視</strong>します");
    expect(b.cookie("sf_fixed_sid")).not.toBe(sid);
  });

  it("攻撃失敗: ログインでセッションIDが作り直され、攻撃者の SID では被害者の画面が見えない", async () => {
    const b = new Browser();
    const { attackerSid, cookieAfterTrap, cookieAfterLogin, loginRes } = await fixateAndLogin(b, "fixed");
    expect(loginRes.status).toBe(303);
    expect(cookieAfterTrap).not.toBe(attackerSid);
    expect(cookieAfterLogin).not.toBe(attackerSid);
    expect(cookieAfterLogin).not.toBe(cookieAfterTrap); // ログイン前後で ID が変わる
    const view = await attackerView(b, "fixed", attackerSid);
    expect(view).toContain("未ログイン");
    expect(view).not.toContain("アリス・サンプル");
    expect(view).not.toContain("被害者のアカウント情報が見えてしまいました");
  });

  it("ログイン前の古い SID は破棄される", async () => {
    const b = new Browser();
    await b.get(`${base("fixed")}/`);
    const before = b.cookie("sf_fixed_sid")!;
    await login(b, "fixed");
    const view = await attackerView(b, "fixed", before);
    expect(view).toContain("この SID のセッションは存在しません");
  });

  it("ログアウトでサーバー側のセッションも破棄される", async () => {
    const b = new Browser();
    await b.get(`${base("fixed")}/`);
    await login(b, "fixed");
    const loggedIn = b.cookie("sf_fixed_sid")!;
    expect(await attackerView(b, "fixed", loggedIn)).toContain("アリス・サンプル"); // SID を知っていれば、ログアウト前は引ける（だから SID は漏らさない）
    await b.post(`${base("fixed")}/logout`);
    expect(await attackerView(b, "fixed", loggedIn)).toContain("この SID のセッションは存在しません");
  });

  it("パスワードが違えばログインできず、セッションも昇格しない", async () => {
    const b = new Browser();
    await b.get(`${base("fixed")}/`);
    const sid = b.cookie("sf_fixed_sid")!;
    const res = await login(b, "fixed", "wrong");
    expect(res.status).toBe(401);
    expect(await attackerView(b, "fixed", sid)).toContain("未ログイン");
  });

  it("セッションID は 128bit 以上の乱数（32桁の16進数）で、ログインのたびに別の値", async () => {
    const ids = new Set<string>();
    for (let i = 0; i < 3; i++) {
      const b = new Browser();
      await b.get(`${base("fixed")}/`);
      await login(b, "fixed");
      const sid = b.cookie("sf_fixed_sid")!;
      expect(sid).toMatch(/^[0-9a-f]{32}$/);
      ids.add(sid);
    }
    expect(ids.size).toBe(3);
  });

  it("Cookie は HttpOnly; SameSite=Lax（https なら Secure）", async () => {
    const http = new Browser();
    const r1 = await http.get(`${base("fixed")}/`);
    const l1 = r1.headers.getSetCookie().find((c) => c.startsWith("sf_fixed_sid="))!;
    expect(l1).toMatch(/HttpOnly/i);
    expect(l1).toMatch(/SameSite=Lax/i);
    expect(l1).not.toMatch(/;\s*Secure/i);
    const https = new Browser("https://lab.test");
    const r2 = await login(https, "fixed");
    const l2 = r2.headers.getSetCookie().find((c) => c.startsWith("sf_fixed_sid="))!;
    expect(l2).toMatch(/HttpOnly/i);
    expect(l2).toMatch(/SameSite=Lax/i);
    expect(l2).toMatch(/;\s*Secure/i);
  });

  it("脆弱版のセッションIDは修正版では引けない（モードごとに分かれる）", async () => {
    const b = new Browser();
    const { attackerSid } = await fixateAndLogin(b, "vuln");
    expect(await attackerView(b, "fixed", attackerSid)).toContain("この SID のセッションは存在しません");
  });
});

describe("セッション固定化 学習者ごとの分離", () => {
  it("別の学習者からは、攻撃者の SID もセッションも見えない", async () => {
    const a = new Browser();
    const other = new Browser();
    const { attackerSid } = await fixateAndLogin(a, "vuln");
    expect(await attackerView(a, "vuln", attackerSid)).toContain("アリス・サンプル");
    expect(await attackerView(other, "vuln", attackerSid)).toContain("この SID のセッションは存在しません");
    expect(await other.text(`${base("vuln")}/`)).not.toContain(attackerSid);
  });
});

describe("セッション固定化 解説ページ", () => {
  it("原因のコード・修正の差分が表示され、[!] の行がハイライトされる", async () => {
    const html = await new Browser().text("/x/session-fixation");
    expect(html).toContain("セッション固定化");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain('class="del"');
  });
});
