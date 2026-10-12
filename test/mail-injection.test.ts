import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

const base = (mode: "vuln" | "fixed") => `/x/mail-injection/${mode}`;
const send = (b: Browser, mode: "vuln" | "fixed", form: Record<string, string>) => b.post(`${base(mode)}/send`, form);
/** 攻撃者がリクエストボディを直接書き換えて送る（% エンコードされた CRLF を含む） */
const sendRaw = (b: Browser, mode: "vuln" | "fixed", raw: string) => b.post(`${base(mode)}/send-raw`, { raw });
const tray = (b: Browser, mode: "vuln" | "fixed") => b.text(`${base(mode)}/`);

const BCC = "from=taro%40example.com&subject=hello%0d%0aBcc:%20victim@example.com&message=test";
const REPLY_TO = "from=taro%40example.com%0d%0aReply-To:%20attacker@example.com&subject=hello&message=test";
const BODY_SWAP =
  "from=taro%40example.com&subject=Re:%20Your%20account%0d%0a%0d%0aYour%20account%20is%20locked.%20Open%20http://evil.example/login&message=ignored";

describe("メールヘッダインジェクション: 脆弱版", () => {
  it("通常の送信: 送信トレイに生の文面と解析結果が出る。宛先は admin だけ", async () => {
    const b = new Browser();
    const res = await send(b, "vuln", { from: "taro@example.com", subject: "お問い合わせ", message: "質問です" });
    expect(res.status).toBe(303);
    const html = await tray(b, "vuln");
    expect(html).toContain("擬似環境です");
    expect(html).toContain("From: taro@example.com");
    expect(html).toContain("To: admin@example.com");
    expect(html).toContain("Subject: お問い合わせ");
    expect(html).toContain("<mark>␍␊</mark>");
    expect(html).toContain("配送先は admin@example.com だけです");
    expect(html).not.toContain("想定外");
  });

  it("件名への CRLF 注入で Bcc ヘッダーが増え、配送先が増える", async () => {
    const b = new Browser();
    await sendRaw(b, "vuln", BCC);
    const html = await tray(b, "vuln");
    expect(html).toContain("想定外（注入された）");
    expect(html).toMatch(/<td>Bcc<\/td><td>victim@example\.com<\/td><td>⚠ 想定外/);
    expect(html).toContain("意図しない宛先に配送されます");
    expect(html).toContain("<code>victim@example.com</code>");
    // 生の文面では Subject が 2 行に分かれている
    expect(html).toContain("Subject: hello<mark>␍␊</mark>\nBcc: victim@example.com<mark>␍␊</mark>");
  });

  it("textarea のように実際の CRLF を含む値でも成立する（%エンコード不要）", async () => {
    const b = new Browser();
    await send(b, "vuln", { from: "taro@example.com", subject: "hello\r\nBcc: victim@example.com", message: "x" });
    expect(await tray(b, "vuln")).toContain("<code>victim@example.com</code>");
  });

  it("返信先 (from) への注入で Reply-To を乗っ取れる", async () => {
    const b = new Browser();
    await sendRaw(b, "vuln", REPLY_TO);
    const html = await tray(b, "vuln");
    expect(html).toMatch(/<td>Reply-To<\/td><td>attacker@example\.com<\/td><td>⚠ 想定外/);
  });

  it("空行の注入で本文が差し替わり、本来のヘッダーは本文側に回る", async () => {
    const b = new Browser();
    await sendRaw(b, "vuln", BODY_SWAP);
    const html = await tray(b, "vuln");
    expect(html).toContain("本来のヘッダー");
    expect(html).toContain("が見つかりません");
    const bodyPart = html.slice(html.indexOf("<h4>本文</h4>"));
    expect(bodyPart).toContain("Your account is locked. Open http://evil.example/login");
    expect(bodyPart).toContain("Content-Type: text/plain"); // 本来のヘッダーが本文に混ざる
  });

  it("入力欄に %0d%0a と書いて送っても、フォームの % は %25 になるだけで改行にならない", async () => {
    const b = new Browser();
    await send(b, "vuln", { from: "taro@example.com", subject: "hello%0d%0aBcc: victim@example.com", message: "x" });
    const html = await tray(b, "vuln");
    expect(html).not.toContain("想定外");
    expect(html).not.toContain("<code>victim@example.com</code>");
  });

  it("入力は画面にエスケープして出る（XSS ではない）", async () => {
    const b = new Browser();
    await send(b, "vuln", { from: "taro@example.com", subject: "<script>alert(1)</script>", message: "<img src=x onerror=alert(1)>" });
    const html = await tray(b, "vuln");
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});

describe("メールヘッダインジェクション: 修正版", () => {
  it("通常の送信: 件名が RFC 2047 風にエンコードされ、デコードして読める。宛先は admin だけ", async () => {
    const b = new Browser();
    const res = await send(b, "fixed", { from: "taro@example.com", subject: "お問い合わせ", message: "質問です\nありがとう" });
    expect(res.status).toBe(303);
    const html = await tray(b, "fixed");
    expect(html).toMatch(/Subject: =\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=/);
    expect(html).toContain("→ 「お問い合わせ」");
    expect(html).toContain("配送先は admin@example.com だけです");
    expect(html).not.toContain("想定外");
    expect(html).toContain("質問です");
  });

  it("脆弱版と同じ攻撃（Bcc / Reply-To / 本文差し替え）はすべて 400 で拒否され、送信トレイに何も増えない", async () => {
    const b = new Browser();
    for (const raw of [BCC, REPLY_TO, BODY_SWAP, "from=taro%40example.com&subject=a%0Ab&message=x", "from=taro%40example.com&subject=a%00b&message=x"]) {
      const res = await sendRaw(b, "fixed", raw);
      const html = await res.text();
      expect(res.status, raw).toBe(400);
      expect(html, raw).toContain("制御文字は使えません");
    }
    const html = await tray(b, "fixed");
    expect(html).toContain("まだ何も送信していません");
    expect(html).not.toContain("victim@example.com");
    expect(html).not.toContain("attacker@example.com");
  });

  it("メールアドレスの形式検証: 不正な返信先は 400", async () => {
    const b = new Browser();
    for (const from of ["not-an-address", "a@b", "taro@example.com, victim@example.com", "<taro@example.com>", "taro@example.com ", ""]) {
      const res = await send(b, "fixed", { from, subject: "hi", message: "x" });
      expect(res.status, JSON.stringify(from)).toBe(400);
      expect(await res.text()).toContain("形式が正しくありません");
    }
  });

  it("件名の長さと空の件名を検証する", async () => {
    const b = new Browser();
    expect((await send(b, "fixed", { from: "taro@example.com", subject: "", message: "x" })).status).toBe(400);
    expect((await send(b, "fixed", { from: "taro@example.com", subject: "a".repeat(101), message: "x" })).status).toBe(400);
    expect((await send(b, "fixed", { from: "taro@example.com", subject: "a".repeat(100), message: "x" })).status).toBe(303);
  });

  it("本文の中に「ヘッダーのような行」があっても、ただの本文として扱われる（宛先は増えない）", async () => {
    const b = new Browser();
    await send(b, "fixed", { from: "taro@example.com", subject: "hi", message: "Bcc: victim@example.com\r\n\r\nspam" });
    const html = await tray(b, "fixed");
    expect(html).toContain("配送先は admin@example.com だけです");
    expect(html).not.toContain("意図しない宛先");
  });
});

describe("送信トレイ・学習者ごとの分離", () => {
  it("送信トレイはモードごとに分かれる", async () => {
    const b = new Browser();
    await sendRaw(b, "vuln", BCC);
    await send(b, "fixed", { from: "taro@example.com", subject: "hi", message: "x" });
    expect(await tray(b, "fixed")).not.toContain("victim@example.com");
    expect(await tray(b, "vuln")).not.toContain("Subject: hi");
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await send(a, "vuln", { from: "taro@example.com", subject: "only-for-a", message: "x" });
    expect(await tray(a, "vuln")).toContain("only-for-a");
    expect(await tray(other, "vuln")).not.toContain("only-for-a");
  });

  it("?raw= で攻撃者の欄に入力済みで開ける（送信はしない）", async () => {
    const b = new Browser();
    const html = await b.text(`${base("vuln")}/?raw=${encodeURIComponent(BCC)}`);
    expect(html).toContain("subject=hello%0d%0aBcc:%20victim@example.com");
    expect(html).toContain("まだ何も送信していません");
  });
});

describe("解説ページ", () => {
  it("原因のコード・修正の差分が表示される", async () => {
    const b = new Browser();
    const html = await b.text("/x/mail-injection");
    expect(html).toContain("メールヘッダインジェクション");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain("Bcc:%20victim@example.com");
  });
});
