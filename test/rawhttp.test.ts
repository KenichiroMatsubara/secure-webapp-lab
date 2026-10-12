import { describe, expect, it } from "vitest";
import {
  buildRawResponse,
  hasControlChars,
  headerLine,
  headersNamed,
  parseRawResponse,
  parseSetCookie,
  visualizeCrlf,
  visualizeCrlfHtml,
} from "../src/lab/rawhttp";
import {
  buildRawMail,
  composeMail,
  decodeMimeWords,
  encodeMimeWord,
  isValidEmail,
  parseRawMail,
  recipientsOf,
} from "../src/lab/rawmail";

describe("rawhttp: 生のレスポンスの組み立てと解析", () => {
  it("ヘッダー行を CRLF でつなぎ、空行のあとに本文を置く", () => {
    const raw = buildRawResponse(302, ["Location: /mypage", "Cache-Control: no-store"], "moved");
    expect(raw).toBe("HTTP/1.1 302 Found\r\nLocation: /mypage\r\nCache-Control: no-store\r\n\r\nmoved");
    const p = parseRawResponse(raw);
    expect(p.status).toBe(302);
    expect(p.reason).toBe("Found");
    expect(p.headers).toEqual([
      { name: "Location", value: "/mypage" },
      { name: "Cache-Control", value: "no-store" },
    ]);
    expect(p.body).toBe("moved");
    expect(p.malformed).toEqual([]);
  });

  it("ヘッダーがなくても組み立てられる", () => {
    expect(buildRawResponse(200, [], "x")).toBe("HTTP/1.1 200 OK\r\n\r\nx");
    expect(parseRawResponse("HTTP/1.1 200 OK\r\n\r\nx").headers).toEqual([]);
  });

  it("値に CRLF が入っていると、解析側ではヘッダーが増える（ヘッダーインジェクション）", () => {
    const raw = buildRawResponse(200, ["Set-Cookie: lang=" + "ja\r\nSet-Cookie: sid=attacker", "X-After: 1"], "ok");
    const p = parseRawResponse(raw);
    expect(headersNamed(p.headers, "set-cookie").map((h) => h.value)).toEqual(["lang=ja", "sid=attacker"]);
    expect(p.body).toBe("ok");
  });

  it("CRLF CRLF を入れるとヘッダーが終わり、あとの行（本来のヘッダー）が本文に回る（レスポンス分割）", () => {
    const raw = buildRawResponse(200, ["Set-Cookie: lang=" + "ja\r\n\r\n<h1>fake</h1>", "Cache-Control: no-store"], "<p>real</p>");
    const p = parseRawResponse(raw);
    expect(p.headers).toEqual([{ name: "Set-Cookie", value: "lang=ja" }]);
    expect(p.body).toBe("<h1>fake</h1>\r\nCache-Control: no-store\r\n\r\n<p>real</p>");
  });

  it("LF だけの注入も、寛容な実装では行の区切りとして解釈される。CR だけは区切りにならない", () => {
    const lf = parseRawResponse(buildRawResponse(200, ["X-A: 1\nX-B: 2"]));
    expect(lf.headers.map((h) => h.name)).toEqual(["X-A", "X-B"]);
    const cr = parseRawResponse(buildRawResponse(200, ["X-A: 1\rX-B: 2"]));
    expect(cr.headers).toEqual([{ name: "X-A", value: "1\rX-B: 2" }]);
  });

  it("名前: 値になっていない行は malformed に入り、空行がなければ本文はない", () => {
    const p = parseRawResponse("HTTP/1.1 200 OK\r\nX-A: 1\r\nnot a header\r\n bad name: x\r\n");
    expect(p.malformed).toEqual(["not a header", " bad name: x"]);
    expect(p.terminated).toBe(false);
    expect(p.body).toBe("");
  });

  it("ステータス行が不正でも例外にならない", () => {
    const p = parseRawResponse("garbage");
    expect(p.status).toBeNull();
    expect(p.statusLine).toBe("garbage");
  });

  it("Set-Cookie の解析", () => {
    expect(parseSetCookie("sid=abc; Path=/; HttpOnly")).toEqual({ name: "sid", value: "abc", attrs: ["Path=/", "HttpOnly"] });
    expect(parseSetCookie("=novalue")).toBeNull();
    expect(parseSetCookie("junk")).toBeNull();
  });
});

describe("rawhttp: 検証つきのヘッダー行（Headers API の模擬）と可視化", () => {
  it("制御文字を含む値・不正な名前は例外", () => {
    expect(headerLine("Location", "/ok")).toBe("Location: /ok");
    expect(headerLine("X-Tab", "a\tb")).toBe("X-Tab: a\tb");
    expect(() => headerLine("Location", "/a\r\nSet-Cookie: x=1")).toThrow(/制御文字/);
    expect(() => headerLine("Location", "/a\nb")).toThrow();
    expect(() => headerLine("Location", "/a\0b")).toThrow();
    expect(() => headerLine("Bad Name", "x")).toThrow(/ヘッダー名/);
    expect(hasControlChars("a\rb")).toBe(true);
    expect(hasControlChars("plain 日本語\t")).toBe(false);
  });

  it("CR/LF を記号にして見せる", () => {
    expect(visualizeCrlf("a\r\nb\nc\rd")).toBe("a␍␊\nb␊\nc␍d");
  });

  it("HTML 版は本文を必ずエスケープし、改行記号を mark で包む", () => {
    const html = visualizeCrlfHtml("X: <b>\r\n\r\n");
    expect(html).toBe("X: &lt;b&gt;<mark>␍␊</mark>\n<mark>␍␊</mark>\n");
    expect(html).not.toContain("<b>");
  });
});

describe("rawmail: メール文面の組み立てと解析", () => {
  it("ヘッダーと本文を空行で区切る", () => {
    const raw = buildRawMail(["From: a@example.com", "To: admin@example.com", "Subject: hi"], "body\r\nline2");
    expect(raw).toBe("From: a@example.com\r\nTo: admin@example.com\r\nSubject: hi\r\n\r\nbody\r\nline2");
    const p = parseRawMail(raw);
    expect(p.headers.map((h) => h.name)).toEqual(["From", "To", "Subject"]);
    expect(p.body).toBe("body\r\nline2");
  });

  it("件名への CRLF 注入で Bcc ヘッダーが増え、配送先が増える", () => {
    const raw = buildRawMail(["From: a@example.com", "To: admin@example.com", "Subject: " + "hello\r\nBcc: victim@example.com"], "x");
    const p = parseRawMail(raw);
    expect(p.headers.map((h) => h.name)).toEqual(["From", "To", "Subject", "Bcc"]);
    expect(recipientsOf(p)).toEqual(["admin@example.com", "victim@example.com"]);
  });

  it("空行の注入で本文を差し替えられ、本来のヘッダーは本文側に回る", () => {
    const raw = buildRawMail(["To: admin@example.com", "Subject: " + "s\r\n\r\nspam body", "Content-Type: text/plain"], "orig");
    const p = parseRawMail(raw);
    expect(p.body.startsWith("spam body\r\n")).toBe(true);
    expect(p.headers.map((h) => h.name)).toEqual(["To", "Subject"]);
  });

  it("折り返し（継続行）は 1 つのヘッダーにまとめる", () => {
    const p = parseRawMail("Subject: =?UTF-8?B?44GC?=\r\n =?UTF-8?B?44GE?=\r\nTo: a@example.com\r\n\r\n");
    expect(p.headers).toHaveLength(2);
    expect(decodeMimeWords(p.headers[0].value)).toBe("あい");
  });

  it("recipientsOf は To/Cc/Bcc のアドレスを重複なく拾う（大文字小文字は同一視）", () => {
    const p = parseRawMail("To: A <admin@example.com>, b@example.com\r\nCc: ADMIN@example.com\r\nSubject: x@example.com\r\n\r\n");
    expect(recipientsOf(p)).toEqual(["admin@example.com", "b@example.com"]);
  });

  it("メールアドレスの簡易検証", () => {
    expect(isValidEmail("taro@example.com")).toBe(true);
    expect(isValidEmail("taro+lab@sub.example.com")).toBe(true);
    for (const bad of ["", "taro", "taro@", "@example.com", "a b@example.com", "taro@example.com\n", "taro@example.com\r\nBcc: x@example.com", "<a@example.com>", "a@b", "a@example.com, b@example.com"]) {
      expect(isValidEmail(bad), JSON.stringify(bad)).toBe(false);
    }
    expect(isValidEmail("a".repeat(65) + "@example.com")).toBe(false);
  });

  it("RFC 2047 風のエンコード: 日本語は =?UTF-8?B?…?= になり、読み戻せる", () => {
    expect(encodeMimeWord("Hello")).toBe("Hello");
    const enc = encodeMimeWord("お問い合わせ");
    expect(enc).toMatch(/^=\?UTF-8\?B\?[A-Za-z0-9+/=]+\?=$/);
    expect(decodeMimeWords(enc)).toBe("お問い合わせ");
    const long = "あ".repeat(60);
    const encLong = encodeMimeWord(long);
    expect(encLong).toContain("\r\n ");
    for (const w of encLong.split("\r\n ")) expect(w.length).toBeLessThanOrEqual(75);
    expect(decodeMimeWords(encLong.replace(/\r\n /g, " "))).toBe(long);
    expect(() => encodeMimeWord("a\r\nBcc: x")).toThrow();
  });

  it("composeMail: 値を渡すだけでヘッダーを組み立て、改行を含む値や不正なアドレスは拒否する", () => {
    const raw = composeMail({ from: "taro@example.com", to: "admin@example.com", subject: "お問い合わせ", text: "line1\nline2" });
    const p = parseRawMail(raw);
    expect(p.headers.map((h) => h.name)).toEqual(["From", "To", "Subject", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"]);
    expect(decodeMimeWords(p.headers[2].value)).toBe("お問い合わせ");
    expect(p.body).toBe("line1\r\nline2");
    expect(() => composeMail({ from: "taro@example.com", to: "admin@example.com", subject: "x\r\nBcc: v@example.com", text: "" })).toThrow(/制御文字/);
    expect(() => composeMail({ from: "taro@example.com\nBcc: v@example.com", to: "admin@example.com", subject: "x", text: "" })).toThrow();
    expect(() => composeMail({ from: "not-an-address", to: "admin@example.com", subject: "x", text: "" })).toThrow(/形式/);
    // 本文の中の「ヘッダーのような行」はただの本文
    const safe = parseRawMail(composeMail({ from: "t@example.com", to: "admin@example.com", subject: "x", text: "Bcc: v@example.com" }));
    expect(recipientsOf(safe)).toEqual(["admin@example.com"]);
  });
});
