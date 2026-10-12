import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

const dl = (mode: "vuln" | "fixed", file: string, route = "download") =>
  `/x/path-traversal/${mode}/${route}?file=${encodeURIComponent(file)}`;

describe("ディレクトリトラバーサル: 脆弱版", () => {
  it("通常の資料は読め、OS が解決したパスが画面に出る", async () => {
    const b = new Browser();
    const html = await b.text(dl("vuln", "readme.txt"));
    expect(html).toContain("社内資料ポータルのダミーの README");
    expect(html).toContain("/app/public/docs/readme.txt");
    expect(html).toContain("基準ディレクトリの中のファイルです");
  });

  it("../ で基準ディレクトリの外（設定ファイル・/etc/passwd）が読める", async () => {
    const b = new Browser();
    const secrets = await b.text(dl("vuln", "../../config/secrets.env"));
    expect(secrets).toContain("DB_PASSWORD=lab-fake-password");
    expect(secrets).toContain("OS が解決したパス");
    expect(secrets).toContain("/app/config/secrets.env");
    expect(secrets).toContain("基準ディレクトリ <code>/app/public/docs</code> の外");
    const passwd = await b.text(dl("vuln", "../../../etc/passwd"));
    expect(passwd).toContain("root:x:0:0");
    const deep = await b.text(dl("vuln", "../".repeat(10) + "etc/passwd"));
    expect(deep).toContain("labuser:x:1000");
  });

  it("URL エンコードされた ../ もフレームワークがデコードするので通る", async () => {
    const b = new Browser();
    const html = await b.text("/x/path-traversal/vuln/download?file=%2e%2e%2f%2e%2e%2fconfig%2fsecrets.env");
    expect(html).toContain("DB_PASSWORD=lab-fake-password");
  });

  it("存在しないファイルは ENOENT、ディレクトリは EISDIR", async () => {
    const b = new Browser();
    expect(await b.text(dl("vuln", "nothing.txt"))).toContain("ENOENT");
    expect(await b.text(dl("vuln", ".."))).toContain("EISDIR");
  });

  it("簡易対策（../ を消す）: 普通の ../ は防げるが、....// で破られる", async () => {
    const b = new Browser();
    const blocked = await b.text(dl("vuln", "../../config/secrets.env", "download-naive"));
    expect(blocked).not.toContain("DB_PASSWORD");
    expect(blocked).toContain("/app/public/docs/config/secrets.env"); // ../ が消えて docs の下を探しに行く
    const bypass = await b.text(dl("vuln", "....//....//config/secrets.env", "download-naive"));
    expect(bypass).toContain("DB_PASSWORD=lab-fake-password");
    expect(bypass).toContain("/app/config/secrets.env");
  });

  it("入力は画面にエスケープして出る（この演習の主題は XSS ではない）", async () => {
    const b = new Browser();
    const html = await b.text(dl("vuln", "<script>alert(1)</script>"));
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  });
});

describe("ディレクトリトラバーサル: 修正版", () => {
  it("一覧にある資料は読める", async () => {
    const b = new Browser();
    for (const f of ["readme.txt", "guide.txt"]) {
      const res = await b.get(dl("fixed", f));
      expect(res.status).toBe(200);
      expect(await res.text()).toContain("基準ディレクトリの中のファイルです");
    }
  });

  it("脆弱版と同じ攻撃（../、絶対パス、....//）はすべて拒否され、中身は出ない", async () => {
    const b = new Browser();
    const attacks = [
      "../../config/secrets.env",
      "../../../etc/passwd",
      "../images/logo.txt",
      "/etc/passwd",
      "....//....//config/secrets.env",
      "..\\..\\config\\secrets.env",
      "%2e%2e%2f%2e%2e%2fconfig%2fsecrets.env",
      "readme.txt\0.png",
      "docs/../readme.txt",
      "./readme.txt",
      "",
    ];
    for (const a of attacks) {
      const res = await b.get(dl("fixed", a));
      const html = await res.text();
      expect([400, 404], JSON.stringify(a)).toContain(res.status);
      expect(html, JSON.stringify(a)).not.toContain("DB_PASSWORD");
      expect(html, JSON.stringify(a)).not.toContain("root:x:0:0");
      expect(html, JSON.stringify(a)).toContain("拒否しました");
    }
  });

  it("拒否の理由: 文字の検査は 400、許可リストにないものは 404", async () => {
    const b = new Browser();
    expect((await b.get(dl("fixed", "a\\b"))).status).toBe(400);
    expect((await b.get(dl("fixed", "a%2eb"))).status).toBe(400);
    expect((await b.get(dl("fixed", "x\0y"))).status).toBe(400);
    expect((await b.get(dl("fixed", "../../config/secrets.env"))).status).toBe(404);
  });

  it("修正版に簡易対策ルートはない", async () => {
    const b = new Browser();
    expect((await b.get(dl("fixed", "readme.txt", "download-naive"))).status).toBe(404);
  });
});

describe("アクセスログ・学習者ごとの分離", () => {
  it("アクセスログに、読もうとしたパスと結果が残る（モードごとに分かれる）", async () => {
    const b = new Browser();
    await b.get(dl("vuln", "../../config/secrets.env"));
    await b.get(dl("fixed", "../../config/secrets.env"));
    const v = await b.text("/x/path-traversal/vuln/");
    expect(v).toContain("/app/config/secrets.env");
    expect(v).toContain("読めた（基準ディレクトリの外）");
    expect(v).not.toContain("拒否:");
    const f = await b.text("/x/path-traversal/fixed/");
    expect(f).toContain("拒否: 公開資料の一覧にないファイルです");
    expect(f).not.toContain("読めた（基準ディレクトリの外）");
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await a.get(dl("vuln", "../only-for-a.txt"));
    expect(await a.text("/x/path-traversal/vuln/")).toContain("only-for-a.txt");
    expect(await other.text("/x/path-traversal/vuln/")).not.toContain("only-for-a.txt");
  });
});

describe("解説ページ", () => {
  it("原因のコード・修正の差分が表示される", async () => {
    const b = new Browser();
    const html = await b.text("/x/path-traversal");
    expect(html).toContain("ディレクトリトラバーサル");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain("....//....//config/secrets.env");
  });
});
