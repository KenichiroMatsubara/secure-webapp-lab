import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

const ping = (b: Browser, mode: "vuln" | "fixed", host: string, route = "ping") =>
  b.post(`/x/os-command-injection/${mode}/${route}`, { host });

describe("OSコマンドインジェクション: 脆弱版", () => {
  it("通常のホストは ping の出力が出て、実行されたコマンドライン・コマンドが表示される", async () => {
    const b = new Browser();
    const html = await (await ping(b, "vuln", "localhost")).text();
    expect(html).toContain("$ ping -c 1 localhost");
    expect(html).toContain("PING localhost (127.0.0.1)");
    expect(html).toContain("擬似環境です");
    const unknown = await (await ping(b, "vuln", "nothere.example")).text();
    expect(unknown).toContain("ping: unknown host nothere.example");
  });

  it("; で任意のコマンドがつながり、設定ファイル（ダミー）が読める", async () => {
    const b = new Browser();
    const html = await (await ping(b, "vuln", "localhost; cat /app/config/secrets.env")).text();
    expect(html).toContain("$ ping -c 1 localhost; cat /app/config/secrets.env");
    expect(html).toContain("DB_PASSWORD=lab-fake-password");
    expect(html).toContain("cat /app/config/secrets.env"); // 実際に実行されたコマンドの表
  });

  it("&& / || / | / $( ) / バッククォートも成立する", async () => {
    const b = new Browser();
    expect(await (await ping(b, "vuln", "localhost && id")).text()).toContain("uid=1000(labuser)");
    expect(await (await ping(b, "vuln", "nothere.example || id")).text()).toContain("uid=1000(labuser)");
    expect(await (await ping(b, "vuln", "nothere.example && id")).text()).not.toContain("uid=1000");
    const pipe = await (await ping(b, "vuln", "localhost | ls /app")).text();
    expect(pipe).toContain("config");
    expect(pipe).not.toContain("PING localhost");
    const sub = await (await ping(b, "vuln", "$(whoami)")).text();
    expect(sub).toContain("ping: unknown host labuser");
    expect(await (await ping(b, "vuln", "`id`")).text()).toContain("ping: unknown host uid=1000(labuser)");
  });

  it("引数インジェクション: -c を差し込むと ping の回数が書き換わる", async () => {
    const b = new Browser();
    const html = await (await ping(b, "vuln", "-c 5000 localhost")).text();
    expect(html).toContain("5000 packets transmitted");
  });

  it("破壊的コマンドは実行されず、その旨が出る", async () => {
    const b = new Browser();
    const html = await (await ping(b, "vuln", "localhost; rm -rf /app")).text();
    expect(html).toContain("(擬似環境のため実行しません)");
    const still = await (await ping(b, "vuln", "localhost; cat /etc/passwd")).text();
    expect(still).toContain("root:x:0:0");
  });

  it("引用符で囲む対策版: ; や $( ) は防げるが、- で始まる値はオプションとして解釈される", async () => {
    const b = new Browser();
    const semi = await (await ping(b, "vuln", "localhost; cat /app/config/secrets.env", "ping-quoted")).text();
    expect(semi).not.toContain("DB_PASSWORD");
    expect(semi).toContain("unknown host localhost; cat /app/config/secrets.env");
    const sub = await (await ping(b, "vuln", "$(whoami)", "ping-quoted")).text();
    expect(sub).toContain("unknown host $(whoami)");
    const opt = await (await ping(b, "vuln", "-c5000 localhost", "ping-quoted")).text();
    expect(opt).toContain("ping: invalid argument: &#39;5000 localhost&#39;");
  });

  it("入力は画面にエスケープして出る", async () => {
    const b = new Browser();
    const html = await (await ping(b, "vuln", "<script>alert(1)</script>")).text();
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });
});

describe("OSコマンドインジェクション: 修正版", () => {
  it("通常のホストは実行でき、シェルを通さない旨と argv が表示される", async () => {
    const b = new Browser();
    for (const h of ["localhost", "example.com"]) {
      const res = await ping(b, "fixed", h);
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain(`$ ping -c 1 -- ${h}`);
      expect(html).toContain("1 packets transmitted, 1 received");
      expect(html).toContain("シェルを通さず");
    }
    // 形式として正しければ実行される（存在しないホストは unknown host）
    expect(await (await ping(b, "fixed", "nothere.example")).text()).toContain("ping: unknown host nothere.example");
  });

  it("脆弱版と同じペイロードは、すべて入力検証で拒否される（コマンドは実行されない）", async () => {
    const b = new Browser();
    const attacks = [
      "localhost; cat /app/config/secrets.env",
      "localhost && id",
      "nothere.example || id",
      "localhost | ls /app",
      "$(whoami)",
      "`id`",
      "-c 5000 localhost",
      "-c5000",
      "localhost\nid",
      "localhost\n",
      "",
      "a".repeat(300),
      "localhost.",
      "-localhost",
    ];
    for (const a of attacks) {
      const res = await ping(b, "fixed", a);
      const html = await res.text();
      expect(res.status, JSON.stringify(a)).toBe(400);
      expect(html, JSON.stringify(a)).toContain("ホスト名として使えない文字");
      expect(html, JSON.stringify(a)).not.toContain("DB_PASSWORD");
      expect(html, JSON.stringify(a)).not.toContain("uid=1000");
      expect(html, JSON.stringify(a)).not.toContain("packets transmitted");
    }
  });

  it("検証を通る入力は、argv の1つの要素として渡る（シェルは介在しない）", async () => {
    const b = new Browser();
    const html = await (await ping(b, "fixed", "a-b.example")).text();
    expect(html).toContain("ping -c 1 -- a-b.example");
    expect(html).toContain("実際に実行されたコマンド");
  });
});

describe("実行履歴・学習者ごとの分離", () => {
  it("履歴はモードごとに残る", async () => {
    const b = new Browser();
    await ping(b, "vuln", "localhost; id");
    await ping(b, "fixed", "localhost");
    const v = await b.text("/x/os-command-injection/vuln/");
    expect(v).toContain("ping -c 1 localhost; id");
    expect(v).not.toContain("ping -c 1 -- localhost");
    const f = await b.text("/x/os-command-injection/fixed/");
    expect(f).toContain("ping -c 1 -- localhost");
  });

  it("学習者ごとにデータが分かれる（別のブラウザには見えない）", async () => {
    const a = new Browser();
    const other = new Browser();
    await ping(a, "vuln", "localhost; echo only-for-a");
    expect(await a.text("/x/os-command-injection/vuln/")).toContain("only-for-a");
    expect(await other.text("/x/os-command-injection/vuln/")).not.toContain("only-for-a");
  });
});

describe("解説ページ", () => {
  it("原因のコード・修正の差分が表示される", async () => {
    const b = new Browser();
    const html = await b.text("/x/os-command-injection");
    expect(html).toContain("OSコマンドインジェクション");
    expect(html).toContain('class="ln hl"');
    expect(html).toContain('class="add"');
    expect(html).toContain("localhost; cat /app/config/secrets.env");
  });
});
