import { describe, expect, it } from "vitest";
import { Browser } from "./helpers";

describe("ホームと基本ページ", () => {
  it("ホームに演習一覧と安全上の注意が出る", async () => {
    const html = await new Browser().text("/");
    expect(html).toContain("安全なWebアプリの作り方ラボ");
    expect(html).toContain("/x/xss-reflected");
    expect(html).toContain("意図的に脆弱");
  });

  it("robots.txt は全拒否、about ページが開く", async () => {
    const b = new Browser();
    expect(await b.text("/robots.txt")).toContain("Disallow: /");
    expect(await b.text("/about")).toContain("6 つの仕組み");
  });

  it("存在しない演習は 404", async () => {
    expect((await new Browser().get("/x/nope")).status).toBe(404);
  });
});

describe("リセットと進捗", () => {
  it("リセットすると学習データが初期状態に戻る", async () => {
    const b = new Browser();
    await b.get("/attacker/xss-reflected/collect?c=to-be-erased");
    expect(await b.text("/attacker/xss-reflected/")).toContain("to-be-erased");
    const res = await b.post("/lab/reset");
    expect(res.status).toBe(303);
    expect(await b.text("/attacker/xss-reflected/")).not.toContain("to-be-erased");
  });

  it("リセットと進捗の更新は同一オリジンからだけ受け付ける（CSRF対策）", async () => {
    const b = new Browser();
    const cross = { "Sec-Fetch-Site": "cross-site" };
    expect((await b.post("/lab/reset", {}, cross)).status).toBe(403);
    expect((await b.post("/lab/progress", { exercise: "xss-reflected", attacked: "on" }, cross)).status).toBe(403);
    // Sec-Fetch-Site がない古いクライアントでも、Origin が一致しなければ拒否
    const noFetchMeta = await b.request("/lab/reset", {
      method: "POST",
      headers: { Origin: "https://evil.example", "Content-Type": "application/x-www-form-urlencoded" },
      body: "",
    });
    expect(noFetchMeta.status).toBe(403);
  });

  it("進捗を記録するとホームに反映される", async () => {
    const b = new Browser();
    const res = await b.post("/lab/progress", { exercise: "xss-reflected", attacked: "on", understood: "on" });
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe("/x/xss-reflected#progress");
    const home = await b.text("/");
    expect(home).toContain("攻撃できた");
    expect(home).toContain("修正を理解した");
    expect((await b.post("/lab/progress", { exercise: "nope" })).status).toBe(404);
  });
});
