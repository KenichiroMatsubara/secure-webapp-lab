import { describe, expect, it } from "vitest";
import { exercises } from "../src/lab/registry";
import { sources } from "../src/generated/sources";
import { Browser } from "./helpers";

// すべての演習が満たすべき「教材としての約束」。演習を足したときの受け入れ基準になる
describe("演習の契約", () => {
  it("id は一意で、小文字とハイフンだけ", () => {
    const ids = exercises.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^[a-z][a-z0-9-]*$/);
  });

  it("第4章と第5章の演習がそろっている", () => {
    expect(exercises.filter((e) => e.book.chapter === 4).length).toBeGreaterThanOrEqual(12);
    expect(exercises.filter((e) => e.book.chapter === 5).length).toBeGreaterThanOrEqual(3);
  });

  for (const e of exercises) {
    describe(e.id, () => {
      it("表名は演習IDの接頭辞で始まる", () => {
        const prefix = e.id.replace(/-/g, "_") + "_";
        for (const s of e.schema ?? []) {
          const m = /CREATE TABLE(?: IF NOT EXISTS)?\s+([A-Za-z0-9_]+)/i.exec(s);
          expect(m, s).toBeTruthy();
          expect(m![1].startsWith(prefix), `${m![1]} は ${prefix} で始める`).toBe(true);
        }
      });

      it("解説が揃っている（目標・手順・原因・修正・確認・クイズ）", () => {
        const d = e.doc;
        expect(e.summary.length).toBeGreaterThan(15);
        expect(d.goals.length).toBeGreaterThanOrEqual(2);
        expect(d.background.length).toBeGreaterThan(80);
        expect(d.steps.length).toBeGreaterThanOrEqual(3);
        expect(d.cause.length).toBeGreaterThan(40);
        expect(d.fix.length).toBeGreaterThan(40);
        expect(d.verify.length).toBeGreaterThanOrEqual(2);
        expect(d.beyond.length).toBeGreaterThan(40);
        expect(d.quiz.length).toBeGreaterThanOrEqual(2);
        for (const s of d.steps) expect(s.title && s.body).toBeTruthy();
        expect(JSON.stringify(d)).not.toMatch(/TODO/);
      });

      it("原因のコードに [!] があり、修正の差分が空でない", () => {
        const s = sources[e.id];
        expect(s, "npm run gen を実行してください").toBeTruthy();
        expect(s.vuln).toContain("[!]");
        expect(s.fixed).not.toContain("[!]");
        expect(s.diff).toMatch(/^[+-][^+-]/m);
      });

      it("解説・脆弱版・修正版のトップが開く", async () => {
        const b = new Browser();
        for (const path of [`/x/${e.id}`, `/x/${e.id}/vuln/`, `/x/${e.id}/fixed/`]) {
          const res = await b.get(path);
          expect(res.status, path).toBe(200);
        }
        if (e.attacker) expect((await b.get(`/attacker/${e.id}/`)).status).toBe(200);
      });

      it("解説の「開く」リンクがすべて生きている", async () => {
        const b = new Browser();
        for (const s of e.doc.steps) {
          if (!s.open) continue;
          const href = s.open.href.startsWith("/") ? s.open.href : `/x/${e.id}/${s.open.href}`;
          const res = await b.get(href);
          expect(res.status, href).toBeLessThan(400);
        }
      });

      it("脆弱版ページのガード CSP と、noindex が付く", async () => {
        const res = await new Browser().get(`/x/${e.id}/vuln/`);
        expect(res.headers.get("content-security-policy")).toContain("connect-src 'self'");
        expect(res.headers.get("x-robots-tag")).toContain("noindex");
        if (e.allowFramingOfVuln) expect(res.headers.get("content-security-policy")).not.toContain("frame-ancestors");
      });
    });
  }
});
