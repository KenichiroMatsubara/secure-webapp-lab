/**
 * 各演習ファイルの `//#region vuln` と `//#region fixed` を抜き出し、
 * 解説ページの「原因のコード」「修正の差分」に使う src/generated/sources.ts を作る。
 *
 * 同じ名前の region が複数あれば、出現順に空行を挟んで連結する。
 * `[!]` を含む行は、解説ページで黄色くハイライトされる。
 */
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createTwoFilesPatch } from "diff";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dir = join(root, "src", "exercises");

function extract(src: string, name: "vuln" | "fixed", file: string): string {
  const re = new RegExp(`^[ \\t]*//#region ${name}\\b.*\\n([\\s\\S]*?)^[ \\t]*//#endregion`, "gm");
  const parts = [...src.matchAll(re)].map((m) => m[1].replace(/\s+$/, ""));
  if (parts.length === 0) throw new Error(`${file}: //#region ${name} が見つかりません`);
  return dedent(parts.join("\n\n")) + "\n";
}

function dedent(s: string): string {
  const lines = s.split("\n");
  const indents = lines.filter((l) => l.trim()).map((l) => l.match(/^[ \t]*/)![0].length);
  const n = indents.length ? Math.min(...indents) : 0;
  return lines.map((l) => l.slice(n)).join("\n");
}

const out: Record<string, { vuln: string; fixed: string; diff: string }> = {};
for (const f of readdirSync(dir).filter((f) => f.endsWith(".ts")).sort()) {
  const id = f.replace(/\.ts$/, "");
  const src = readFileSync(join(dir, f), "utf8");
  const vuln = extract(src, "vuln", f);
  const fixed = extract(src, "fixed", f);
  const diff = createTwoFilesPatch("脆弱版", "修正版", vuln, fixed, "", "", { context: 3 });
  out[id] = { vuln, fixed, diff };
}

mkdirSync(join(root, "src", "generated"), { recursive: true });
writeFileSync(
  join(root, "src", "generated", "sources.ts"),
  `// 自動生成: scripts/gen-sources.ts（編集しない）\nimport type { ExerciseSource } from "../lab/types";\n\nexport const sources: Record<string, ExerciseSource> = ${JSON.stringify(out, null, 2)};\n`,
);
console.log(`generated sources for ${Object.keys(out).length} exercises`);
