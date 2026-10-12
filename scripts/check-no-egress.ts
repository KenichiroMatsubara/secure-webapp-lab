/**
 * 「アプリのコードは外部へ通信しない」ことの静的検査。
 * Cloudflare Workers には通常のWorker向けの送信ファイアウォールがないため、コード側で禁止し CI で守る。
 * 例外は src/lab/access.ts（Cloudflare Access の公開鍵 JWKS の取得）だけ。
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const ALLOWED = new Set(["src/lab/access.ts"]);
const FORBIDDEN: [RegExp, string][] = [
  // `async fetch(` は Worker のエクスポートメソッドの定義（呼び出しではない）
  [/(?<![.\w])(?<!async\s)fetch\s*\(/, "fetch()"],
  [/\b(globalThis|self|window)\.fetch\b/, "globalThis.fetch"],
  [/\benv\.\w+\.fetch\b/, "サービスバインディングの fetch"],
  [/\bXMLHttpRequest\b/, "XMLHttpRequest"],
  [/\bWebSocket\b/, "WebSocket"],
  [/cloudflare:sockets/, "cloudflare:sockets"],
  [/\bcreateRemoteJWKSet\b/, "createRemoteJWKSet"],
  [/\bnode:(http|https|net|tls|dgram)\b/, "node:http など"],
  [/\bcaches\b\s*\./, "Cache API"],
];

// サーバー側のコードだけが対象。ブラウザへ配る文字列（ページ内の <script>）は検査しない
function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith(".ts") ? [p] : [];
  });
}

/** テンプレートリテラル/文字列の中身（ブラウザ向けコード）を粗く除いたうえで検査する */
function stripStringsAndComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^\s*\/\/.*$/gm, "")
    .replace(/`(?:\\[\s\S]|\$\{[^}]*\}|[^`\\])*`/g, "``");
}

let bad = 0;
for (const file of walk(join(root, "src"))) {
  const rel = relative(root, file);
  if (ALLOWED.has(rel) || rel.startsWith("src/generated/")) continue;
  const code = stripStringsAndComments(readFileSync(file, "utf8"));
  for (const [re, label] of FORBIDDEN) {
    if (re.test(code)) {
      console.error(`NG: ${rel} に ${label} があります（外部通信の疑い）`);
      bad++;
    }
  }
}
if (bad) process.exit(1);
console.log("OK: 外部通信コードは src/lab/access.ts 以外にありません");
