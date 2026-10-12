/**
 * 演習ページ共通のHTMLヘルパー。
 *
 * - 修正版では必ず escapeHtml() を通す。脆弱版ではわざと通さない（テンプレートリテラルに直接埋め込む）。
 * - md() は解説文用の簡易マークアップ。常に全体をエスケープするので、解説文に生のHTMLは書けない。
 */

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** 解説文の簡易マークアップ → HTML。空行で段落、`- ` で箇条書き、`code`、**太字** */
export function md(text: string): string {
  const inline = (s: string) =>
    escapeHtml(s)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  return text
    .trim()
    .split(/\n{2,}/)
    .map((block) => {
      const lines = block.split("\n");
      if (lines.every((l) => /^\s*- /.test(l))) {
        return `<ul>${lines.map((l) => `<li>${inline(l.replace(/^\s*- /, ""))}</li>`).join("")}</ul>`;
      }
      if (lines.every((l) => /^\s*\d+\. /.test(l))) {
        return `<ol>${lines.map((l) => `<li>${inline(l.replace(/^\s*\d+\. /, ""))}</li>`).join("")}</ol>`;
      }
      return `<p>${lines.map(inline).join("<br>")}</p>`;
    })
    .join("\n");
}

interface ExercisePageOptions {
  /** 演習ID（バナーの「解説へ」リンクに使う） */
  id: string;
  mode: "vuln" | "fixed";
  title: string;
  /** <main> の中身（脆弱版では未エスケープの入力が混ざることがある） */
  body: string;
  /** <head> に追加する要素（<script src> など） */
  head?: string;
}

/** 脆弱版・修正版で共通の外枠。バナーで「いまどちらを触っているか」を常に示す */
export function exercisePage(o: ExercisePageOptions): string {
  const vuln = o.mode === "vuln";
  const banner = vuln
    ? `<strong>⚠ 脆弱版</strong><span>意図的に脆弱です。ダミーデータだけを使い、実在する情報は入力しないでください。</span>`
    : `<strong>✓ 修正版</strong><span>脆弱版と同じ操作を試して、攻撃が成立しなくなることを確かめましょう。</span>`;
  const other = vuln
    ? `<a href="/x/${o.id}/fixed/">修正版へ</a>`
    : `<a href="/x/${o.id}/vuln/">脆弱版へ</a>`;
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(o.title)} — ${vuln ? "脆弱版" : "修正版"}</title>
<link rel="stylesheet" href="/assets/lab.css">
${o.head ?? ""}
</head>
<body class="ex ex--${o.mode}">
<div class="ex-banner ex-banner--${o.mode}" role="note">
  ${banner}
  <nav><a href="/x/${o.id}">解説</a>${other}<a href="/">一覧</a></nav>
</div>
<main class="ex-main">
${o.body}
</main>
</body>
</html>`;
}

/** ダミーデータの表（値は常にエスケープする。XSS以外の演習で結果を表示するときに使う） */
export function table(headers: string[], rows: (string | number | null)[][]): string {
  const th = headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("");
  const tr = rows
    .map((r) => `<tr>${r.map((v) => `<td>${escapeHtml(String(v ?? "NULL"))}</td>`).join("")}</tr>`)
    .join("");
  return `<table class="data"><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table>`;
}
