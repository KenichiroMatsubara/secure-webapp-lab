import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { sources } from "../generated/sources";
import { labCss, labJs } from "./assets";
import { escapeHtml, md } from "./html";
import { exercises, getExercise } from "./registry";
import type { Exercise, Step } from "./types";

/** ホーム・解説ページ・リセットなど、ラボ本体（演習ではない）のページ */
export const shell = new Hono<AppEnv>();

const BOOK = "『体系的に学ぶ 安全なWebアプリケーションの作り方（第2版）』";

function layout(title: string, body: string): string {
  return `<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/assets/lab.css">
<script src="/assets/lab.js" defer></script>
</head>
<body>
<header class="site-header"><div class="wrap">
  <a class="brand" href="/">🛡 安全なWebアプリの作り方ラボ</a>
  <nav><a href="/">演習一覧</a><a href="/about">安全上の仕組み</a></nav>
</div></header>
<div class="wrap">
${body}
<footer class="site-footer">
  <p>個人学習用の副教材です。${BOOK}（徳丸 浩 著）を読みながら手を動かすための独自演習で、書籍の本文・コード・図は含みません。著者・出版社とは無関係です。</p>
</footer>
</div>
</body>
</html>`;
}

function stars(n: number): string {
  return "★".repeat(n) + "☆".repeat(3 - n);
}

/** 同一オリジンからのリクエストだけを受け付ける（ラボ自身の状態変更APIをCSRFから守る） */
function isSameOrigin(c: Context<AppEnv>): boolean {
  const site = c.req.header("Sec-Fetch-Site");
  if (site) return site === "same-origin";
  const origin = c.req.header("Origin");
  return !!origin && origin === new URL(c.req.url).origin;
}

// ---------- 静的アセット ----------
shell.get("/assets/lab.css", (c) => c.body(labCss, 200, { "Content-Type": "text/css; charset=UTF-8" }));
shell.get("/assets/lab.js", (c) =>
  c.body(labJs, 200, { "Content-Type": "text/javascript; charset=UTF-8" }),
);
shell.get("/robots.txt", (c) => c.text("User-agent: *\nDisallow: /\n"));

// ---------- ホーム ----------
shell.get("/", async (c) => {
  const rows = await c.var.db.all<{ exercise_id: string; attacked: number; understood: number }>(
    "SELECT exercise_id, attacked, understood FROM lab_progress",
  );
  const progress = new Map(rows.map((r) => [r.exercise_id, r]));

  const card = (e: Exercise) => {
    const p = progress.get(e.id);
    const tags = [
      p?.attacked ? `<span class="tag tag--done">攻撃できた</span>` : "",
      p?.understood ? `<span class="tag tag--done">修正を理解した</span>` : "",
    ].join("");
    return `<article class="card">
  <h3><a href="/x/${e.id}">${escapeHtml(e.title)}</a></h3>
  <p>${escapeHtml(e.summary)}</p>
  <div class="meta"><span>難易度 ${stars(e.level)}</span><span>本書 第${e.book.chapter}章「${escapeHtml(e.book.topic)}」</span></div>
  <div class="meta">${tags}</div>
  <div class="links"><a href="/x/${e.id}">解説</a><a href="/x/${e.id}/vuln/">⚠ 脆弱版</a><a href="/x/${e.id}/fixed/">✓ 修正版</a></div>
</article>`;
  };

  const section = (chapter: 4 | 5, heading: string) => {
    const list = exercises.filter((e) => e.book.chapter === chapter);
    if (!list.length) return "";
    return `<h2>${heading}</h2><div class="grid">${list.map(card).join("")}</div>`;
  };

  const done = [...progress.values()].filter((p) => p.attacked && p.understood).length;

  return c.html(
    layout(
      "安全なWebアプリの作り方ラボ",
      `<h1>安全なWebアプリの作り方ラボ</h1>
<p class="lede">${BOOK}の第4章・第5章に沿って、<strong>わざと脆弱にしたアプリを攻撃し、原因のコードを読み、修正版で防げることを確かめる</strong>ハンズオンです。</p>
<div class="notice">
  <strong>学び方:</strong> 各演習は「①解説で攻撃手順を読む → ②脆弱版を攻撃する → ③原因のコードを読む → ④修正の差分を読む → ⑤修正版で同じ攻撃が止まるのを確かめる」の順に進みます。
  進み具合: <strong>${done} / ${exercises.length}</strong> 演習が完了。
</div>
<div class="notice notice--warn">
  脆弱版は<strong>意図的に脆弱</strong>です。ダミーデータだけを使い、実在の個人情報やパスワードは入力しないでください。
  学習データはあなた専用で、${escapeHtml(c.env.LAB_TTL_HOURS || "24")} 時間操作がないと自動で削除されます。
</div>
${section(4, "第4章 Webアプリケーションの機能別に見るセキュリティバグ")}
${section(5, "第5章 代表的なセキュリティ機能（認証・アカウント管理・認可）")}
<h2>学習データのリセット</h2>
<form method="post" action="/lab/reset" class="actions">
  <button class="danger" type="submit">すべての演習データを初期状態に戻す</button>
</form>`,
    ),
  );
});

// ---------- 安全上の仕組み ----------
shell.get("/about", (c) =>
  c.html(
    layout(
      "安全上の仕組み",
      `<h1>このラボが安全に公開できる理由</h1>
<p class="lede">脆弱なアプリをインターネットに置けば、そのままでは第三者の攻撃やフィッシングの踏み台に使われます。そこで次の 6 つの仕組みで囲っています。</p>
${md(`
1. **Cloudflare Access で本人だけが入れる** … 前段で認証を求めます。さらにアプリ自身も Access の JWT（署名・発行者・対象アプリ）を毎回検証し、設定がなければ全リクエストを拒否します（fail-closed）。
2. **学習者ごとにデータを分離** … 学習者 1 人につき 1 つの SQLite（Durable Object）を割り当てます。SQL インジェクションで何を壊しても、影響は自分のデータだけです。
3. **外部へ通信しない** … アプリのコードは外部へリクエストを送りません（Access の公開鍵の取得だけが例外で、CI で検査しています）。XSS が成立しても Cookie を外部へ送れないよう、脆弱版ページには CSP（\`connect-src 'self'\` など）を外側からかけています。
4. **実在サイトへリダイレクトしない** … オープンリダイレクトの演習でも、転送先が \`.example\` / \`.test\` などの予約ドメイン以外なら、転送せずに「転送しようとした」ことだけを表示します。
5. **データは自動で消える** … 最後の操作から一定時間（既定 24 時間）で学習データを削除します。いつでも手動でリセットもできます。
6. **検索エンジンに載せない** … \`noindex\` と \`robots.txt\` で除外し、キャッシュも禁止しています。
`)}
<h2>擬似的に再現している演習</h2>
${md(`
Cloudflare Workers にはファイルシステムもシェルもなく、HTTP ヘッダーの改行も拒否されます。そのため次の演習は、**同じ原理を JavaScript で作った擬似環境**で再現しています。実際のコマンド実行やメール送信は行いません。

- ディレクトリトラバーサル … メモリ上の仮想ファイルシステム
- OSコマンドインジェクション … JavaScript 製の擬似シェル
- HTTPヘッダインジェクション・メールヘッダインジェクション … 改行を含む生のヘッダー行を組み立てて解析する擬似実装
`)}
<h2>ローカルで動かす</h2>
<pre><code>npm install
npm run dev   # http://localhost:8787</code></pre>
<p>ローカルでは Access の検証を省略します。本番へ出す手順は <code>docs/DEPLOY.md</code> を見てください。</p>`,
    ),
  ),
);

// ---------- ラボの状態変更（同一オリジンのみ） ----------
shell.post("/lab/reset", async (c) => {
  if (!isSameOrigin(c)) return c.text("Forbidden", 403);
  await c.var.db.reset();
  return c.redirect("/", 303);
});

shell.post("/lab/progress", async (c) => {
  if (!isSameOrigin(c)) return c.text("Forbidden", 403);
  const form = await c.req.parseBody();
  const id = String(form["exercise"] ?? "");
  if (!getExercise(id)) return c.text("Not found", 404);
  const attacked = form["attacked"] === "on" ? 1 : 0;
  const understood = form["understood"] === "on" ? 1 : 0;
  await c.var.db.run(
    `INSERT INTO lab_progress (exercise_id, attacked, understood) VALUES (?, ?, ?)
     ON CONFLICT(exercise_id) DO UPDATE SET attacked = excluded.attacked, understood = excluded.understood`,
    [id, attacked, understood],
  );
  return c.redirect(`/x/${id}#progress`, 303);
});

// ---------- 解説ページ ----------
function renderCode(src: string): string {
  const lines = src.replace(/\n+$/, "").split("\n");
  const body = lines
    .map((l) => `<span class="ln${l.includes("[!]") ? " hl" : ""}">${escapeHtml(l) || " "}</span>`)
    .join("");
  return `<pre class="code"><code>${body}</code></pre>`;
}

function renderDiff(diff: string): string {
  const lines = diff.split("\n").filter((l) => !/^(Index:|={5,}|---|\+\+\+)/.test(l));
  const body = lines
    .filter((l, i, a) => !(i === a.length - 1 && l === ""))
    .map((l) => {
      const cls = l.startsWith("@@") ? "hunk" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "ctx";
      return `<span class="${cls}">${escapeHtml(l) || " "}</span>`;
    })
    .join("");
  return `<pre class="code diff"><code>${body}</code></pre>`;
}

function renderStep(e: Exercise, s: Step): string {
  const payloads = (s.payloads ?? [])
    .map(
      (p) => `<div class="payload"><span class="lbl">${escapeHtml(p.label)}</span>
  <code>${escapeHtml(p.value)}</code>
  <button type="button" class="ghost copy" data-copy="${escapeHtml(p.value)}">コピー</button>
  ${p.note ? `<span class="note">${escapeHtml(p.note)}</span>` : ""}</div>`,
    )
    .join("");
  const href = s.open ? (s.open.href.startsWith("/") ? s.open.href : `/x/${e.id}/${s.open.href}`) : "";
  const open = s.open
    ? `<p><a class="btn" href="${escapeHtml(href)}">${escapeHtml(s.open.label)} →</a></p>`
    : "";
  return `<li class="step"><h3>${escapeHtml(s.title)}</h3>${md(s.body)}${payloads}${open}</li>`;
}

shell.get("/x/:id", async (c) => {
  const e = getExercise(c.req.param("id"));
  if (!e) return c.notFound();
  const src = sources[e.id];
  const p = await c.var.db.first<{ attacked: number; understood: number }>(
    "SELECT attacked, understood FROM lab_progress WHERE exercise_id = ?",
    [e.id],
  );
  const d = e.doc;

  const body = `<p><a href="/">← 演習一覧</a></p>
<h1>${escapeHtml(e.title)}</h1>
<p class="lede">${escapeHtml(e.summary)}</p>
<p><span class="badge">難易度 ${stars(e.level)}</span>
   <span class="badge">本書 第${e.book.chapter}章「${escapeHtml(e.book.topic)}」</span></p>
<div class="actions">
  <a class="btn" href="/x/${e.id}/vuln/">⚠ 脆弱版を開く</a>
  <a class="btn btn--ghost" href="/x/${e.id}/fixed/">✓ 修正版を開く</a>
</div>
<nav class="toc"><strong>目次</strong><ol>
  <li><a href="#goals">学習目標</a></li><li><a href="#background">どんな脆弱性か</a></li>
  <li><a href="#attack">攻撃してみる</a></li><li><a href="#cause">原因のコード</a></li>
  <li><a href="#fix">修正の差分</a></li><li><a href="#verify">修正版で確かめる</a></li>
  <li><a href="#beyond">残るリスクと多層防御</a></li><li><a href="#quiz">理解度チェック</a></li>
  <li><a href="#book">本書の対応章</a></li>
</ol></nav>

<h2 id="goals">学習目標</h2>
<ul>${d.goals.map((g) => `<li>${escapeHtml(g)}</li>`).join("")}</ul>

<h2 id="background">どんな脆弱性か</h2>
${md(d.background)}

<h2 id="attack">攻撃してみる <span class="badge badge--vuln">脆弱版</span></h2>
<ol class="steps">${d.steps.map((s) => renderStep(e, s)).join("")}</ol>

<h2 id="cause">原因のコード</h2>
${md(d.cause)}
${src ? renderCode(src.vuln) : ""}
<p class="lede">黄色の行（<code>[!]</code> 付き）が問題の箇所です。</p>

<h2 id="fix">修正の差分 <span class="badge badge--fixed">修正版</span></h2>
${md(d.fix)}
${src ? renderDiff(src.diff) : ""}
<details class="qa"><summary>修正版の全文を見る</summary>${src ? renderCode(src.fixed) : ""}</details>

<h2 id="verify">修正版で確かめる</h2>
<ol>${d.verify.map((v) => `<li>${escapeHtml(v)}</li>`).join("")}</ol>
<p><a class="btn btn--ghost" href="/x/${e.id}/fixed/">✓ 修正版を開く →</a></p>

<h2 id="beyond">残るリスクと多層防御</h2>
${md(d.beyond)}

<h2 id="quiz">理解度チェック</h2>
${d.quiz.map((q) => `<details class="qa"><summary>${escapeHtml(q.q)}</summary>${md(q.a)}</details>`).join("")}

<h2 id="book">本書の対応章</h2>
<p>${BOOK}の <strong>第${e.book.chapter}章「${escapeHtml(e.book.topic)}」</strong>に対応します。節番号や詳しい説明は、お手元の版の目次で確認してください。</p>

<form id="progress" method="post" action="/lab/progress" class="progress">
  <input type="hidden" name="exercise" value="${e.id}">
  <label><input type="checkbox" name="attacked" ${p?.attacked ? "checked" : ""}> 脆弱版を攻撃できた</label>
  <label><input type="checkbox" name="understood" ${p?.understood ? "checked" : ""}> 修正の理由を説明できる</label>
  <button type="submit">記録する</button>
</form>`;

  return c.html(layout(`${e.title} — 解説`, body));
});
