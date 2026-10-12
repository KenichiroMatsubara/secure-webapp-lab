import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { FakeShell, escapeShellArg, formatCommand, type ShellResult } from "../lab/fakeshell";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";

/**
 * OSコマンドインジェクション。
 *
 * Workers にはシェルがないので、JavaScript 製の擬似シェル（src/lab/fakeshell.ts）で再現する。
 * 実際のコマンドは一切実行しない。ping も cat も、ダミーの出力を返すだけ。
 */

const ID = "os-command-injection";
type Mode = "vuln" | "fixed";

const shell = new FakeShell();

const NOTICE = `<div class="notice"><strong>擬似環境です。</strong> Cloudflare Workers にはシェルがないため、JavaScript で作った擬似シェルが <code>ping</code> や <code>cat</code> を「実行したふり」をします。実際のコマンド実行・ファイル読み取り・ネットワーク通信は一切行いません。</div>`;

interface Run {
  /** シェルに渡した 1 行（修正版は argv を表示用に整形したもの） */
  line: string;
  /** どう実行したか */
  how: string;
  result: ShellResult;
}

/** 実行履歴に残し、結果ページを返す */
async function showResult(c: Context<AppEnv>, mode: Mode, run: Run, status: 200 | 400 = 200) {
  await c.var.db.run(
    "INSERT INTO os_command_injection_history (mode, commandline, output, exit_code) VALUES (?, ?, ?, ?)",
    [mode, run.line.slice(0, 500), run.result.output.slice(0, 2000), run.result.exitCode],
  );
  const r = run.result;
  const executed = r.executed.length
    ? table(
        ["#", "実際に実行されたコマンド", "終了コード"],
        r.executed.map((e, i) => [i + 1, formatCommand(e.argv), e.exitCode]),
      )
    : "<p>実行されたコマンドはありません。</p>";
  const body = `<h1>疎通確認の結果</h1>
${NOTICE}
<h2>実行されたコマンドライン</h2>
<pre class="code"><code>$ ${escapeHtml(run.line)}</code></pre>
<p>${escapeHtml(run.how)}</p>
<h2>実際に実行されたコマンド</h2>
${executed}
<h2>出力</h2>
<pre class="code"><code>${escapeHtml(r.output) || " "}</code></pre>
<p>終了コード: <strong>${r.exitCode}</strong></p>
<p><a href="/x/${ID}/${mode}/">← 入力へ戻る</a></p>`;
  return c.html(exercisePage({ id: ID, mode, title: "疎通確認の結果", body }), status);
}

/** 入力フォームと実行履歴 */
async function formPage(c: Context<AppEnv>, mode: Mode, error = "", status: 200 | 400 = 200, submitted?: string) {
  const host = (submitted ?? c.req.query("host") ?? "localhost").slice(0, 500);
  const history = await c.var.db.all<{ commandline: string; output: string; exit_code: number }>(
    "SELECT commandline, output, exit_code FROM os_command_injection_history WHERE mode = ? ORDER BY id DESC LIMIT 5",
    [mode],
  );
  const quoted =
    mode === "vuln"
      ? `<h2>引用符で囲む対策版</h2>
<p>こちらは入力を <code>escapeshellarg</code> のように引用符で囲んでからシェルに渡す、別ルートです。本当に防げているか試してください。</p>
<form method="post" action="/x/${ID}/vuln/ping-quoted">
  <label>ホスト名 <input name="host" value="${escapeHtml(host)}" size="40"></label> <button>疎通確認</button>
</form>`
      : "";
  const body = `<h1>サーバー疎通確認ツール</h1>
${NOTICE}
<p>入力したホストに <code>ping</code> を 1 回送り、届くかどうかを確かめる社内ツールです。試せるホスト名は <code>example.com</code> と <code>localhost</code> です。</p>
${error ? `<div class="notice notice--warn"><strong>入力エラー:</strong> ${escapeHtml(error)}</div>` : ""}
<form method="post" action="/x/${ID}/${mode}/ping">
  <label>ホスト名 <input name="host" value="${escapeHtml(host)}" size="40"></label> <button>疎通確認</button>
</form>
${quoted}
<h2>実行履歴</h2>
${history.length ? table(["コマンドライン", "出力（先頭）", "終了コード"], history.map((h) => [h.commandline, h.output.slice(0, 80), h.exit_code])) : "<p>まだありません。</p>"}`;
  return c.html(exercisePage({ id: ID, mode, title: "サーバー疎通確認ツール", body }), status);
}

/** フォームの host を取り出す（長すぎる入力は切り詰める） */
async function hostOf(c: Context<AppEnv>): Promise<string> {
  const form = await c.req.parseBody();
  return String(form["host"] ?? "").slice(0, 500);
}

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.get("/", (c) => formPage(c, "vuln"));

vuln.post("/ping", async (c) => {
  const host = await hostOf(c);
  const commandline = "ping -c 1 " + host; // [!] 入力をそのままコマンドライン（シェルが解釈する文字列）に連結している
  const result = shell.run(commandline); // [!] 文字列をシェルに渡すので、; && | $( ) などがシェルの文法として効く
  return showResult(c, "vuln", { line: commandline, how: "文字列全体をシェルに渡して実行しました。", result });
});

// 引用符で囲むだけの対策。; や $( ) は防げるが、- で始まる値（引数インジェクション）は防げない
vuln.post("/ping-quoted", async (c) => {
  const host = await hostOf(c);
  const commandline = "ping -c 1 " + escapeShellArg(host); // [!] 引用符で囲んでも、"-" で始まる値はオプションとして解釈される
  const result = shell.run(commandline);
  return showResult(c, "vuln", { line: commandline, how: "引数を引用符で囲み、シェルに渡して実行しました。", result });
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

fixed.get("/", (c) => formPage(c, "fixed"));

// 先頭は英数字（"-" で始まる値を弾く）、全体はホスト名に使える文字だけ
const HOST_RE = /^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

fixed.post("/ping", async (c) => {
  const host = await hostOf(c);
  if (!HOST_RE.test(host)) {
    return formPage(c, "fixed", "ホスト名として使えない文字が含まれています。英数字・ドット・ハイフンだけで、先頭と末尾は英数字にしてください。", 400, host);
  }
  // シェルを通さず、argv（引数の配列）のまま実行する。"--" で以降をオプションとして解釈させない
  const argv = ["ping", "-c", "1", "--", host];
  const result = shell.execFile(argv);
  return showResult(c, "fixed", { line: formatCommand(argv), how: "シェルを通さず、引数の配列のまま実行しました。", result });
});
//#endregion

export const exercise: Exercise = {
  id: ID,
  title: "OSコマンドインジェクション",
  summary: "入力をシェルに渡すコマンドラインへ連結すると、; や $( ) で任意のコマンドを実行される。",
  level: 2,
  book: { chapter: 4, topic: "OSコマンド呼び出しの際に発生する脆弱性" },
  schema: [
    `CREATE TABLE os_command_injection_history (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       mode TEXT NOT NULL,
       commandline TEXT NOT NULL,
       output TEXT NOT NULL,
       exit_code INTEGER NOT NULL,
       created_at TEXT NOT NULL DEFAULT (datetime('now'))
     )`,
  ],
  vuln,
  fixed,
  doc: {
    goals: [
      "文字列を連結してシェルに渡すと、; && | $( ) などのメタ文字が命令として解釈されることを、実際に動かして説明できる",
      "入力の検証（ホスト名の形式）と、シェルを通さない実行（argv 形式）の役割の違いを説明できる",
      "引数インジェクション（- で始まる値）が、引用符で囲んでも防げない理由を説明できる",
    ],
    background: `
OS コマンドインジェクションは、Web アプリが外部のコマンド（ping、画像変換、PDF 生成など）を呼ぶときに、利用者の入力をコマンドラインの文字列に連結することで起きます。コマンドラインを解釈する**シェル**には、命令をつなぐ記号（\`;\` \`&&\` \`||\` \`|\`）や、別のコマンドの結果を埋め込む記号（\`$(...)\` とバッククォート）があります。入力にこれらが混ざると、攻撃者は**サーバー上で任意のコマンド**を実行できます。

被害は、ファイルの読み取り（設定ファイルの秘密）、データの破壊、別サーバーへの侵入の踏み台化など、サーバーの乗っ取りに直結します。Web アプリの脆弱性の中でも、被害が最も大きい部類です。

この演習は、Workers にシェルがないため、**JavaScript で作った擬似シェル**で同じ仕組みを再現しています。コマンドは \`ping\` \`cat\` \`ls\` など数種類で、出力はすべてダミー、ファイルは仮想ファイルツリーです。実際には何も実行されません。
`,
    steps: [
      {
        title: "通常の動作を確認する",
        body: "ホスト名に `localhost` を入れて「疎通確認」を押します。画面に「実行されたコマンドライン」と出力が出ます。次に `nothere.example` で、知らないホストの出力も確かめてください。",
        open: { label: "脆弱版を開く", href: "vuln/?host=localhost" },
      },
      {
        title: "; で別のコマンドをつなぐ",
        body: "ホスト名の後ろに `;` と別のコマンドを書きます。`;` はシェルにとって「ここで命令が終わり。次の命令」という意味です。ping の後に `cat` が実行され、ダミーの設定ファイル（偽のパスワード）が画面に出ます。「実際に実行されたコマンド」の表に 2 行出ていることを確かめてください。",
        payloads: [{ label: "ホスト名", value: "localhost; cat /app/config/secrets.env" }],
        open: {
          label: "入力欄に入れて開く",
          href: "vuln/?host=" + encodeURIComponent("localhost; cat /app/config/secrets.env"),
        },
      },
      {
        title: "&& と | と || を試す",
        body: "`&&` は「前が成功したら次」、`||` は「前が失敗したら次」、`|` は前の出力を次へ渡します。ping が成功するホスト、失敗するホストで結果がどう変わるかを見比べてください。",
        payloads: [
          { label: "&&（ping が成功したときだけ id を実行）", value: "localhost && id" },
          { label: "||（ping が失敗したときだけ id を実行）", value: "nothere.example || id" },
          { label: "|（ping の出力を捨てて ls を表示）", value: "localhost | ls /app" },
        ],
        open: { label: "入力欄に入れて開く", href: "vuln/?host=" + encodeURIComponent("localhost && id") },
      },
      {
        title: "$( ) で別のコマンドの結果を埋め込む",
        body: "`$(コマンド)` は、そのコマンドの出力でその場を置き換えます。`;` や `&&` が使えないよう記号を禁止していても、これで実行できてしまいます。`ping` の引数が `labuser`（`whoami` の結果）になっていることと、**先に `whoami` が実行されている**ことを確かめてください。バッククォートも同じ働きをします。",
        payloads: [
          { label: "ホスト名", value: "$(whoami)" },
          { label: "バッククォート版", value: "`id`" },
        ],
        open: { label: "入力欄に入れて開く", href: "vuln/?host=" + encodeURIComponent("$(whoami)") },
      },
      {
        title: "引数インジェクション（- で始まる値）",
        body: "シェルのメタ文字を使わなくても、ホスト名の位置に**オプション**を入れられます。`-c 5000` を差し込むと、ping の回数が後ろの値で上書きされ、5000 回（約 83 分）の送信になります。実際のサーバーなら、リクエストのたびにプロセスが長時間居座る攻撃になります。",
        payloads: [{ label: "ホスト名", value: "-c 5000 localhost" }],
        open: { label: "入力欄に入れて開く", href: "vuln/?host=" + encodeURIComponent("-c 5000 localhost") },
      },
      {
        title: "引用符で囲む対策を試す",
        body: "一覧ページ下部の「引用符で囲む対策版」で、手順 2 と 4 のペイロードを試します。`;` や `$( )` は、引用符の中ではただの文字になり、防がれます。しかし `-c5000` のように `-` で始まる値は、引用符で囲んでも **ping がオプションとして解釈**してしまいます（エラーメッセージで確認できます）。",
        payloads: [
          { label: "防がれる", value: "localhost; id" },
          { label: "防がれない（ping がオプションと解釈する）", value: "-c5000 localhost" },
        ],
        open: { label: "脆弱版のフォームを開く", href: "vuln/?host=" + encodeURIComponent("localhost; id") },
      },
    ],
    cause: `
原因は、**入力を連結した 1 本の文字列を、シェルにそのまま渡していること**です。ハイライトした行が問題です。

- 1 行目: \`"ping -c 1 " + host\` で、入力がコマンドラインの文法の一部になります。ホスト名のつもりの値が、\`;\` や \`$( )\` を含むとコマンドの区切りや置き換えとして働きます。
- 2 行目: 文字列を渡す先が**シェル**であることが本質です。シェルは受け取った 1 行を自分で解釈し、命令に分解して実行します。ここで入力の中の記号が「命令」に昇格します。
- 3 行目: 引用符で囲む方法です。\`;\` などは防げますが、\`-\` で始まる値は、シェルを通過した後に **ping 自身がオプションとして解釈**します。引用符はシェルに対する防御で、呼ばれたコマンドの引数解釈には効きません。

「入力をデータとして渡したつもり」でも、渡し方が文字列の連結なら、シェルはそれをデータと命令に区別できません。
`,
    fix: `
修正の本命は、**そもそもシェルを呼ばない**ことです。コマンドと引数を配列（argv）で渡して実行すれば（\`execFile\` の形式）、引数に \`;\` や \`$( )\` が入っていても、ただの文字列としてコマンドに渡されます。解釈するシェルがいないので、メタ文字の問題が成立しません。

それに加えて、次の 2 つを入れています。

- **入力の検証**: ホスト名として使える文字（英数字・ドット・ハイフン）だけを許可し、先頭と末尾は英数字にします。先頭の \`-\` を禁止するので、引数インジェクションも防げます。検証はあくまで追加の防御で、シェルを通さないことが本命です。
- **\`--\`（オプションの終わり）**: 引数の配列の中で \`--\` の後ろに置いた値は、コマンドがオプションとして解釈しません。検証を通ったあとの保険です。

どうしてもシェルを通す必要があるときは、\`escapeshellarg\` のように**引数ごとに**引用符で囲む関数を使います。ただし、ホスト名のような値には、上記の検証や \`--\` も併用してください。
`,
    verify: [
      "修正版で手順 2〜5 のペイロードをそのまま入力する。「ホスト名として使えない文字が含まれています」と拒否され、コマンドは実行されない",
      "`localhost` と `example.com` は、修正版でも普通に疎通確認できる",
      "「実行されたコマンドライン」が、`ping -c 1 -- localhost` のように、配列を並べた形になっていることを確かめる",
      "修正版で `nothere.example` を入れる。形式は正しいので実行され、unknown host の出力が出る（検証は「安全な形か」であって、「存在するか」ではない）",
    ],
    beyond: `
**検証だけに頼らない。** ホスト名の正規表現が正しくても、別の場所の見落としで破られる可能性があります。\`;\` を禁止リストで消す方式は、抜け道を塞ぎきれません（\`$( )\`、改行、リダイレクト…）。許可する文字を絞る検証と、シェルを通さない実行を重ねてください。

**シェルを通さない実行でも、引数の解釈は残ります。** argv 形式にしても、コマンド自身が \`-\` で始まる引数をオプションとして扱う問題は残ります。\`curl\`、\`tar\`、\`git\`、\`rsync\` などは、オプション次第でファイルの書き込みや別コマンドの実行までできます。\`--\` を挟めるコマンドでは必ず挟み、挟めないコマンドでは先頭が \`-\` の値を拒否します。

**そもそも外部コマンドを避ける。** 画像のリサイズや PDF 生成、DNS 引きなどは、多くの言語にライブラリがあります。外部コマンドを呼ばなければ、この種の問題は起きません。

**Windows のシェルは別の文法です。** \`&\` や \`|\`、\`^\`、\`%VAR%\` などがメタ文字になります。argv 形式でも、Windows では最終的にコマンドライン文字列に組み立てられるので、言語ごとの仕様を確かめる必要があります。

**最小権限。** 万が一破られても被害が小さくなるよう、アプリを動かすユーザーの権限を絞り、読めるファイル（設定ファイルなど）を減らします。**ディレクトリトラバーサル**の演習で見たように、ファイルを読めるだけでも秘密は漏れます。
`,
    quiz: [
      {
        q: "脆弱版で `localhost; cat /app/config/secrets.env` を入れると、なぜ設定ファイルが表示されるの？",
        a: "アプリが `ping -c 1 localhost; cat /app/config/secrets.env` という 1 本の文字列をシェルに渡すからです。シェルは `;` を命令の区切りとして解釈し、ping の後に cat を実行します。入力がデータではなく命令の一部になっています。",
      },
      {
        q: "`;` と `&` と `|` を入力から取り除けば、OS コマンドインジェクションは防げる？",
        a: "防げません。`$(...)` やバッククォート、改行、リダイレクトなど、命令を差し込む書き方は他にもあります。禁止する記号を列挙する方式は抜け道が残ります。本命は、シェルを通さず引数の配列で実行することです。",
      },
      {
        q: "ホスト名を引用符で囲んでシェルに渡せば十分？ 修正版はなぜ先頭の `-` も禁止しているの？",
        a: "引用符は `;` や `$( )` などシェルのメタ文字には効きますが、`-c5000` のように `-` で始まる値は、シェルを抜けた後で ping 自身がオプションとして解釈します（引数インジェクション）。そのため先頭の `-` を拒否し、さらに argv の中で `--` を挟んでオプションの終わりを明示しています。",
      },
    ],
  },
};
