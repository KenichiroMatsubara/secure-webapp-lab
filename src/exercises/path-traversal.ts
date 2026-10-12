import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import type { Exercise } from "../lab/types";
import { labVfs, normalizePath, type ReadResult } from "../lab/vfs";

/**
 * ディレクトリトラバーサル。
 *
 * Workers にはファイルシステムがないので、メモリ上の仮想ファイルシステム（src/lab/vfs.ts）で再現する。
 * 実際のファイルは一切読まない。中身はすべてダミー。
 */

const ID = "path-traversal";
type Mode = "vuln" | "fixed";

/** 資料ダウンロード機能が公開してよい基準ディレクトリ */
const BASE = "/app/public/docs";

interface View {
  route: "download" | "download-naive";
  file: string;
  /** 入力から読み取りまでの経過（段階の名前, 値） */
  trace: [string, string][];
  /** 読み取ったパス（拒否したときは空） */
  resolved: string;
  result: ReadResult | null;
  /** 拒否した理由（修正版） */
  denied: string | null;
  status?: 200 | 400 | 404;
}

const NOTICE = `<div class="notice"><strong>擬似環境です。</strong> Cloudflare Workers にはファイルシステムがないため、メモリ上の仮想ファイルツリーを読んでいます。実際のファイルは一切読みません（中身はすべてダミーです）。</div>`;

/** 基準ディレクトリの内側か（画面に「範囲外に出た」と示すための表示用。防御ではない） */
const isInside = (p: string) => p === BASE || p.startsWith(BASE + "/");

/** アクセスログに残し、結果ページを返す */
async function showFile(c: Context<AppEnv>, mode: Mode, v: View) {
  const outside = !!v.resolved && !isInside(v.resolved);
  const outcome = v.denied
    ? `拒否: ${v.denied}`
    : v.result?.ok
      ? outside
        ? "読めた（基準ディレクトリの外）"
        : "読めた"
      : (v.result?.error.split(":")[0] ?? "-");
  await c.var.db.run(
    "INSERT INTO path_traversal_log (mode, route, requested, resolved, outcome) VALUES (?, ?, ?, ?, ?)",
    [mode, v.route, v.file.slice(0, 200), v.resolved, outcome],
  );

  let result: string;
  if (v.denied) {
    result = `<p class="ng">拒否しました: ${escapeHtml(v.denied)}</p>`;
  } else if (v.result?.ok) {
    result =
      (outside
        ? `<div class="notice notice--warn"><strong>⚠ 基準ディレクトリ <code>${BASE}</code> の外にあるファイルが読めてしまいました。</strong></div>`
        : `<p class="ok">基準ディレクトリの中のファイルです。</p>`) +
      `<pre class="code"><code>${escapeHtml(v.result.content)}</code></pre>`;
  } else {
    result = `<p class="ng">読めませんでした: ${escapeHtml(v.result?.error ?? "")}</p>`;
  }

  const body = `<h1>資料ダウンロード</h1>
${NOTICE}
<h2>パスが決まるまで</h2>
${table(["段階", "値"], v.trace)}
<h2>結果</h2>
<div class="result">${result}</div>
<p><a href="/x/${ID}/${mode}/">← 資料の一覧へ</a></p>`;
  return c.html(exercisePage({ id: ID, mode, title: "資料ダウンロード", body }), v.status ?? 200);
}

/** 資料の一覧とアクセスログ */
async function indexPage(c: Context<AppEnv>, mode: Mode) {
  const names = labVfs.list(BASE) ?? [];
  const links = names
    .map((n) => `<li><a href="/x/${ID}/${mode}/download?file=${encodeURIComponent(n)}">${escapeHtml(n)}</a></li>`)
    .join("");
  const logs = await c.var.db.all<{ route: string; requested: string; resolved: string; outcome: string }>(
    "SELECT route, requested, resolved, outcome FROM path_traversal_log WHERE mode = ? ORDER BY id DESC LIMIT 8",
    [mode],
  );
  const naive =
    mode === "vuln"
      ? `<h2>簡易対策版（<code>../</code> を取り除く）</h2>
<p>こちらは「<code>../</code> という文字列を削除してから連結する」だけの対策を入れた別ルートです。本当に防げているか試してください。</p>
<form method="get" action="/x/${ID}/vuln/download-naive">
  <label>ファイル名 <input name="file" value="readme.txt" size="40"></label> <button>開く</button>
</form>`
      : "";
  const body = `<h1>社内資料ポータル</h1>
${NOTICE}
<p>公開してよい資料は基準ディレクトリ <code>${BASE}</code> の下にあります。</p>
<h2>資料の一覧</h2>
<ul>${links}</ul>
<form method="get" action="/x/${ID}/${mode}/download">
  <label>ファイル名を直接指定 <input name="file" value="readme.txt" size="40"></label> <button>開く</button>
</form>
${naive}
<h2>サーバーのアクセスログ</h2>
${logs.length ? table(["ルート", "リクエストの file", "読もうとしたパス", "結果"], logs.map((l) => [l.route, l.requested, l.resolved || "-", l.outcome])) : "<p>まだありません。</p>"}`;
  return c.html(exercisePage({ id: ID, mode, title: "社内資料ポータル", body }));
}

//#region vuln
const vuln = new Hono<AppEnv>();

vuln.get("/", (c) => indexPage(c, "vuln"));

vuln.get("/download", (c) => {
  const file = c.req.query("file") ?? "";
  const joined = BASE + "/" + file; // [!] 入力をそのままパスに連結している（".." も "/" もそのまま通る）
  const resolved = normalizePath(joined); // OS が ".." を解決するのと同じ処理。連結した後に解決されるので外へ出られる
  const result = labVfs.read(resolved); // [!] 解決後のパスが基準ディレクトリの中かを確かめずに読んでいる
  return showFile(c, "vuln", {
    route: "download",
    file,
    trace: [
      ["リクエストの file", file],
      ['基準 + "/" + file', joined],
      ["OS が解決したパス", resolved],
    ],
    resolved,
    result,
    denied: null,
  });
});

// 「../ を取り除く」だけの簡易対策。1 回しか取り除かないので、取り除いた結果に ../ が再び現れる入力で破られる
vuln.get("/download-naive", (c) => {
  const file = c.req.query("file") ?? "";
  const cleaned = file.replaceAll("../", ""); // [!] 取り除いた後に "../" が残る入力（....//）を想定していない
  const joined = BASE + "/" + cleaned;
  const resolved = normalizePath(joined);
  const result = labVfs.read(resolved);
  return showFile(c, "vuln", {
    route: "download-naive",
    file,
    trace: [
      ["リクエストの file", file],
      ["../ を取り除いた後", cleaned],
      ['基準 + "/" + 取り除いた後', joined],
      ["OS が解決したパス", resolved],
    ],
    resolved,
    result,
    denied: null,
  });
});
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

fixed.get("/", (c) => indexPage(c, "fixed"));

// 本命: 一覧に出しているファイル名だけを許可する
const ALLOWED = new Set(labVfs.list(BASE) ?? []);

type Check = { ok: true; path: string } | { ok: false; reason: string; status: 400 | 404 };

function check(file: string): Check {
  if (file.includes("\0")) return { ok: false, reason: "NUL バイトは使えません", status: 400 };
  if (file.includes("\\")) return { ok: false, reason: "バックスラッシュは使えません", status: 400 };
  if (file.includes("%")) return { ok: false, reason: "% を含む名前は使えません（二重エンコードの疑い）", status: 400 };
  if (!ALLOWED.has(file)) return { ok: false, reason: "公開資料の一覧にないファイルです", status: 404 };
  // 補助: 正規化した後のパスが、基準ディレクトリ + "/" で始まることを確かめる
  const path = normalizePath(BASE + "/" + file);
  if (!path.startsWith(BASE + "/")) return { ok: false, reason: "基準ディレクトリの外です", status: 400 };
  return { ok: true, path };
}

fixed.get("/download", (c) => {
  const file = c.req.query("file") ?? "";
  const checked = check(file);
  if (!checked.ok) {
    return showFile(c, "fixed", {
      route: "download",
      file,
      trace: [
        ["リクエストの file", file],
        ["検査", "拒否"],
      ],
      resolved: "",
      result: null,
      denied: checked.reason,
      status: checked.status,
    });
  }
  const result = labVfs.read(checked.path);
  return showFile(c, "fixed", {
    route: "download",
    file,
    trace: [
      ["リクエストの file", file],
      ["許可リスト", "一覧にあるファイル名 → 通過"],
      ["正規化後のパス", checked.path],
      ["基準ディレクトリの中か", "はい → 通過"],
    ],
    resolved: checked.path,
    result,
    denied: null,
  });
});
//#endregion

export const exercise: Exercise = {
  id: ID,
  title: "ディレクトリトラバーサル",
  summary: "ファイル名を受け取って読み出す機能に ../ を渡すと、公開していないファイル（設定ファイルなど）まで読まれる。",
  level: 1,
  book: { chapter: 4, topic: "ファイルアクセスにまつわる問題" },
  schema: [
    `CREATE TABLE path_traversal_log (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       mode TEXT NOT NULL,
       route TEXT NOT NULL,
       requested TEXT NOT NULL,
       resolved TEXT NOT NULL,
       outcome TEXT NOT NULL,
       created_at TEXT NOT NULL DEFAULT (datetime('now'))
     )`,
  ],
  vuln,
  fixed,
  doc: {
    goals: [
      "ファイル名の入力がパスに連結され、OS が .. を解決することで、基準ディレクトリの外へ出られる仕組みを説明できる",
      "「../ を取り除く」型の簡易対策が破られる理由を、実際に ....// で試して説明できる",
      "対策の本命は「許可リスト（そもそもパスを入力にしない）」で、正規化後の範囲検査は補助だと位置づけられる",
    ],
    background: `
ディレクトリトラバーサルは、利用者が指定したファイル名を使ってサーバー上のファイルを読み書きする機能で、**意図した範囲（基準ディレクトリ）の外のファイル**に到達されてしまう脆弱性です。資料のダウンロード、画像の表示、テンプレートの読み込み、ログの閲覧などで起きやすい問題です。

仕組みは単純です。アプリは \`基準ディレクトリ + "/" + 利用者の入力\` でパスを作り、そのままファイルを開きます。ところが OS は、パスの中の \`..\`（ひとつ上のディレクトリ）を解釈するので、\`../../\` を続ければ基準ディレクトリの外へ上っていけます。

読まれるのは、設定ファイル（DB のパスワード）、ソースコード、システムのファイルなど、公開するつもりのないものです。ここで読まれた秘密が、次の攻撃の足がかりになります。

この演習は、Workers にファイルシステムがないため、**メモリ上の仮想ファイルツリー**で同じ現象を再現しています。ファイルの中身はすべてダミーです。
`,
    steps: [
      {
        title: "通常の動作を確認する",
        body: "資料の一覧から `readme.txt` を開きます。画面の表に、入力から OS が解決したパスまでが出ます。基準ディレクトリの中のファイルが読めているだけで、ここまでは正常です。",
        open: { label: "readme.txt を開く", href: "vuln/download?file=readme.txt" },
      },
      {
        title: "../ で基準ディレクトリの外へ出る",
        body: "`..` はひとつ上のディレクトリです。`docs` から `..` で `public` に上がり、`images/logo.txt` を読みます。まだ公開用の無害なファイルですが、**基準ディレクトリの外**が読めた時点で、トラバーサルが成立しています。",
        payloads: [{ label: "file", value: "../images/logo.txt" }],
        open: {
          label: "このペイロードで試す",
          href: "vuln/download?file=" + encodeURIComponent("../images/logo.txt"),
        },
      },
      {
        title: "設定ファイルを読む",
        body: "もう一段上がって `config` を指定します。ダミーのパスワードや API キーが画面に出れば、公開していない秘密を読まれたということです。「OS が解決したパス」の行を確かめてください。",
        payloads: [{ label: "file", value: "../../config/secrets.env" }],
        open: {
          label: "このペイロードで試す",
          href: "vuln/download?file=" + encodeURIComponent("../../config/secrets.env"),
        },
      },
      {
        title: "ルートまで上ってシステムのファイルを読む",
        body: "`..` を多めに書いても、ルートより上には行けないので、深さを正確に数えなくても届きます。攻撃者は「多すぎるくらい」の `../` を付けるのが普通です。",
        payloads: [
          { label: "file", value: "../../../etc/passwd" },
          { label: "file（多めに上る）", value: "../../../../../../../../etc/passwd" },
        ],
        open: {
          label: "このペイロードで試す",
          href: "vuln/download?file=" + encodeURIComponent("../../../../../../../../etc/passwd"),
        },
      },
      {
        title: "簡易対策（../ を取り除く）を破る",
        body: "一覧ページの「簡易対策版」は、入力から `../` を削除してから連結します。まず `../../config/secrets.env` を試すと、`../` が消えて失敗します。次に下の入力を試してください。`....//` は、**真ん中の `../` を 1 回削除した結果が、また `../` になります**。",
        payloads: [
          { label: "file（普通の ../ は消される）", value: "../../config/secrets.env" },
          { label: "file（破る入力）", value: "....//....//config/secrets.env" },
        ],
        open: {
          label: "簡易対策版を破る",
          href: "vuln/download-naive?file=" + encodeURIComponent("....//....//config/secrets.env"),
        },
      },
    ],
    cause: `
原因は、**入力をそのままパスに連結し、OS が解決した後のパスが基準ディレクトリの中にあるかを確かめていない**ことです。ハイライトした 3 行が問題です。

- 1 行目（\`joined\`）: \`BASE + "/" + file\` で、入力に含まれる \`..\` や \`/\` がそのままパスの構造になります。その次の \`normalizePath\` は OS が \`..\` を解決する動きの再現で、アプリが書くコードではありません。連結した後に解決されるので、基準ディレクトリの外のパスが完成します。
- 2 行目（\`labVfs.read\`）: 解決後のパスを検査せずに読んでいます。
- 3 行目（\`replaceAll("../", "")\`）: 簡易対策版です。危険な文字列を**見つけて消す**方式なので、消した結果に危険な文字列が再び現れる入力（\`....//\`）が作れます。\`..\\\` や URL エンコード（\`%2e%2e%2f\`）など、書き方の違いも無数にあります。「悪いものを列挙して消す」やり方は、抜け道を塞ぎきれません。
`,
    fix: `
修正の本命は**許可リスト**です。一覧に出している資料のファイル名（\`readme.txt\` と \`guide.txt\`）だけを受け付け、それ以外は拒否します。そもそもパスの構造を入力に持ち込ませないので、\`..\` の書き方をどれだけ工夫しても通りません。

保険として、次も入れています。

- 連結して**正規化した後**のパスが \`基準ディレクトリ + "/"\` で始まることを確かめる（末尾の \`/\` を付けるのは、\`/app/public/docs-private\` のような名前の似た別ディレクトリを通さないため）
- バックスラッシュ、NUL バイト、\`%\` を含む名前を拒否する

検査は必ず**正規化した後**に行います。先に検査してから正規化やデコードをすると、検査をすり抜ける入力が作れます。
`,
    verify: [
      "修正版で `../../config/secrets.env` を試す。「公開資料の一覧にないファイルです」と拒否され、404 になる",
      "`....//....//config/secrets.env` や `/etc/passwd`、`..%5c..%5cconfig` など、手順 2〜5 のペイロードをすべて試して拒否されることを確かめる",
      "一覧にある `readme.txt` と `guide.txt` は、修正版でも普通に開ける",
      "アクセスログの表で、拒否された試行も記録されていること（結果が「拒否: …」、読もうとしたパスが「-」になる）を確かめる",
    ],
    beyond: `
**エンコードの罠。** Web フレームワークは URL エンコードを一度デコードしてから渡します。\`%2e%2e%2f\` が \`../\` になるので、デコード**前**の文字列を検査しても意味がありません。デコードを二重に行う実装では、\`%252e%252e%252f\` のような二重エンコードも通ってしまいます。検査は、最後にパスとして使う直前の値に対して行います。

**区切り文字は OS ごとに違います。** Windows では \`..\\\` も有効で、ドライブ文字（\`C:\\\`）や予約名もあります。この仮想ファイルツリーは POSIX 風なので \`\\\` を区切りとして扱いませんが、実際のサーバーが Windows なら \`..\\\` で破られます。修正版が \`\\\` を拒否しているのはそのためです。

**NUL バイト。** 古い言語や実装では、パスの途中の NUL（\`%00\`）で文字列が打ち切られます。「拡張子が .txt なら読んでよい」という検査を、\`../../etc/passwd%00.txt\` が通り抜けた事例があります。

**シンボリックリンク。** 正規化は文字列だけを見るので、基準ディレクトリの中にあるリンクが外を指していても気づけません。重要な場面では、実体のパス（realpath）を求めてから検査します。

**設計で避ける。** いちばん堅いのは、利用者にファイル名を決めさせないことです。アップロードされたファイルは、DB の ID やオブジェクトストレージのキー（ランダムな名前）で管理し、ID から保存先を引きます。元のファイル名は表示用に別の列へ保存するだけにします。

**関連。** 同じ「入力をパスやコマンドに混ぜる」問題は、OS コマンドインジェクションの演習で \`cat\` を通じて体験できます。アプリの実行ユーザーに最小限の権限しか与えないことも、読まれる範囲を狭める保険になります。
`,
    quiz: [
      {
        q: "脆弱版で `file=../../config/secrets.env` を渡すと、なぜ基準ディレクトリの外が読めるの？",
        a: "`基準 + \"/\" + 入力` で作ったパスは `/app/public/docs/../../config/secrets.env` になり、OS が `..` を解決して `/app/config/secrets.env` になります。アプリは解決後のパスが基準ディレクトリの中かを確かめていないので、そのまま読みます。",
      },
      {
        q: "「`../` を空文字に置き換える」対策が不十分なのはなぜ？ 修正版はどう違う？",
        a: "置き換えは 1 回しか行われず、`....//` のように置き換えた結果が `../` に戻る入力で破られます。`..\\` や `%2e%2e%2f` など書き方の違いも無数にあります。修正版は危険な文字列を探して消すのではなく、**許可した名前だけを通す**方式なので、書き方を工夫する余地がありません。",
      },
      {
        q: "正規化後のパスの検査で `startsWith(BASE)` とだけ書くと、どんな問題が起きる？",
        a: "`BASE` が `/app/public/docs` のとき、名前が似た `/app/public/docs-private/…` も `startsWith` を満たして通ってしまいます。`BASE + \"/\"` で比較すれば、別ディレクトリは通りません。そもそも本命は許可リストで、この検査は保険です。",
      },
    ],
  },
};
