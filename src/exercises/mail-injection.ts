import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { escapeHtml, exercisePage, table } from "../lab/html";
import { hasControlChars, visualizeCrlfHtml } from "../lab/rawhttp";
import { buildRawMail, composeMail, decodeMimeWords, isValidEmail, parseRawMail, recipientsOf } from "../lab/rawmail";
import type { Exercise } from "../lab/types";

/**
 * メールヘッダインジェクション。
 *
 * 実際にはメールを送らない。「送信するはずだったメール」を、生の文面として画面の送信トレイ（模擬）に出すだけ。
 * 生の文面の組み立てと解析は src/lab/rawmail.ts（純粋な文字列操作）。
 */

const ID = "mail-injection";
type Mode = "vuln" | "fixed";

/** お問い合わせの宛先（固定） */
const ADMIN = "admin@example.com";

interface ContactInput {
  from: string;
  subject: string;
  message: string;
}

type Composed = { ok: true; raw: string } | { ok: false; errors: string[] };

const NOTICE = `<div class="notice"><strong>擬似環境です。</strong> 「送信」を押しても、実際にはメールを送りません。「送信するはずだったメール」の文面を、下の<strong>送信トレイ（模擬）</strong>に表示するだけです。</div>`;

/** 組み立てたメールが持つはずのヘッダー（これ以外が増えていたら注入） */
const EXPECTED = ["from", "to", "subject", "mime-version", "content-type", "content-transfer-encoding"];

/** 送信トレイの 1 通。生の文面と、メールサーバーがそれをどう解釈するかを並べる */
function mailCard(m: { id: number; raw: string; created_at: string }): string {
  const p = parseRawMail(m.raw);
  const names = p.headers.map((h) => h.name.toLowerCase());
  const seen = new Set<string>();
  const rows = p.headers.map((h, i) => {
    const n = h.name.toLowerCase();
    const dup = seen.has(n);
    seen.add(n);
    const ok = EXPECTED.includes(n) && !dup && (n !== "to" || h.value === ADMIN);
    const decoded = decodeMimeWords(h.value);
    return [i + 1, h.name, decoded === h.value ? h.value : `${h.value}  → 「${decoded}」`, ok ? "想定どおり" : "⚠ 想定外（注入された）"];
  });
  const missing = EXPECTED.filter((n) => !names.includes(n));
  const to = recipientsOf(p);
  const extra = to.filter((a) => a !== ADMIN);

  return `<article class="result" id="mail-${m.id}">
<h3>#${m.id} <small>${escapeHtml(m.created_at)}</small></h3>
<h4>生の文面</h4>
<p><mark>␍␊</mark> は CR LF（行の終わり）です。入力に含まれた改行も、システムが入れた改行と区別なく並びます。</p>
<pre class="code"><code>${visualizeCrlfHtml(m.raw)}</code></pre>
<h4>メールサーバーの解釈</h4>
${rows.length ? table(["#", "ヘッダー名", "値", "判定"], rows) : "<p>ヘッダーはありません。</p>"}
${missing.length ? `<div class="notice notice--warn"><strong>⚠ 本来のヘッダー（${escapeHtml(missing.join(", "))}）が見つかりません。</strong> 空行でヘッダーが終わり、残りが本文に回りました。</div>` : ""}
<p>配送先（To / Cc / Bcc）: ${to.map((a) => `<code>${escapeHtml(a)}</code>`).join(" ") || "なし"}</p>
${extra.length ? `<div class="notice notice--warn"><strong>⚠ 意図しない宛先に配送されます:</strong> ${extra.map((a) => `<code>${escapeHtml(a)}</code>`).join(" ")}</div>` : `<p class="ok">配送先は ${ADMIN} だけです。</p>`}
<h4>本文</h4>
<pre class="code"><code>${escapeHtml(p.body) || " "}</code></pre>
</article>`;
}

async function contactPage(c: Context<AppEnv>, mode: Mode) {
  const mails = await c.var.db.all<{ id: number; raw: string; created_at: string }>(
    "SELECT id, raw, created_at FROM mail_injection_outbox WHERE mode = ? ORDER BY id DESC LIMIT 5",
    [mode],
  );
  const prefill = (c.req.query("raw") ?? "").slice(0, 3000);
  const defaultRaw = "from=taro%40example.com&subject=" + encodeURIComponent("お問い合わせ") + "&message=" + encodeURIComponent("製品について質問です。");
  const attacker = `<details${prefill ? " open" : ""}><summary>攻撃者の視点: リクエストを直接書き換える</summary>
<p>ブラウザの 1 行入力欄には改行を入力できません。しかし攻撃者は画面を使わず、HTTP リクエストを直接組み立てて送れます（開発者ツール、curl、プロキシツールなど）。ここではその代わりに、<strong>リクエストボディ（<code>application/x-www-form-urlencoded</code>）を直接編集</strong>して送ります。改行は <code>%0d%0a</code> と書きます。</p>
<form method="post" action="/x/${ID}/${mode}/send-raw">
  <textarea name="raw" rows="4" cols="70">${escapeHtml(prefill || defaultRaw)}</textarea>
  <p><button>この内容でリクエストを送る</button></p>
</form></details>`;
  const body = `<h1>お問い合わせフォーム</h1>
${NOTICE}
<p>入力した内容は、サポート窓口（<code>${ADMIN}</code>）宛てのメールになります。</p>
<form method="post" action="/x/${ID}/${mode}/send">
  <label>返信先のメールアドレス（from） <input name="from" value="taro@example.com" size="40"></label>
  <label>件名（subject） <input name="subject" value="お問い合わせ" size="40"></label>
  <label>内容（message）<br><textarea name="message" rows="4" cols="60">製品について質問です。</textarea></label>
  <p><button>送信</button></p>
</form>
${attacker}
<h2 id="tray">送信トレイ（模擬）</h2>
${mails.length ? mails.map(mailCard).join("") : "<p>まだ何も送信していません。</p>"}`;
  return c.html(exercisePage({ id: ID, mode, title: "お問い合わせフォーム", body }));
}

function rejectPage(c: Context<AppEnv>, mode: Mode, input: ContactInput, errors: string[]) {
  const body = `<h1>400 Bad Request</h1>
${NOTICE}
<div class="notice notice--warn"><strong>送信を受け付けませんでした。</strong></div>
<ul>${errors.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>
<p>受け取った値（改行は記号で表示）:</p>
<pre class="code"><code>from:    ${visualizeCrlfHtml(input.from.slice(0, 200))}
subject: ${visualizeCrlfHtml(input.subject.slice(0, 200))}</code></pre>
<p>メールの文面は組み立てていません。送信トレイにも何も追加されていません。</p>
<p><a href="/x/${ID}/${mode}/">← フォームへ戻る</a></p>`;
  return c.html(exercisePage({ id: ID, mode, title: "400 Bad Request", body }), 400);
}

/** 組み立てに成功したら送信トレイに入れてフォームへ戻す。失敗したら 400 */
async function deliver(c: Context<AppEnv>, mode: Mode, input: ContactInput, composed: Composed) {
  if (!composed.ok) return rejectPage(c, mode, input, composed.errors);
  await c.var.db.run("INSERT INTO mail_injection_outbox (mode, raw) VALUES (?, ?)", [mode, composed.raw]);
  return c.redirect(`/x/${ID}/${mode}/#tray`, 303);
}

/** 両モード共通のルート。compose だけが脆弱版と修正版で違う */
function mountContact(app: Hono<AppEnv>, mode: Mode, compose: (input: ContactInput) => Composed) {
  app.get("/", (c) => contactPage(c, mode));

  app.post("/send", async (c) => {
    const f = await c.req.parseBody();
    const input: ContactInput = {
      from: String(f["from"] ?? "").slice(0, 500),
      subject: String(f["subject"] ?? "").slice(0, 500),
      message: String(f["message"] ?? "").slice(0, 3000),
    };
    return deliver(c, mode, input, compose(input));
  });

  // 攻撃者がリクエストボディを直接書き換えて送る場合の模擬（画面の1行入力欄には改行を入れられないため）
  app.post("/send-raw", async (c) => {
    const f = await c.req.parseBody();
    const q = new URLSearchParams(String(f["raw"] ?? "").slice(0, 3000));
    const input: ContactInput = {
      from: (q.get("from") ?? "").slice(0, 500),
      subject: (q.get("subject") ?? "").slice(0, 500),
      message: (q.get("message") ?? "").slice(0, 3000),
    };
    return deliver(c, mode, input, compose(input));
  });
}

//#region vuln
const vuln = new Hono<AppEnv>();

function composeVuln(input: ContactInput): Composed {
  const headers = [
    "From: " + input.from, // [!] 入力をそのままヘッダー行に連結している（CR/LF を検査しない）
    "To: " + ADMIN,
    "Subject: " + input.subject, // [!] 件名も同じ。改行を入れると新しいヘッダーや本文を作れる
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit",
  ];
  return { ok: true, raw: buildRawMail(headers, input.message) };
}

mountContact(vuln, "vuln", composeVuln);
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();

function composeFixed(input: ContactInput): Composed {
  const errors: string[] = [];
  if (hasControlChars(input.from) || hasControlChars(input.subject)) {
    errors.push("返信先と件名に、改行などの制御文字は使えません。");
  } else {
    if (!isValidEmail(input.from)) errors.push("返信先のメールアドレスの形式が正しくありません。");
    if (input.subject.trim() === "" || input.subject.length > 100) errors.push("件名は 1〜100 文字で入力してください。");
  }
  if (errors.length) return { ok: false, errors };
  try {
    // メール送信ライブラリに任せる: 項目ごとに値を渡すだけで、ヘッダー行は自分で連結しない（宛先は固定）
    return { ok: true, raw: composeMail({ from: input.from, to: ADMIN, subject: input.subject, text: input.message }) };
  } catch (e) {
    return { ok: false, errors: [(e as Error).message] };
  }
}

mountContact(fixed, "fixed", composeFixed);
//#endregion

export const exercise: Exercise = {
  id: ID,
  title: "メールヘッダインジェクション",
  summary: "お問い合わせフォームの件名や返信先に改行を混ぜると、宛先を増やしたり本文を差し替えたりして、迷惑メールの中継に使われる。",
  level: 2,
  book: { chapter: 4, topic: "メール送信の問題" },
  schema: [
    `CREATE TABLE mail_injection_outbox (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       mode TEXT NOT NULL,
       raw TEXT NOT NULL,
       created_at TEXT NOT NULL DEFAULT (datetime('now'))
     )`,
  ],
  vuln,
  fixed,
  doc: {
    goals: [
      "メールのヘッダーが「行を CRLF で区切り、空行のあとが本文」という文字列であることから、改行の注入で宛先の追加や本文の差し替えができる理由を説明できる",
      "Bcc の注入（迷惑メールの中継）、Reply-To の注入（返信の横取り）、空行による本文の差し替えの違いを区別できる",
      "対策は「改行の拒否」「形式の検証」「ライブラリに任せる（連結しない）」「宛先の固定」の重ね合わせだと説明できる",
    ],
    background: `
お問い合わせフォームは、利用者が入力した「返信先のメールアドレス」「件名」「内容」から、サポート窓口宛てのメールを組み立てて送ります。このとき、メールの文面を**文字列の連結**で作っていると問題になります。

メールの文面は、HTTP のレスポンスとよく似た形式です。\`名前: 値\` のヘッダー行を CRLF で並べ、**空行**が来たらヘッダーが終わり、その後ろが本文です。件名や返信先の中に改行が含まれていると、メールサーバーは**入力の途中で行が終わった**と解釈します。攻撃者は、次のことができます。

- **宛先の追加（\`Bcc\` / \`Cc\`）**: 窓口宛てのメールが、攻撃者の指定した大量の宛先にも届きます。このフォームが、迷惑メールを送る**踏み台（中継）**になります。送信元は正規の会社のサーバーなので、受信側のスパム判定をすり抜けやすくなります。
- **返信先の書き換え（\`Reply-To\`）**: 窓口の担当者が返信すると、攻撃者に届きます。
- **本文の差し替え**: 改行を 2 回続けて空行を作ると、そこでヘッダーが終わり、後ろは本文になります。フィッシング文面を、正規のドメインから送れます。

この演習は、実際にはメールを送りません。生の文面を組み立て、**メールサーバーがどう解釈するか**を解析して、送信トレイ（模擬）に並べて見せます。
`,
    steps: [
      {
        title: "通常の送信を確認する",
        body: "フォームをそのまま送信します。送信トレイ（模擬）に、組み立てられた生のメール文面（`␍␊` が行の終わり）と、メールサーバーの解釈（ヘッダーの表、配送先、本文）が出ます。配送先は `admin@example.com` だけです。",
        open: { label: "脆弱版のフォームを開く", href: "vuln/" },
      },
      {
        title: "Bcc を注入して宛先を増やす",
        body: "画面の1行入力欄には改行を入れられませんが、攻撃者はリクエストを直接書き換えられます。「攻撃者の視点」の欄で、件名に `%0d%0a`（改行）と `Bcc:` の行を足して送ってください。生の文面で `Subject` が 2 行に分かれ、解釈結果の表に「⚠ 想定外（注入された）」の `Bcc` が増え、配送先に `victim@example.com` が加わります。",
        payloads: [
          {
            label: "リクエストボディ",
            value: "from=taro%40example.com&subject=hello%0d%0aBcc:%20victim@example.com&message=test",
          },
        ],
        open: {
          label: "入力欄に入れて開く",
          href: "vuln/?raw=" + encodeURIComponent("from=taro%40example.com&subject=hello%0d%0aBcc:%20victim@example.com&message=test"),
        },
      },
      {
        title: "返信先 (from) にも注入できる",
        body: "注入できるのは件名だけではありません。ヘッダーに連結している値なら、どれでも同じです。返信先に `Reply-To:` を足すと、窓口が「返信」を押したときの宛先が攻撃者になります。",
        payloads: [
          {
            label: "リクエストボディ",
            value: "from=taro%40example.com%0d%0aReply-To:%20attacker@example.com&subject=hello&message=test",
          },
        ],
        open: {
          label: "入力欄に入れて開く",
          href:
            "vuln/?raw=" +
            encodeURIComponent("from=taro%40example.com%0d%0aReply-To:%20attacker@example.com&subject=hello&message=test"),
        },
      },
      {
        title: "空行を作って本文を差し替える",
        body: "改行を 2 回続けると、空行の位置でヘッダーが終わり、後ろがすべて本文になります。本来の `MIME-Version` などのヘッダーは、本文の側に回ってしまいます（解釈結果の警告に注目）。窓口宛てのメールの本文を、攻撃者の文面に置き換えられます。",
        payloads: [
          {
            label: "リクエストボディ",
            value:
              "from=taro%40example.com&subject=Re:%20Your%20account%0d%0a%0d%0aYour%20account%20is%20locked.%20Open%20http://evil.example/login&message=ignored",
          },
        ],
        open: {
          label: "入力欄に入れて開く",
          href:
            "vuln/?raw=" +
            encodeURIComponent(
              "from=taro%40example.com&subject=Re:%20Your%20account%0d%0a%0d%0aYour%20account%20is%20locked.%20Open%20http://evil.example/login&message=ignored",
            ),
        },
      },
    ],
    cause: `
原因は、**メールのヘッダー行を文字列の連結で作り、入力に含まれる改行を検査していないこと**です。ハイライトした 2 行が問題です。

- 1 行目: 返信先を \`"From: " + input.from\` と連結しています。入力に CRLF があれば、そこで行が分かれ、続く文字列が新しいヘッダー行になります。
- 2 行目: 件名も同じ作りです。改行を 2 回続けると空行になり、後ろが本文に変わります。

メールのヘッダーでは、改行が**値の終わりと次のヘッダーの始まり**を意味します。入力の中に構造を表す文字が混ざっているのに、区別できないのです。HTTP ヘッダインジェクションと同じ原理です。
`,
    fix: `
修正の要点は、**ヘッダーを自分で連結せず、メール送信の部品に項目ごとの値を渡す**ことです。

- **メール送信ライブラリに任せる**: \`composeMail({ from, to, subject, text })\` のように、項目ごとに値を渡します。部品の側が、値に改行などの制御文字があれば拒否し、件名を必要に応じてエンコード（RFC 2047 の \`=?UTF-8?B?…?=\`）します。実務では、SMTP クライアントのライブラリや、メール送信 API を使います。
- **改行などの制御文字を含む入力を拒否する（400）**: 入力の時点でも弾きます。
- **メールアドレスの形式を検証する**: 簡易な正規表現でも、空白・カンマ・改行・括弧を含む値を通さない効果があります。
- **宛先を固定する**: \`To\` は利用者の入力から作らず、定数にします。

「ライブラリに任せる」が本命で、入力の拒否と形式の検証は、それを補う重ね合わせです。
`,
    verify: [
      "修正版の「攻撃者の視点」の欄に、手順 2〜4 のリクエストボディをそのまま貼って送る。400 Bad Request になり、送信トレイには何も増えない",
      "修正版のフォームをそのまま送信する。通常の内容は送信トレイに出て、件名の日本語が `=?UTF-8?B?…?=` の形にエンコードされ、解釈結果で「→ 「お問い合わせ」」と読めること",
      "返信先に `not-an-address` を入れて送信する。形式エラーで 400 になる",
      "どの場合も、配送先が `admin@example.com` だけであることを確かめる",
    ],
    beyond: `
**本物のメール送信でも同じ。** 古い言語のメール送信関数には、追加ヘッダーの文字列をそのまま受け取るものがあります。そこに入力を連結すると、この演習と同じことが起きます。現代のメール送信ライブラリや API は、項目ごとに値を受け取り、改行を拒否します。

**メールアドレスの検証は意外に難しい。** 仕様上は、引用符で囲んだ形式（\`"a b"@example.com\`）など、特殊な書き方が有効です。簡易な検証は「仕様より厳しく」しておくのが安全です。また、言語によっては、正規表現の \`$\` が**末尾の改行の手前にも一致**します（PHP や Perl など）。\`foo@example.com\\n\` が検査を通り抜ける原因になります。この演習の検証は JavaScript なので \`$\` は文字列の最後だけに一致しますが、他の言語では \`\\z\` や専用のフラグを使います。

**送信元 (From) を利用者の入力にしない。** 実務では、\`From\` はサービス自身のアドレスに固定し、利用者のアドレスは \`Reply-To\` に入れます。送信元ドメインの認証（SPF / DKIM / DMARC）が通らなくなる問題と、なりすまし防止の両方に効きます。

**踏み台にされない設計。** 宛先の固定に加えて、送信回数の制限（レート制限）、ボット対策、送信ログの監視を入れます。宛先を利用者に決めさせる機能（友達に紹介、など）は、特に慎重に設計します。

**別のプロトコルへの広がり。** SMTP を直接話す実装では、本文の中の「単独の \`.\` の行」がメッセージの終わりを意味するなど、同じ種類の注入があります。**HTTPヘッダインジェクション**の演習も、原理は同じです。
`,
    quiz: [
      {
        q: "件名に `hello%0d%0aBcc: victim@example.com` を入れると、なぜ victim にメールが届くの？",
        a: "デコードされた件名に CRLF が含まれるため、`Subject: hello` の行がそこで終わり、`Bcc: victim@example.com` が新しいヘッダー行になるからです。メールサーバーはヘッダーの `Bcc` を見て、配送先を増やします。サーバーが送信元になるので、迷惑メールの踏み台になります。",
      },
      {
        q: "件名の改行だけを防げば十分？",
        a: "足りません。ヘッダーに連結している値は、返信先 (`From`) など、どれも同じ危険があります。個別に対策するのではなく、ヘッダーを自分で連結せず、項目ごとに値を渡す送信ライブラリを使うのが本命です。入力の拒否や形式の検証は、その上の保険です。",
      },
      {
        q: "宛先 (`To`) を定数にしているのに、迷惑メールの踏み台にされるのはなぜ？",
        a: "`To` が固定でも、`Bcc` や `Cc` の行を注入されれば宛先が増えるからです。宛先を固定しても、他の入力から改行が入れば、ヘッダーを追加されます。注入そのものを防ぐ必要があります。",
      },
    ],
  },
};
