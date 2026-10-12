# 演習の書き方（AUTHORING）

新しい演習を足す、または既存の演習を直すときのガイドです。見本は [`src/exercises/xss-reflected.ts`](../src/exercises/xss-reflected.ts) と [`test/xss-reflected.test.ts`](../test/xss-reflected.test.ts) です。**まずこの 2 つを読んでください。**

## 1. 全体像

```
src/index.ts            Hono アプリ。ガード → Access検証 → 学習者DB の順にミドルウェアを通す
src/lab/guard.ts        外側から安全網をかける（CSP・リダイレクト制限・noindex）
src/lab/access.ts       Cloudflare Access の JWT 検証（アプリ内で唯一の外部通信）
src/lab/learner.ts      学習者の特定と、その人専用DB（Durable Object）の割り当て
src/lab/db.ts           学習者ごとの SQLite（Durable Object）
src/lab/shell.ts        ホーム・解説ページ・リセット・進捗
src/lab/registry.ts     演習の一覧（学習順）
src/exercises/<id>.ts   1演習＝1ファイル（脆弱版・修正版・攻撃者ページ・解説）
src/generated/          scripts/gen-sources.ts が作るソース抜粋（編集しない・gitignore）
test/<id>.test.ts       攻撃が脆弱版で成立し、修正版で成立しないことの検証
```

URL は次のとおりです。

| URL | 中身 |
|---|---|
| `/x/<id>` | 解説ページ（シェルが `doc` とソース抜粋から自動生成） |
| `/x/<id>/vuln/…` | 脆弱版（演習ファイルの `vuln`） |
| `/x/<id>/fixed/…` | 修正版（演習ファイルの `fixed`） |
| `/attacker/<id>/…` | 攻撃者サイト役のページ（演習ファイルの `attacker`。CSP sandbox で別オリジン扱い） |

## 2. 演習ファイルの形

```ts
//#region vuln
const vuln = new Hono<AppEnv>();
…                                   // 脆弱版のコードだけ
//#endregion

//#region fixed
const fixed = new Hono<AppEnv>();
…                                   // 修正版のコードだけ
//#endregion

const attacker = new Hono<AppEnv>(); // 任意
…
export const exercise: Exercise = { id, title, summary, level, book, schema, seed, vuln, fixed, attacker, doc };
```

- `//#region vuln` と `//#region fixed` の**中身がそのまま**解説ページの「原因のコード」「修正の差分」になります（`npm run gen` が抜き出します）。同名の region が複数あれば連結されます。
- region の中には、**脆弱版・修正版それぞれに固有のコードだけ**を書きます。共通の部品（DB の初期化、画面の外枠など）は region の外に出すと、差分が「本当に直した箇所」だけになります。
- 脆弱な行には**行末に `// [!] 何が問題か`** を付けます（解説ページで黄色くなります）。HTML を組み立てるテンプレートリテラルの内側にはコメントを書けないので、**脆弱な埋め込みは `const` の 1 行に切り出し、その行末にコメントを付けます**（ページのソースにコメントが漏れません）。
- 修正版は、脆弱版と**できるだけ同じ構造・同じ変数名**にします。差分が小さいほど「どこを直せば防げるか」が伝わります。
- `id` は `src/lab/registry.ts` の登録と、ファイル名、URL に使うので、小文字とハイフンだけにします。

## 3. データベース

学習者 1 人につき 1 つの SQLite が割り当てられ、`c.var.db` で使います。

```ts
const rows = await c.var.db.all<{ id: number; name: string }>("SELECT id, name FROM sqli_users WHERE id = ?", [id]);
const one  = await c.var.db.first("SELECT … WHERE … = ?", [x]);   // 見つからなければ null
const { changes } = await c.var.db.run("UPDATE … SET … = ? WHERE …", [v]);
```

- 表は演習の `schema`（`CREATE TABLE …`）と `seed`（`INSERT …`）に書きます。**表名は演習 ID のハイフンをアンダースコアにしたものを接頭辞にします**（`sqli_users`、`xss_stored_posts` など）。他の演習の表を触りません。
- スキーマ・初期データを変えたら、次回アクセス時に学習者のDBが自動で作り直されます（データは使い捨て）。
- 脆弱版の SQL インジェクション演習では、あえて文字列連結で SQL を組み立てます。**学習者のDBの中だけに閉じる**ので安全です。
- パスワードのハッシュなど非同期の計算が必要な初期データは、`seed` ではなく、最初のアクセス時に「表が空なら投入する」関数で入れます。

## 4. ページとヘルパー（`src/lab/html.ts`）

- `exercisePage({ id, mode, title, body, head })` … バナー付きの外枠。`<head>` に `<script src>` を足せます。
- `escapeHtml(s)` … **修正版で使う**。脆弱版ではわざと通さない場合がある。
- `table(headers, rows)` … 値を常にエスケープして表にする（XSS 以外の演習で、結果を安全に見せるために使う）。
- 脆弱版・修正版のページは `c.html(exercisePage(…))` で返します。ブラウザ側の JavaScript は、(a) 脆弱版はページ内の `<script>`（CSP が `'unsafe-inline'` を許す）、(b) 修正版で CSP を厳しくした場合は `fixed.get("/app.js", …)` のような**同一オリジンの外部ファイル**で配ります。

## 5. Cookie

- Cookie 名は演習ごとに変えます（例: `csrf_vuln_sid`、`csrf_fixed_sid`）。`lab_id` と `CF_Authorization` は予約です。
- 脆弱版の Cookie は、**脆弱性の説明に必要な属性だけ**を外します（例: HttpOnly なし）。それ以外のことで壊れないよう、`path` は演習の URL（`/x/<id>/vuln`）に絞ってください。
- クロスサイトの攻撃を再現する演習（CSRF、クリックジャッキング）では、脆弱版の Cookie を `SameSite=None; Secure` にします。`c.var.crossSiteCookies` が true のとき（https または localhost）だけ使えます。false のときは `Lax` にフォールバックし、攻撃が再現できない旨を画面に出します。
- 修正版は `HttpOnly; SameSite=Lax`（または `Strict`）を基本にします。

## 6. 攻撃者サイト役（`attacker`）

`/attacker/<id>/` に載せるページです。ガードが `Content-Security-Policy: sandbox allow-forms allow-scripts …`（`allow-same-origin` なし）を付けるため、**ブラウザからは別オリジン（`Origin: null`）扱い**になります。CSRF やクリックジャッキングの「別サイトから送る」を、1 つのWorkerだけで再現するための仕組みです。

- 攻撃者ページは「ここは攻撃者側を演じる模擬ページです」と明示します。
- 攻撃者サイトの「受け皿」（盗まれた情報を記録するエンドポイントなど）は、同一オリジンの表として自分のDBに記録します。**外部へは何も送りません。**
- 攻撃の実行は、必ず**学習者が押すボタン**にします（読み込んだだけで自動送信しない）。

## 7. 安全のルール（破ると PR を通しません）

1. **外部へ通信しない。** サーバー側コードに `fetch(` / `WebSocket` / `cloudflare:sockets` などを書かない（`npm run check:egress` が検査します）。ブラウザ側で動く文字列の中の `fetch('/同一オリジン')` は構いません。
2. **擬似環境は純粋に仮想にする。** OS コマンド・ファイル・メール送信を再現する演習は、メモリ上のデータと自作のインタプリタだけで動かし、実際には何も実行・送信しません。
3. **ダミーデータだけ。** 実在の人物・企業・ドメインを使わない。ドメインは `*.example` / `example.com` / `*.test` などの予約ドメイン、メールは `@example.com` を使う。
4. 脆弱版を**ガードを回避する形で**作らない（`guard.ts` が付ける CSP やリダイレクト制限に頼らず、また破らない）。
5. 学習者以外のデータに影響する処理（グローバルな状態）を作らない。状態は必ず `c.var.db` に置く。

## 8. 解説（`doc`）の書き方

- すべて**日本語・自分の言葉**で書きます。書籍の本文・図・コードの転載や、近い言い換えはしません。書籍との対応は `book: { chapter, topic }`（章とトピック名）だけで示します。
- `steps`（攻撃手順）は、**コピーして貼るだけで再現できる**ペイロードを `payloads` で用意し、`open` で脆弱版へのリンクを付けます。1 ステップ 1 学び。
- `cause` は「どの行が、なぜ問題か」を `[!]` の行と対応づけて書きます。
- `fix` は「何をどう直したか」と「なぜそれで防げるか」を書きます。対策が複数あるなら、本命と保険を区別します。
- `verify` は、修正版で**同じ攻撃が止まる**ことを確かめる具体的な操作です。
- `beyond` は、残るリスク、実務での注意、関連する他の演習への誘導です。
- `quiz` は 2〜3 問。答えは短く、理由を含めます。
- 文章の簡易マークアップは `md()`（空行で段落、`- ` で箇条書き、`1. ` で番号付き、`` `code` ``、`**太字**`）。HTML は書けません（すべてエスケープされます）。

## 9. テスト

見本: `test/xss-reflected.test.ts`。**最低限、次を検証します。**

1. 脆弱版で攻撃が成立する（レスポンス・DBの状態・リダイレクト先などで確認する）。
2. 修正版で**同じ攻撃が成立しない**（そして正常系の操作は引き続き動く）。
3. 学習者ごとにデータが分かれている（別の `new Browser()` から見えない）。

`test/helpers.ts` の `Browser` は Cookie を覚える簡易ブラウザです（Cookie の Path は無視します）。`b.post()` は `Sec-Fetch-Site: same-origin` を付けます。クロスサイトのリクエストを模すときは、`b.request(path, { method: "POST", headers: { "Sec-Fetch-Site": "cross-site", Origin: "null" }, … })` のように自分で指定します。

## 10. ハマりどころ

- **ハンドラーから生の `new Response()` を返さない。** Hono の `c.html()` / `c.body()` / `c.json()` / `c.redirect()` で返します。生の `Response` を返すと、学習者の特定ミドルウェアが付けた `lab_id` の `Set-Cookie` が捨てられ、最初のリクエストが POST のとき学習者のDBが毎回変わってしまいます。
- **ガードの `Referrer-Policy` は `same-origin`。** `no-referrer` にすると、ブラウザが同一オリジンの POST にも `Origin: null` を付け、Origin 検証（CSRF の修正版）が正当なフォーム送信まで拒否します。テストの `Browser` はこの挙動を再現しないので、**Origin を検証する演習は必ず実ブラウザで通しで確かめてください。**
- **ブラウザの入力欄からは CR/LF を送れません。** 改行注入の演習は、URL を直接書き換える手順にするか、リクエストボディを編集する欄を用意します。
- **`.d.ts` は型エラーが隠れます**（`skipLibCheck`）。テスト用の型の拡張は `test/env-types.ts` のように通常の `.ts` に置きます。
- 解説ページのソース抜粋は `npm run gen` で作ります。`npm run dev` は演習ファイルの変更を検知して自動で再生成します。

## 11. 完了の定義

```bash
npm run typecheck   # 型エラーなし（gen → src / scripts / test）
npm test            # すべて成功
npm run check:egress
```

加えて、`npm run dev` で実際のブラウザから通しで触り、解説ページの手順どおりに攻撃でき、修正版で止まることを確かめます。
