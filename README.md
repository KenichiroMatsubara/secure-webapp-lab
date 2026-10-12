# 安全なWebアプリの作り方ラボ

徳丸 浩 著『体系的に学ぶ 安全なWebアプリケーションの作り方（第2版）』の**第4章・第5章**を読みながら、手を動かして学ぶための**個人学習用の副教材**です。

**わざと脆弱にしたアプリを攻撃し → 原因のコードを読み → 修正版で同じ攻撃が止まるのを確かめる**、という流れを 15 の演習で体験できます。Cloudflare Workers + Hono で動き、ローカルでも `npm run dev` ですぐ試せます。

> ⚠️ **脆弱なコードを含みます。** ここに書かれた「脆弱版」のコードを、実際のアプリに流用しないでください。公開するときは必ず [Cloudflare Access で入口を閉じ](docs/DEPLOY.md)てください。安全設計は [docs/SAFETY.md](docs/SAFETY.md) にあります。

> 本リポジトリは書籍の副教材として作った**独自の演習**で、書籍の本文・コード・図は含みません。著者・出版社とは無関係です。各演習には「本書のどの章に対応するか」だけを記してあるので、詳しい説明は書籍で読んでください。

## 学び方

各演習の解説ページ（`/x/<id>`）は、次の順に進みます。

1. **学習目標** と **どんな脆弱性か**
2. **攻撃してみる** … コピーして貼るだけのペイロード付きの手順で、脆弱版を攻撃する
3. **原因のコード** … 問題の行がハイライトされる
4. **修正の差分** … 脆弱版 → 修正版の差分
5. **修正版で確かめる** … 同じ攻撃が止まることを確認する
6. **残るリスクと多層防御**、**理解度チェック**

## 演習一覧

| 章 | ID | 演習 | 本書の対応トピック |
|---|---|---|---|
| 4 | `xss-reflected` | 反射型XSS | 表示処理に伴う問題 |
| 4 | `xss-stored` | 格納型XSS | 表示処理に伴う問題 |
| 4 | `xss-dom` | DOM Based XSS | JavaScriptの問題 |
| 4 | `sqli` | SQLインジェクション | SQL呼び出しに伴う脆弱性 |
| 4 | `csrf` | CSRF | 重要な処理の際に混入する脆弱性 |
| 4 | `clickjacking` | クリックジャッキング | 重要な処理の際に混入する脆弱性 |
| 4 | `session-fixation` | セッション固定化 | セッション管理の不備 |
| 4 | `open-redirect` | オープンリダイレクト | リダイレクト処理にまつわる問題 |
| 4 | `header-injection` | HTTPヘッダインジェクション | リダイレクト・クッキー出力にまつわる問題 |
| 4 | `mail-injection` | メールヘッダインジェクション | メール送信の問題 |
| 4 | `path-traversal` | ディレクトリトラバーサル | ファイルアクセスにまつわる問題 |
| 4 | `os-command-injection` | OSコマンドインジェクション | OSコマンド呼び出しの際に発生する脆弱性 |
| 5 | `password-storage` | パスワードの保存 | 認証 |
| 5 | `bruteforce` | ブルートフォース攻撃 | 認証 |
| 5 | `authz` | 認可不備（IDOR）＋監査ログ | 認可・ログ出力 |

ディレクトリトラバーサル・OSコマンド・ヘッダー/メールの改行注入は、Workers にファイルもシェルもない（HTTP ヘッダーの改行も拒否される）ため、**同じ原理を JavaScript で作った擬似環境**で再現しています。実際のコマンド実行・メール送信は行いません。

節番号は版によって異なるため、章とトピック名だけを書いています。お手元の目次で探してください。

## 動かす

```bash
npm install
npm run dev          # 表示される URL を開く（既定は http://localhost:8787）
```

- 推奨ブラウザは Chrome / Firefox。CSRF・クリックジャッキングは `localhost` の `SameSite=None; Secure` Cookie を使うため、Safari では再現できません。
- 脆弱版は XSS・CSRF の被害をあなたのブラウザで実際に受けます。**専用のブラウザプロファイル**で開くと安心です。
- 学習データはブラウザごとに分かれ、24 時間操作しないと消えます。ホームの「リセット」ボタンでいつでも初期化できます。

```bash
npm test             # 全演習の「脆弱版で成立 / 修正版で成立しない」を自動検証
npm run typecheck
npm run check:egress # アプリのコードが外部へ通信していないことの静的検査
```

## 公開する

[docs/DEPLOY.md](docs/DEPLOY.md) の手順で、Cloudflare Workers にデプロイし、Cloudflare Access で自分だけが入れるようにします。

## しくみ

| | |
|---|---|
| 実行環境 | Cloudflare Workers + [Hono](https://hono.dev/) |
| データ | 学習者ごとの SQLite 内蔵 Durable Object（他人と混ざらない・24 時間で自動削除） |
| 入口 | Cloudflare Access ＋ アプリ内での JWT 検証（設定が空なら全拒否） |
| 安全網 | ラボガード（外部への持ち出し防止 CSP、実在サイトへのリダイレクト停止、攻撃者ページの sandbox） |
| テスト | Vitest（[`@cloudflare/vitest-plugin`](https://developers.cloudflare.com/workers/testing/vitest-integration/) で Workers ランタイム上で実行） |

演習の足し方・書き方は [docs/AUTHORING.md](docs/AUTHORING.md) を見てください。
