# 公開手順（Cloudflare Workers + Cloudflare Access）

脆弱なアプリを公開するので、**先に Access で入口を閉じてからデプロイ**します。この順番を守れば、閉じていない状態のURLが一瞬でも外に出ることはありません。

> このドキュメントの操作は Cloudflare ダッシュボードとあなたのアカウントに対するものです。コマンドは自分で実行してください。

## 0. 前提

- Cloudflare アカウント（無料プランで動きます）
- Zero Trust（無料プラン）の有効化。Access のログイン方法は「ワンタイムPIN（メール）」で足ります
- Node.js 20 以上、`npm install` 済み

無料プランで動かすときの注意は [§6](#6-無料プランでの注意) にまとめています。

## 1. ローカルで動作確認

```bash
npm install
npm test
npm run dev        # http://localhost:8787
```

ローカルでは Access の検証を省略します（`npm run dev` が `ENVIRONMENT=development` を付けるため）。

## 2. Worker を作る（まだ公開しない）

最初のデプロイでは、`ACCESS_TEAM_DOMAIN` と `ACCESS_AUD` が空のままなので、**アプリ自身がすべてのリクエストを 503 で拒否します**（fail-closed）。つまり Access を設定する前にデプロイしても、中身は見えません。

```bash
npx wrangler login
npm run deploy      # 型・外部通信の検査 → wrangler deploy
```

デプロイ後に表示される `https://secure-webapp-lab.<あなたのサブドメイン>.workers.dev` をメモします。

## 3. Access で保護する

### 3-1. workers.dev に Access を有効化（いちばん簡単）

1. ダッシュボード → **Workers & Pages** → `secure-webapp-lab`
2. **Settings** → **Domains & Routes**
3. `workers.dev` の行で **Enable Cloudflare Access** をクリック
4. **Manage Cloudflare Access** を開き、ポリシーで**許可するメールアドレスを自分だけ**にする

プレビューURL（`*-secure-webapp-lab.<sub>.workers.dev`）は `wrangler.jsonc` の `preview_urls: false` で無効化済みです。

### 3-2. 自前ドメインで公開する場合

Zero Trust → **Access** → **Applications** → **Add an application** → **Self-hosted** で、ホスト名に Worker のカスタムドメインを指定し、同様に自分だけを許可するポリシーを作ります。

## 4. アプリ側の JWT 検証を有効にする

Access の前段ポリシーが誤って外れても守れるよう、アプリ自身も JWT を検証します（二重防御）。

1. **Team domain** … Zero Trust → **Settings** → **Custom pages**（または **General**）に表示される `https://<チーム名>.cloudflareaccess.com`
2. **AUD タグ** … Zero Trust → **Access** → **Applications** → 作られたアプリ → **Overview** の **Application Audience (AUD) Tag**
3. `wrangler.jsonc` の `vars` に設定します。

```jsonc
"vars": {
  "ENVIRONMENT": "production",
  "ACCESS_TEAM_DOMAIN": "https://<チーム名>.cloudflareaccess.com",
  "ACCESS_AUD": "<AUDタグ>",
  "ALLOWED_EMAILS": "you@example.com",   // 任意: ポリシーに加えた二重チェック
  …
}
```

4. もう一度デプロイします。

```bash
npm run deploy
```

AUD タグはシークレットではありません（JWT の `aud` に入っています）。リポジトリに置いて構いません。

## 5. 動作確認

- シークレットウィンドウで URL を開く → Access のログイン画面になる（アプリの画面は見えない）
- ログイン後、ホームが表示される
- 別のメールでログインを試す → ポリシーで拒否される
- `curl -i https://<…>.workers.dev/` → Access のログインへリダイレクトされ、アプリの中身は返らない

### CSRF・クリックジャッキングの演習が本番で動かないとき

この 2 つは「別サイトのページから、ログイン済みのブラウザで送る」攻撃を再現します。攻撃者ページ（sandbox で別オリジン扱い）からのリクエストに **Access 自身の Cookie（`CF_Authorization`）が付かない**と、Access がログイン画面へ飛ばして攻撃が再現されません。

Zero Trust → **Access** → **Applications** → 該当アプリ → **Configure** → **Advanced settings** → **Cookie settings** で、**SameSite を `None`** にすると再現できます（既定のままで動くなら変更は不要です）。`HttpOnly` は有効のままにしてください。

ローカル（`npm run dev`）では不要です。

## 6. 無料プランでの注意

- **Durable Objects（SQLite 内蔵）** は無料プランで使えます。学習者 1 人 1 インスタンスです。
- **CPU 時間は 1 リクエスト 10ms まで**です。パスワード演習の PBKDF2 は `PBKDF2_ITERATIONS`（既定 10000）で調整できます。`Exceeded CPU` が出たら値を下げます。有料プランなら Workers の上限の 100000 にできます。
- リクエスト数の上限（無料プランは 1 日あたり 10 万）を超えないよう、ブルートフォース演習の自動試行は数十回に抑えてあります。

## 7. 運用

- **データは自動で消えます。** 最後の操作から `LAB_TTL_HOURS`（既定 24 時間）で学習データを削除します。
- **手動リセット** … ホームの「すべての演習データを初期状態に戻す」ボタン。
- **スキーマを変えたとき** … 次のアクセスで学習者のデータが自動的に作り直されます。
- **公開をやめる** … `npx wrangler delete` で Worker を削除し、Access アプリケーションも削除します。

## 8. GitHub に置く

コード自体は公開しても構いません（デプロイ先は Access で閉じています）。ただし、**脆弱なコードをそのままコピーして使われるリスク**は残るので、README の注意書きは消さないでください。

```bash
git init
git add .
git commit -m "Initial commit"
gh repo create secure-webapp-lab --public --source=. --push   # 非公開にするなら --private
```

リポジトリに入れてはいけないもの: `.dev.vars`（`.gitignore` 済み）、Cloudflare の API トークン、アカウントID。
