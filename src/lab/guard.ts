import { escapeHtml } from "./html";
import { exercises } from "./registry";

/**
 * ラボガード: 脆弱版のコードには手を入れず、レスポンスを返す直前に外側から安全網をかける。
 *
 *  1. 外部への持ち出し防止 … XSS が成立しても、Cookie や入力値を第三者のサイトへ送れないよう CSP で縛る
 *     （スクリプトの実行自体は許す。XSS を体験できなくなるため）
 *  2. 実在サイトへのリダイレクトを止める … オープンリダイレクトがフィッシングの踏み台にならないよう、
 *     予約ドメイン（.example / .test など）以外への転送は、転送せず「転送しようとした」ことだけを表示する
 *  3. 攻撃者ページは CSP sandbox で別オリジン扱いにする … CSRF / クリックジャッキングのクロスサイト再現用
 *  4. 検索エンジンに載せない・キャッシュさせない
 */

/** RFC 2606 / 6761 で予約された、実在しないことが保証されているドメイン */
const SAFE_SUFFIXES = [".example", ".test", ".invalid", ".localhost", ".example.com", ".example.net", ".example.org"];
const SAFE_HOSTS = ["example.com", "example.net", "example.org", "localhost", "127.0.0.1", "[::1]"];

export function isLabSafeHost(hostname: string): boolean {
  const h = hostname.toLowerCase();
  return SAFE_HOSTS.includes(h) || SAFE_SUFFIXES.some((s) => h.endsWith(s));
}

function exfilGuardCsp(allowFraming: boolean): string {
  return [
    "default-src 'self' 'unsafe-inline' data:",
    "connect-src 'self'",
    "img-src 'self' data:",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    ...(allowFraming ? [] : ["frame-ancestors 'self'"]),
  ].join("; ");
}

const SHELL_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join("; ");

// 攻撃者ページ: allow-same-origin を付けない sandbox ＝ opaque origin（Origin: null のクロスサイト扱い）
const ATTACKER_CSP = [
  "sandbox allow-forms allow-scripts",
  "default-src 'none'",
  "style-src 'self' 'unsafe-inline'",
  "script-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "frame-src 'self'",
  "form-action 'self'",
  "connect-src 'self'",
].join("; ");

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function blockedRedirectPage(location: string): string {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>ラボガード</title>
<link rel="stylesheet" href="/assets/lab.css"></head><body class="ex ex--guard"><main class="ex-main">
<h1>🛡 ラボガードがリダイレクトを止めました</h1>
<p>このページは次の <code>Location</code> へリダイレクトしようとしました。</p>
<pre class="code"><code>Location: ${escapeHtml(location)}</code></pre>
<p>脆弱なリダイレクトがフィッシングの踏み台にならないよう、このラボは実在するサイトへは転送しません。
転送先が <code>https://evil.example/</code> のような予約ドメイン（<code>.example</code> / <code>.test</code> など）であれば、実際に転送されます。</p>
<p>攻撃が成立している（外部の任意の URL へ飛ばせている）ことは、上の <code>Location</code> ヘッダの値で確認できます。</p>
<p><a href="/">一覧へ戻る</a></p>
</main></body></html>`;
}

const framable = new Set(exercises.filter((e) => e.allowFramingOfVuln).map((e) => e.id));

/**
 * アプリが返したレスポンスに、外側から安全網をかける。
 * Hono のミドルウェアではなく fetch ハンドラーの外側で行う理由: Hono の `c.res = …` は古いレスポンスの
 * ヘッダーを新しい方へ上書きコピーするため、差し替えた Location や、重ねて付けた CSP が元に戻ってしまう。
 */
export function applyLabGuard(request: Request, original: Response): Response {
  let res = original;

  // 2. 実在サイトへのリダイレクトを止める
  if (REDIRECT_STATUSES.has(res.status)) {
    const loc = res.headers.get("Location");
    if (loc) {
      let blocked = false;
      try {
        const target = new URL(loc, request.url);
        const sameOrigin = target.origin === new URL(request.url).origin;
        const http = target.protocol === "http:" || target.protocol === "https:";
        blocked = !sameOrigin && !(http && isLabSafeHost(target.hostname));
      } catch {
        blocked = true;
      }
      if (blocked) {
        const page = new Response(blockedRedirectPage(loc), {
          status: 200,
          headers: { "Content-Type": "text/html; charset=UTF-8" },
        });
        // ログイン後のリダイレクトなど、Cookie の発行は維持する
        for (const cookie of res.headers.getSetCookie()) page.headers.append("Set-Cookie", cookie);
        res = page;
      }
    }
  }

  // ヘッダーを書き換えられるよう複製する（Response.redirect() などは不変）
  const out = new Response(res.body, res);
  const h = out.headers;
  h.set("X-Robots-Tag", "noindex, nofollow, noarchive");
  // no-referrer にしてはいけない: ブラウザが同一オリジンの POST にも `Origin: null` を付け、
  // Origin 検証（修正版の CSRF 対策）が正当なフォーム送信まで拒否してしまう
  h.set("Referrer-Policy", "same-origin");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Cache-Control", "no-store");

  const path = new URL(request.url).pathname;
  const m = /^\/x\/([^/]+)\/(vuln|fixed)(\/|$)/.exec(path);
  if (m) {
    // 1. 持ち出し防止（各演習が自前で付けた CSP とは独立に、追加で適用される）
    h.append("Content-Security-Policy", exfilGuardCsp(m[2] === "vuln" && framable.has(m[1])));
  } else if (path.startsWith("/attacker/")) {
    // 3. 攻撃者ページ
    h.set("Content-Security-Policy", ATTACKER_CSP);
  } else {
    h.set("Content-Security-Policy", SHELL_CSP);
    h.set("X-Frame-Options", "DENY");
  }
  return out;
}
