/**
 * 仮想ファイルシステム（メモリ上の読み取り専用のファイルツリー）。
 *
 * ディレクトリトラバーサルと OS コマンドインジェクションの演習が使う。
 * Cloudflare Workers にはファイルシステムがなく、この演習は実際のファイルを一切読まない。
 * 中身はすべて、ラボ用に書いたダミーの文字列。
 */

/** ダミーのファイルツリー。秘密に見えるものも、すべて偽物 */
const FILES: Record<string, string> = {
  "/app/public/docs/readme.txt":
    "ようこそ。これは社内資料ポータルのダミーの README です。\n公開してよい資料は /app/public/docs の下に置かれています。\n",
  "/app/public/docs/guide.txt":
    "利用ガイド（ダミー）\n1. 左の一覧から資料を選びます。\n2. 資料の内容が画面に表示されます。\n",
  "/app/public/images/logo.txt": "[ロゴ画像の代わりのダミーテキスト]\n  ____\n | LAB |\n  ----\n",
  "/app/config/secrets.env":
    "# ラボ用のダミーです。実在の認証情報ではありません\nDB_PASSWORD=lab-fake-password\nAPI_KEY=lab-fake-api-key-0000\nSESSION_SECRET=lab-fake-session-secret\n",
  "/app/src/server.js":
    "// ダミーのサーバープログラム（偽）\nconst config = require('../config/secrets.env');\napp.get('/download', (req, res) => {\n  /* ... */\n});\n",
  "/etc/passwd":
    "root:x:0:0:root:/root:/bin/sh\nlabuser:x:1000:1000:Lab User:/home/labuser:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
};

/**
 * POSIX 風のパス正規化。連続するスラッシュを 1 つにし、`.` を取り除き、`..` を 1 つ上のディレクトリとして解決する。
 * ルートより上へは行けない（`/..` は `/`）。相対パスは相対パスのまま（先頭の `..` は残る）。
 * 区切りは `/` だけ。`\` はただの文字（POSIX と同じ）。node:path は使わない。
 */
export function normalizePath(p: string): string {
  const abs = p.startsWith("/");
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (out.length > 0 && out[out.length - 1] !== "..") out.pop();
      else if (!abs) out.push("..");
      continue;
    }
    out.push(seg);
  }
  const joined = out.join("/");
  if (abs) return "/" + joined;
  return joined === "" ? "." : joined;
}

/** 基準ディレクトリに相対パスを連結して正規化する（OS が `base + "/" + rel` を解決するのと同じ）。rel が絶対パスならそれを使う */
export function resolvePath(base: string, rel: string): string {
  return normalizePath(rel.startsWith("/") ? rel : base + "/" + rel);
}

export type ReadResult =
  | { ok: true; content: string }
  | { ok: false; code: "ENOENT" | "EISDIR" | "EINVAL"; error: string };

export class Vfs {
  private files: Map<string, string>;
  private dirs: Set<string>;

  constructor(files: Record<string, string> = FILES) {
    this.files = new Map(Object.entries(files));
    this.dirs = new Set(["/"]);
    for (const f of this.files.keys()) {
      let d = f;
      while (d !== "/") {
        d = d.slice(0, d.lastIndexOf("/")) || "/";
        this.dirs.add(d);
      }
    }
  }

  isFile(path: string): boolean {
    return this.files.has(path);
  }

  isDir(path: string): boolean {
    return this.dirs.has(path);
  }

  /**
   * ファイルを読む（open(2) の模擬）。引数は呼び出し側が解決済みの絶対パスを渡すこと。
   * NUL を含むパスは現代のランタイムと同じくエラーにする。
   */
  read(path: string): ReadResult {
    if (path.includes("\0")) return { ok: false, code: "EINVAL", error: "EINVAL: パスに NUL バイトが含まれています" };
    const c = this.files.get(path);
    if (c !== undefined) return { ok: true, content: c };
    if (this.isDir(path)) return { ok: false, code: "EISDIR", error: `EISDIR: ${path} はディレクトリです` };
    return { ok: false, code: "ENOENT", error: `ENOENT: ${path} というファイルはありません` };
  }

  /** ディレクトリ直下の名前（ファイルとサブディレクトリ）を辞書順で返す。ディレクトリでなければ null */
  list(dir: string): string[] | null {
    if (!this.isDir(dir)) return null;
    const prefix = dir === "/" ? "/" : dir + "/";
    const names = new Set<string>();
    for (const p of [...this.files.keys(), ...this.dirs]) {
      if (p === dir || !p.startsWith(prefix)) continue;
      names.add(p.slice(prefix.length).split("/")[0]);
    }
    return [...names].sort();
  }

  size(path: string): number {
    return new TextEncoder().encode(this.files.get(path) ?? "").length;
  }
}

/** ラボ共通の仮想ファイルシステム（読み取り専用なので、どの学習者でも同じ） */
export const labVfs = new Vfs();
