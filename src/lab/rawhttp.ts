/**
 * 生の HTTP レスポンス（バイト列）を組み立てる/解析するための擬似部品。
 *
 * HTTPヘッダインジェクションとメールヘッダインジェクションの演習だけが使う。
 *
 * なぜ必要か:
 *  - 現代の Fetch API（Headers / Response）は、ヘッダー値に CR/LF が含まれると TypeError を投げる。
 *    つまり Workers の普通のコードでは、この脆弱性は起きない。
 *  - 古い実装・独自実装・別のプロトコル（メール、ログ）では、いまも「文字列を連結して CRLF で区切る」
 *    作りが存在する。そこで、その作りを純粋な文字列操作だけで再現する。
 *  - 実際のネットワーク通信は一切しない。すべてメモリ上の文字列。
 */
import { escapeHtml } from "./html";

export const CRLF = "\r\n";

const REASONS: Record<number, string> = {
  200: "OK",
  301: "Moved Permanently",
  302: "Found",
  303: "See Other",
  400: "Bad Request",
  404: "Not Found",
};

/** ヘッダー値に使ってはいけない文字（CR・LF・NUL を含む制御文字。TAB だけは許される） */
const CONTROL_RE = /[\u0000-\u0008\u000a-\u001f\u007f]/;

export function hasControlChars(s: string): boolean {
  return CONTROL_RE.test(s);
}

export class HeaderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HeaderError";
  }
}

const TOKEN_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * 検証つきでヘッダー行を作る（Fetch API の Headers.set() が内部でやっているのと同じ検査の模擬）。
 * 名前は token、値は制御文字を含まないこと。違反したら例外。
 */
export function headerLine(name: string, value: string): string {
  if (!TOKEN_RE.test(name)) throw new HeaderError(`ヘッダー名が不正です: ${JSON.stringify(name)}`);
  if (hasControlChars(value)) throw new HeaderError(`ヘッダー値に改行などの制御文字が含まれています: ${JSON.stringify(name)}`);
  return `${name}: ${value}`;
}

/**
 * 生の HTTP レスポンスを組み立てる。ヘッダー行は呼び出し側が作ったものを CRLF で並べるだけ。
 * （これが「文字列連結でヘッダーを作る古い実装」の模擬。値に CRLF が入っていても検査しない）
 */
export function buildRawResponse(status: number, headerLines: string[], body = ""): string {
  const statusLine = `HTTP/1.1 ${status} ${REASONS[status] ?? "Status"}`;
  return [statusLine, ...headerLines].join(CRLF) + CRLF + CRLF + body;
}

export interface Header {
  name: string;
  value: string;
}

export interface ParsedHeaderBlock {
  headers: Header[];
  /** 「名前: 値」の形になっていない行 */
  malformed: string[];
  /** 空行で終わっていたか（終わっていなければ、本文はない） */
  terminated: boolean;
  body: string;
}

/**
 * ヘッダーブロックを解析する。空行（CRLF CRLF、または LF LF）でヘッダーが終わり、残りが本文。
 * 行末は CRLF のほか LF だけも受け入れる（多くの実装が寛容に受け取るため、%0a だけの注入も成立する）。
 * 単独の CR は行末とみなさない。
 */
export function parseHeaderBlock(text: string, opts: { unfold?: boolean } = {}): ParsedHeaderBlock {
  const headers: Header[] = [];
  const malformed: string[] = [];
  let i = 0;
  let terminated = false;
  while (i < text.length) {
    const nl = text.indexOf("\n", i);
    const end = nl === -1 ? text.length : nl;
    const line = text.slice(i, end).replace(/\r$/, "");
    i = nl === -1 ? text.length : nl + 1;
    if (line === "") {
      terminated = true;
      break;
    }
    if (opts.unfold && /^[ \t]/.test(line) && headers.length > 0) {
      const last = headers[headers.length - 1];
      last.value = (last.value + " " + line.trim()).trim();
      continue;
    }
    const colon = line.indexOf(":");
    const name = colon > 0 ? line.slice(0, colon) : "";
    if (!name || !TOKEN_RE.test(name)) {
      malformed.push(line);
      continue;
    }
    headers.push({ name, value: line.slice(colon + 1).trim() });
  }
  return { headers, malformed, terminated, body: terminated ? text.slice(i) : "" };
}

export interface ParsedResponse extends ParsedHeaderBlock {
  statusLine: string;
  status: number | null;
  reason: string;
}

/** プロキシ/ブラウザが受け取ったバイト列をどう解釈するか。最初の1行がステータス行、続いてヘッダー、空行、本文 */
export function parseRawResponse(raw: string): ParsedResponse {
  const nl = raw.indexOf("\n");
  const first = (nl === -1 ? raw : raw.slice(0, nl)).replace(/\r$/, "");
  const rest = nl === -1 ? "" : raw.slice(nl + 1);
  const m = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/.exec(first);
  const block = parseHeaderBlock(rest);
  return {
    statusLine: first,
    status: m ? Number(m[1]) : null,
    reason: m?.[2] ?? "",
    ...block,
  };
}

/** 同名ヘッダーをすべて返す（Set-Cookie のように複数あり得るもの用） */
export function headersNamed(headers: Header[], name: string): Header[] {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n);
}

export interface ParsedCookie {
  name: string;
  value: string;
  attrs: string[];
}

/** Set-Cookie の値を「名前=値; 属性…」に分ける。名前が空なら null */
export function parseSetCookie(value: string): ParsedCookie | null {
  const [pair, ...attrs] = value.split(";").map((s) => s.trim());
  const eq = pair.indexOf("=");
  if (eq <= 0) return null;
  return { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim(), attrs: attrs.filter(Boolean) };
}

const MARK: Record<string, string> = { "\r\n": "␍␊", "\n": "␊", "\r": "␍" };

/** 改行を目に見える記号にした平文（CRLF → ␍␊ + 実際の改行、LF だけ → ␊、CR だけ → ␍）。テストや説明用 */
export function visualizeCrlf(raw: string): string {
  return raw.replace(/\r\n|\n|\r/g, (m) => (m === "\r" ? MARK[m] : MARK[m] + "\n"));
}

/** 改行を <mark> で強調した HTML（本文は全部エスケープ済み）。CR/LF がどこにあるかを目で追うための表示 */
export function visualizeCrlfHtml(raw: string): string {
  let out = "";
  let last = 0;
  for (const m of raw.matchAll(/\r\n|\n|\r/g)) {
    out += escapeHtml(raw.slice(last, m.index));
    out += `<mark>${MARK[m[0]]}</mark>` + (m[0] === "\r" ? "" : "\n");
    last = m.index + m[0].length;
  }
  return out + escapeHtml(raw.slice(last));
}
