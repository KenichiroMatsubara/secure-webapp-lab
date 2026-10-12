/**
 * 生のメール文面（RFC 5322 風のテキスト）を組み立てる/解析するための擬似部品。
 *
 * メールヘッダインジェクションの演習だけが使う。実際にはメールを送らない（メモリ上の文字列だけ）。
 * HTTP と同じく「ヘッダー行を CRLF で並べ、空行のあとが本文」という形式なので、解析は rawhttp.ts と共通。
 */
import { CRLF, hasControlChars, parseHeaderBlock, type ParsedHeaderBlock } from "./rawhttp";

/** ヘッダー行は呼び出し側が作ったものを CRLF で並べるだけ（検査しない＝文字列連結の実装の模擬） */
export function buildRawMail(headerLines: string[], body: string): string {
  return headerLines.join(CRLF) + CRLF + CRLF + body;
}

export type ParsedMail = ParsedHeaderBlock;

/** メール文面を解釈する。折り返し（行頭が空白の継続行）も解く */
export function parseRawMail(raw: string): ParsedMail {
  return parseHeaderBlock(raw, { unfold: true });
}

const ADDRESS_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+/g;

/** To / Cc / Bcc ヘッダーに書かれたメールアドレス（配送先）を、重複なしで出現順に返す */
export function recipientsOf(mail: ParsedMail): string[] {
  const seen = new Set<string>();
  for (const h of mail.headers) {
    if (!/^(to|cc|bcc)$/i.test(h.name)) continue;
    for (const a of h.value.match(ADDRESS_RE) ?? []) seen.add(a.toLowerCase());
  }
  return [...seen];
}

/** 簡易的なメールアドレスの形式検査（実務ではライブラリや確認メールで検証する。ここでは CR/LF や空白・括弧を通さないことが目的） */
const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$/;

export function isValidEmail(s: string): boolean {
  return s.length <= 254 && EMAIL_RE.test(s);
}

// ---- RFC 2047 風のエンコード（件名に日本語などを入れるときの「エンコード済み単語」） ----

function toBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * 件名を RFC 2047 の B エンコード（=?UTF-8?B?…?=）にする。
 * ASCII の印字可能文字だけなら、そのまま返す。1 語は 75 文字以内に収まるよう分割し、折り返し（CRLF + 空白）でつなぐ。
 * CR/LF を含む値は、エンコードの前に拒否する（エンコードすれば改行が消えるので「結果的に安全」だが、入力の時点で弾く方が筋がよい）。
 */
export function encodeMimeWord(s: string): string {
  if (/[\r\n]/.test(s)) throw new Error("件名に改行は使えません");
  if (/^[\x20-\x7e]*$/.test(s)) return s;
  const enc = new TextEncoder();
  const words: string[] = [];
  let chunk = "";
  for (const ch of s) {
    if (enc.encode(chunk + ch).length > 45) {
      words.push(chunk);
      chunk = "";
    }
    chunk += ch;
  }
  if (chunk) words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${toBase64(enc.encode(w))}?=`).join(CRLF + " ");
}

/** =?UTF-8?B?…?= を元の文字列に戻す（画面で件名を読めるようにするため）。隣り合うエンコード済み単語の間の空白は無視する */
export function decodeMimeWords(s: string): string {
  const dec = new TextDecoder();
  return s
    .replace(/(\?=)\s+(?==\?UTF-8\?B\?)/gi, "$1")
    .replace(/=\?UTF-8\?B\?([A-Za-z0-9+/=]*)\?=/gi, (_, b64: string) => {
      try {
        return dec.decode(fromBase64(b64));
      } catch {
        return "�";
      }
    });
}

export class MailError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MailError";
  }
}

export interface MailInput {
  from: string;
  to: string;
  subject: string;
  text: string;
}

/**
 * 「メール送信ライブラリ」の模擬。呼び出し側は項目ごとの値を渡すだけで、ヘッダー行は自分で連結しない。
 * 宛先・差出人は形式を検査し、ヘッダーに入る値に改行などの制御文字があれば例外にする。
 * 件名は必要に応じて RFC 2047 でエンコードする。本文の改行は CRLF にそろえる。
 */
export function composeMail(m: MailInput): string {
  for (const [k, v] of [["from", m.from], ["to", m.to], ["subject", m.subject]] as const) {
    if (hasControlChars(v)) throw new MailError(`${k} に改行などの制御文字は使えません`);
  }
  if (!isValidEmail(m.from)) throw new MailError("from のメールアドレスの形式が正しくありません");
  if (!isValidEmail(m.to)) throw new MailError("to のメールアドレスの形式が正しくありません");
  const headers = [
    `From: ${m.from}`,
    `To: ${m.to}`,
    `Subject: ${encodeMimeWord(m.subject)}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit",
  ];
  return buildRawMail(headers, m.text.replace(/\r\n|\r|\n/g, CRLF));
}
