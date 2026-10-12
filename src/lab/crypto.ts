/**
 * パスワード保存・トークン生成のための暗号ヘルパー（password-storage / bruteforce / password-reset 用）。
 *
 * - WebCrypto だけを使う。MD5 は WebCrypto にないので扱わない（SHA-1 / SHA-256 / PBKDF2 のみ）。
 * - PBKDF2 は Workers の上限が 100000 回。無料プランは CPU 10ms 制限なので、既定は 10000 回（wrangler.jsonc の PBKDF2_ITERATIONS）。
 *   1 リクエストの中で PBKDF2 を何度も回さないこと。
 * - 保存形式: `pbkdf2$<反復回数>$<ソルト(hex)>$<ハッシュ(hex)>`。反復回数とソルトが値の中に入っているので、
 *   あとで反復回数を増やしても、古いユーザーの検証は壊れない。
 */

export const PBKDF2_MAX_ITERATIONS = 100_000;
export const PBKDF2_DEFAULT_ITERATIONS = 10_000;
const SALT_BYTES = 16;
const HASH_BYTES = 32; // SHA-256 の出力長

const enc = new TextEncoder();

export function toHex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) throw new Error("invalid hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function digestHex(algo: "SHA-1" | "SHA-256", s: string): Promise<string> {
  return toHex(await crypto.subtle.digest(algo, enc.encode(s)));
}

/** ソルトなしの SHA-256（hex）。パスワード保存には使ってはいけない例として、脆弱版で使う */
export function sha256Hex(s: string): Promise<string> {
  return digestHex("SHA-256", s);
}

/** ソルトなしの SHA-1（hex）。同上。歴史的な理由で今も見かける */
export function sha1Hex(s: string): Promise<string> {
  return digestHex("SHA-1", s);
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

/** 暗号論的乱数のトークン（既定 32 バイト＝256 ビット）。hex なら 64 文字、base64url なら 43 文字 */
export function randomToken(bytes = 32, encoding: "hex" | "base64url" = "hex"): string {
  const b = randomBytes(bytes);
  return encoding === "hex" ? toHex(b) : toBase64Url(b);
}

/** 環境変数の反復回数を安全な範囲（1〜100000）に丸める。不正な値は既定値 */
export function iterationsFromEnv(value: string | number | undefined): number {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1) return PBKDF2_DEFAULT_ITERATIONS;
  return Math.min(Math.floor(n), PBKDF2_MAX_ITERATIONS);
}

/** PBKDF2-HMAC-SHA-256 で 32 バイトの鍵を導出し、hex で返す */
export async function pbkdf2Hash(password: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    key,
    HASH_BYTES * 8,
  );
  return toHex(bits);
}

/** `pbkdf2$<iter>$<saltHex>$<hashHex>` を作る。ソルトは毎回ランダム */
export async function hashPassword(
  password: string,
  iterations: number = PBKDF2_DEFAULT_ITERATIONS,
  salt: Uint8Array<ArrayBuffer> = randomBytes(SALT_BYTES),
): Promise<string> {
  const it = iterationsFromEnv(iterations);
  return `pbkdf2$${it}$${toHex(salt)}$${await pbkdf2Hash(password, salt, it)}`;
}

export interface ParsedHash {
  iterations: number;
  saltHex: string;
  hashHex: string;
}

export function parseStoredHash(stored: string): ParsedHash | null {
  const m = /^pbkdf2\$(\d{1,6})\$([0-9a-f]{2,64})\$([0-9a-f]{64})$/.exec(stored);
  if (!m) return null;
  const iterations = Number(m[1]);
  if (iterations < 1 || iterations > PBKDF2_MAX_ITERATIONS || m[2].length % 2 !== 0) return null;
  return { iterations, saltHex: m[2], hashHex: m[3] };
}

/** 保存された値と照合する。形式が壊れていれば false（計算はしない） */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const p = parseStoredHash(stored);
  if (!p) return false;
  const actual = await pbkdf2Hash(password, fromHex(p.saltHex), p.iterations);
  return timingSafeEqual(actual, p.hashHex);
}

/**
 * 文字列の定数時間比較。最初に違った位置で止めない（比較時間から正しい値の先頭を推測されないため）。
 * 長さが違うときも全体を走査する（長さそのものは漏れるが、ハッシュ値の比較では常に同じ長さ）。
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

/**
 * 処理にかかった時間（ミリ秒）を測る。
 * Workers のタイマーは「I/O が起きるまで進まない」ため、前後で I/O（io）を 1 回挟んで時計を更新する。
 * io 自体の往復時間が含まれるので、あくまで目安。
 */
export async function measureMs(work: () => Promise<unknown>, io: () => Promise<unknown>): Promise<number> {
  await io();
  const t0 = Date.now();
  await work();
  await io();
  return Date.now() - t0;
}
