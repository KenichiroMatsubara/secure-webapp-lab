import { describe, expect, it } from "vitest";
import {
  PBKDF2_MAX_ITERATIONS,
  fromHex,
  hashPassword,
  iterationsFromEnv,
  parseStoredHash,
  pbkdf2Hash,
  randomToken,
  sha1Hex,
  sha256Hex,
  timingSafeEqual,
  toHex,
  verifyPassword,
} from "../src/lab/crypto";
import { COMMON_PASSWORDS, TOP_PASSWORDS } from "../src/lab/wordlist";
import { formatOffset } from "../src/lab/simclock";

describe("crypto: ハッシュ", () => {
  it("SHA-256 / SHA-1 の既知の値", async () => {
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(await sha1Hex("abc")).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
  });

  it("PBKDF2-HMAC-SHA-256 の既知の値（password / salt / 1 回）", async () => {
    const salt = new TextEncoder().encode("salt");
    expect(await pbkdf2Hash("password", salt, 1)).toBe(
      "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    );
  });

  it("hex の往復と不正な入力", () => {
    expect(toHex(fromHex("00ff10"))).toBe("00ff10");
    expect(() => fromHex("abc")).toThrow();
    expect(() => fromHex("zz")).toThrow();
  });
});

describe("crypto: トークン", () => {
  it("既定は 256 ビット（hex 64 文字）で、毎回違う。base64url も選べる", () => {
    const a = randomToken();
    const b = randomToken();
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toBe(b);
    expect(randomToken(32, "base64url")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(randomToken(16)).toHaveLength(32);
  });
});

describe("crypto: パスワードの保存と検証", () => {
  it("pbkdf2$反復$ソルト$ハッシュ の形式で、検証できる", async () => {
    const stored = await hashPassword("correct horse", 1000);
    expect(stored).toMatch(/^pbkdf2\$1000\$[0-9a-f]{32}\$[0-9a-f]{64}$/);
    expect(await verifyPassword("correct horse", stored)).toBe(true);
    expect(await verifyPassword("correct horsf", stored)).toBe(false);
    expect(await verifyPassword("", stored)).toBe(false);
  });

  it("同じパスワードでも、ソルトが違うので毎回別の値になる", async () => {
    const a = await hashPassword("same", 1000);
    const b = await hashPassword("same", 1000);
    expect(a).not.toBe(b);
    expect(await verifyPassword("same", a)).toBe(true);
    expect(await verifyPassword("same", b)).toBe(true);
  });

  it("反復回数は値の中に入っているので、後から設定を変えても古い値を検証できる", async () => {
    const old = await hashPassword("pw", 1000);
    const next = await hashPassword("pw", 2000);
    expect(parseStoredHash(old)?.iterations).toBe(1000);
    expect(parseStoredHash(next)?.iterations).toBe(2000);
    expect(await verifyPassword("pw", old)).toBe(true);
  });

  it("形式が壊れた値・上限を超える反復回数は false（例外にしない）", async () => {
    expect(await verifyPassword("pw", "plaintext")).toBe(false);
    expect(await verifyPassword("pw", "pbkdf2$1000$zz$abc")).toBe(false);
    const huge = `pbkdf2$${PBKDF2_MAX_ITERATIONS + 1}$${"00".repeat(16)}$${"0".repeat(64)}`;
    expect(parseStoredHash(huge)).toBeNull();
    expect(await verifyPassword("pw", huge)).toBe(false);
  });

  it("反復回数は 1〜100000 に丸める。不正な値は既定の 10000", () => {
    expect(iterationsFromEnv("1000")).toBe(1000);
    expect(iterationsFromEnv("999999")).toBe(PBKDF2_MAX_ITERATIONS);
    expect(iterationsFromEnv(undefined)).toBe(10000);
    expect(iterationsFromEnv("abc")).toBe(10000);
    expect(iterationsFromEnv("0")).toBe(10000);
  });
});

describe("crypto: 定数時間比較", () => {
  it("一致・不一致・長さ違い・空文字", () => {
    expect(timingSafeEqual("abc", "abc")).toBe(true);
    expect(timingSafeEqual("abc", "abd")).toBe(false);
    expect(timingSafeEqual("abc", "abcd")).toBe(false);
    expect(timingSafeEqual("", "")).toBe(true);
    expect(timingSafeEqual("", "a")).toBe(false);
    expect(timingSafeEqual("あ", "あ")).toBe(true);
  });
});

describe("辞書・模擬時計", () => {
  it("辞書は 100〜200 語で重複がなく、先頭 30 語が bruteforce の辞書", () => {
    expect(COMMON_PASSWORDS.length).toBeGreaterThanOrEqual(100);
    expect(COMMON_PASSWORDS.length).toBeLessThanOrEqual(200);
    expect(new Set(COMMON_PASSWORDS).size).toBe(COMMON_PASSWORDS.length);
    expect(TOP_PASSWORDS).toHaveLength(30);
    expect(TOP_PASSWORDS[0]).toBe(COMMON_PASSWORDS[0]);
  });

  it("時計のずれの表示", () => {
    expect(formatOffset(0)).toBe("進めていません");
    expect(formatOffset(30_000)).toBe("+30 秒");
    expect(formatOffset(150_000)).toBe("+2 分 30 秒");
    expect(formatOffset(3600_000)).toBe("+1 時間");
  });
});
