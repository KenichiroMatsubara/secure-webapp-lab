import { describe, expect, it } from "vitest";
import { Vfs, labVfs, normalizePath, resolvePath } from "../src/lab/vfs";

describe("vfs: POSIX 風のパス正規化", () => {
  it("連続スラッシュを畳み、. を取り、.. を解決する", () => {
    expect(normalizePath("/a//b/./c")).toBe("/a/b/c");
    expect(normalizePath("/a/b/../c")).toBe("/a/c");
    expect(normalizePath("/a/b/c/../../d")).toBe("/a/d");
    expect(normalizePath("/a/b/")).toBe("/a/b");
    expect(normalizePath("/")).toBe("/");
    expect(normalizePath("//")).toBe("/");
  });

  it("ルートより上へは行けない", () => {
    expect(normalizePath("/../../etc/passwd")).toBe("/etc/passwd");
    expect(normalizePath("/a/../../..")).toBe("/");
  });

  it("相対パスは相対のまま、先頭の .. は残る", () => {
    expect(normalizePath("a/../b")).toBe("b");
    expect(normalizePath("../a")).toBe("../a");
    expect(normalizePath("a/../..")).toBe("..");
    expect(normalizePath("")).toBe(".");
    expect(normalizePath("./")).toBe(".");
  });

  it("区切りは / だけ。\\ や %2e は特別扱いしない（POSIX と同じ）", () => {
    expect(normalizePath("/a/..\\b")).toBe("/a/..\\b");
    expect(normalizePath("/a/%2e%2e/b")).toBe("/a/%2e%2e/b");
    expect(normalizePath("/a/....//b")).toBe("/a/..../b");
  });

  it("resolvePath: 基準 + / + 相対。相対が絶対パスならそれを採用する", () => {
    expect(resolvePath("/app/public/docs", "readme.txt")).toBe("/app/public/docs/readme.txt");
    expect(resolvePath("/app/public/docs", "../../config/secrets.env")).toBe("/app/config/secrets.env");
    expect(resolvePath("/app/public/docs", "../../../etc/passwd")).toBe("/etc/passwd");
    expect(resolvePath("/app/public/docs", "/etc/passwd")).toBe("/etc/passwd");
    expect(resolvePath("/app/public/docs", "....//....//config")).toBe("/app/public/docs/..../..../config");
  });
});

describe("vfs: ファイルの読み取り", () => {
  it("用意したダミーファイルを読める（秘密はすべて偽物）", () => {
    const r = labVfs.read("/app/config/secrets.env");
    expect(r.ok && r.content).toContain("DB_PASSWORD=lab-fake-password");
    for (const p of ["/app/public/docs/readme.txt", "/app/public/docs/guide.txt", "/app/public/images/logo.txt", "/app/src/server.js", "/etc/passwd"]) {
      expect(labVfs.read(p).ok, p).toBe(true);
    }
  });

  it("存在しない・ディレクトリ・NUL を含むパスはエラー", () => {
    expect(labVfs.read("/nope")).toMatchObject({ ok: false, code: "ENOENT" });
    expect(labVfs.read("/app")).toMatchObject({ ok: false, code: "EISDIR" });
    expect(labVfs.read("/app/public/docs/readme.txt\0.png")).toMatchObject({ ok: false, code: "EINVAL" });
  });

  it("ディレクトリの一覧", () => {
    expect(labVfs.list("/app/public/docs")).toEqual(["guide.txt", "readme.txt"]);
    expect(labVfs.list("/app")).toEqual(["config", "public", "src"]);
    expect(labVfs.list("/")).toEqual(["app", "etc"]);
    expect(labVfs.list("/app/public/docs/readme.txt")).toBeNull();
    expect(labVfs.isDir("/app/public")).toBe(true);
    expect(labVfs.isFile("/app/public")).toBe(false);
  });

  it("独自のファイルツリーも作れる", () => {
    const v = new Vfs({ "/x/y.txt": "hi" });
    expect(v.read("/x/y.txt")).toEqual({ ok: true, content: "hi" });
    expect(v.list("/")).toEqual(["x"]);
    expect(v.size("/x/y.txt")).toBe(2);
  });
});
