import { env } from "cloudflare:workers";
import type { LabDO } from "../src/lab/db";
import type { Row, SqlParam } from "../src/env";
import type { Browser } from "./helpers";

/**
 * パスワード系の演習（password-storage / bruteforce / password-reset）のテスト用。
 * 学習者（Browser）の DB を直接のぞいて、保存された値（ハッシュ・トークンのキー）を確かめる。
 * 学習者の特定は learner.ts と同じ規則（ローカル開発では lab_id Cookie → `c:<id>`）。
 */
export function dbOf(b: Browser) {
  const id = b.cookie("lab_id");
  if (!id) throw new Error("lab_id Cookie がまだない（先にどこかのページを開く）");
  const ns = (env as unknown as { LAB: DurableObjectNamespace<LabDO> }).LAB;
  const stub = ns.get(ns.idFromName(`c:${id}`));
  return {
    all: async <T = Row>(sql: string, params: SqlParam[] = []) => (await stub.all(sql, params)) as unknown as T[],
    first: async <T = Row>(sql: string, params: SqlParam[] = []) =>
      ((await stub.all(sql, params))[0] as T | undefined) ?? null,
  };
}

/** 303 などのリダイレクト先（Location）を相対パスで返す */
export function locationOf(res: Response): string {
  const loc = res.headers.get("Location") ?? "";
  return loc.startsWith("http") ? new URL(loc).pathname + new URL(loc).search : loc;
}
