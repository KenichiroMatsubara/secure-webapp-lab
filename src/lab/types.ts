import type { Hono } from "hono";
import type { AppEnv } from "../env";

/** 攻撃手順の 1 ステップ（解説ページの「攻撃手順」に並ぶ） */
export interface Step {
  title: string;
  /** 簡易マークアップ: 空行で段落、`- ` で箇条書き、`code`、**太字**。全体は HTML エスケープされる */
  body: string;
  /** 貼り付けて試す入力例（コピーボタン付きで表示される） */
  payloads?: { label: string; value: string; note?: string }[];
  /** 演習ページへのリンク。href は /x/<id>/ からの相対パス（例: "vuln/?q=test"）。"/" で始めると絶対パス（例: "/attacker/<id>/"） */
  open?: { label: string; href: string };
}

export interface ExerciseDoc {
  /** 学習目標（3 つ前後） */
  goals: string[];
  /** どんな脆弱性か（背景・なぜ危険か） */
  background: string;
  /** 攻撃手順 */
  steps: Step[];
  /** 原因の解説（「原因のコード」の上に表示） */
  cause: string;
  /** 修正の要点（「修正の差分」の上に表示） */
  fix: string;
  /** 修正版で確かめること */
  verify: string[];
  /** 残るリスク・多層防御・実務での注意 */
  beyond: string;
  /** 理解度チェック */
  quiz: { q: string; a: string }[];
}

export interface Exercise {
  /** URL とソースファイル名に使う（src/exercises/<id>.ts） */
  id: string;
  title: string;
  /** 一覧に出す 1 行説明 */
  summary: string;
  /** 難易度 1〜3 */
  level: 1 | 2 | 3;
  /** 本書（徳丸浩『体系的に学ぶ 安全なWebアプリケーションの作り方』第2版）との対応 */
  book: { chapter: 4 | 5; topic: string };
  /** 学習者 DB の初期化 SQL（CREATE TABLE など）。表名は `<id をアンダースコア化>_` で始める */
  schema?: string[];
  /** 初期データ投入 SQL */
  seed?: string[];
  /** /x/<id>/vuln に載る脆弱版 */
  vuln: Hono<AppEnv>;
  /** /x/<id>/fixed に載る修正版 */
  fixed: Hono<AppEnv>;
  /** /attacker/<id> に載る「攻撃者サイト」役のページ（CSP sandbox で別オリジン扱いになる） */
  attacker?: Hono<AppEnv>;
  /** 脆弱版ページを iframe に埋め込まれてよいか（クリックジャッキングの演習だけ true） */
  allowFramingOfVuln?: boolean;
  doc: ExerciseDoc;
}

/** scripts/gen-sources.ts が生成する、演習ソースの抜粋 */
export interface ExerciseSource {
  vuln: string;
  fixed: string;
  diff: string;
}
