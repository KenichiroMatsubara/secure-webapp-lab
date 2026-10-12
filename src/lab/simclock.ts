import type { LabDb } from "../env";

/**
 * 模擬時計（bruteforce / password-reset 用）。
 *
 * 「30 分たつとトークンが失効する」「60 秒ロックされる」といった時間に依存する挙動を、
 * 本当に待たずに体験・テストできるよう、学習者ごとの DB に「時計のずれ（ミリ秒）」を 1 つ持つ。
 * 現在時刻は「実際の時刻 ＋ ずれ」。ずれは進める方向にしか動かない。状態は学習者の DB の中だけにあり、他人には影響しない。
 */

/** 演習用の時計テーブルを作る SQL（schema に展開して使う）。table は演習 ID の接頭辞付きの固定文字列 */
export function simClockSchema(table: string): { schema: string[]; seed: string[] } {
  return {
    schema: [
      `CREATE TABLE ${table} (id INTEGER PRIMARY KEY CHECK (id = 1), offset_ms INTEGER NOT NULL DEFAULT 0)`,
    ],
    seed: [`INSERT INTO ${table} (id, offset_ms) VALUES (1, 0)`],
  };
}

/** 模擬時計の現在時刻（ミリ秒） */
export async function simNow(db: LabDb, table: string): Promise<number> {
  const row = await db.first<{ offset_ms: number }>(`SELECT offset_ms FROM ${table} WHERE id = 1`);
  return Date.now() + Number(row?.offset_ms ?? 0);
}

/** 模擬時計を進める。1 回で進められるのは最大 24 時間。新しいずれ（ミリ秒）を返す */
export async function advanceSimClock(db: LabDb, table: string, ms: number): Promise<number> {
  const step = Math.min(Math.max(Math.floor(ms) || 0, 0), 24 * 3600_000);
  await db.run(`UPDATE ${table} SET offset_ms = offset_ms + ? WHERE id = 1`, [step]);
  const row = await db.first<{ offset_ms: number }>(`SELECT offset_ms FROM ${table} WHERE id = 1`);
  return Number(row?.offset_ms ?? 0);
}

/** 画面表示用: 「+2 分 30 秒」など */
export function formatOffset(ms: number): string {
  if (ms <= 0) return "進めていません";
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  return `+${h ? `${h} 時間 ` : ""}${m ? `${m} 分 ` : ""}${sec || (!h && !m) ? `${sec} 秒` : ""}`.trim();
}
