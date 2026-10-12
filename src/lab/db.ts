import { DurableObject } from "cloudflare:workers";
import type { Env, LabDb, Row, SqlParam } from "../env";
import { exercises } from "./registry";

/**
 * 学習者 1 人につき 1 つの SQLite 内蔵 Durable Object。
 *
 * - 脆弱版の SQL インジェクションで何を壊しても、影響はこの学習者のデータだけに閉じる。
 * - 最後の操作から LAB_TTL_HOURS 時間たつと alarm で全データを自動削除する。
 * - 演習の schema / seed が変わったら（デプロイ後の初回アクセスで）自動的に作り直す。
 */

const CORE_SCHEMA = [
  `CREATE TABLE lab_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE lab_progress (
     exercise_id TEXT PRIMARY KEY,
     attacked INTEGER NOT NULL DEFAULT 0,
     understood INTEGER NOT NULL DEFAULT 0
   )`,
];

function initStatements(): string[] {
  const stmts = [...CORE_SCHEMA];
  for (const ex of exercises) {
    stmts.push(...(ex.schema ?? []), ...(ex.seed ?? []));
  }
  return stmts;
}

/** FNV-1a。スキーマ変更の検出にだけ使う（セキュリティ用途ではない） */
function fingerprint(stmts: string[]): string {
  let h = 0x811c9dc5;
  for (const ch of stmts.join("\u0000")) {
    h ^= ch.codePointAt(0)!;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16);
}

export class LabDO extends DurableObject<Env> {
  private ready = false;
  private lastTouch = 0;

  private async ensureReady(): Promise<void> {
    if (this.ready) return;
    await this.ctx.blockConcurrencyWhile(async () => {
      if (this.ready) return;
      const sql = this.ctx.storage.sql;
      const stmts = initStatements();
      const want = fingerprint(stmts);
      let have: string | null = null;
      try {
        const rows = sql.exec("SELECT value FROM lab_meta WHERE key = 'schema'").toArray();
        have = rows.length ? String(rows[0].value) : null;
      } catch {
        have = null; // lab_meta がまだない
      }
      if (have !== want) {
        await this.wipe();
        for (const s of stmts) sql.exec(s).toArray();
        sql.exec("INSERT INTO lab_meta (key, value) VALUES ('schema', ?)", want).toArray();
      }
      this.ready = true;
    });
  }

  private async wipe(): Promise<void> {
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }

  /** 操作のたびに自動削除の期限を延ばす（書き込みを減らすため 1 分に 1 回だけ） */
  private async touch(): Promise<void> {
    const now = Date.now();
    if (now - this.lastTouch < 60_000) return;
    this.lastTouch = now;
    const hours = Number(this.env.LAB_TTL_HOURS) || 24;
    await this.ctx.storage.setAlarm(now + hours * 3600_000);
  }

  /** 全データを削除（TTL 切れ）。次のアクセスで初期状態から作り直される */
  async alarm(): Promise<void> {
    await this.wipe();
    this.ready = false;
    this.lastTouch = 0;
  }

  async all(sql: string, params: SqlParam[] = []): Promise<Row[]> {
    await this.ensureReady();
    await this.touch();
    return this.ctx.storage.sql.exec(sql, ...params).toArray() as Row[];
  }

  async run(sql: string, params: SqlParam[] = []): Promise<{ changes: number }> {
    await this.ensureReady();
    await this.touch();
    const cur = this.ctx.storage.sql.exec(sql, ...params);
    cur.toArray();
    return { changes: cur.rowsWritten };
  }

  /** 学習データを初期状態に戻す */
  async reset(): Promise<void> {
    await this.wipe();
    this.ready = false;
    this.lastTouch = 0;
    await this.ensureReady();
    await this.touch();
  }
}

export function dbClient(stub: DurableObjectStub<LabDO>): LabDb {
  return {
    all: async <T = Row>(sql: string, params: SqlParam[] = []) => (await stub.all(sql, params)) as unknown as T[],
    first: async <T = Row>(sql: string, params: SqlParam[] = []) =>
      ((await stub.all(sql, params))[0] as T | undefined) ?? null,
    run: (sql: string, params: SqlParam[] = []) => stub.run(sql, params),
    reset: () => stub.reset(),
  };
}
