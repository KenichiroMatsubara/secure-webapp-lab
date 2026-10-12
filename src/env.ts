import type { LabDO } from "./lab/db";

/** wrangler.jsonc の bindings / vars に対応する型 */
export interface Env {
  LAB: DurableObjectNamespace<LabDO>;
  ENVIRONMENT: string;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  ALLOWED_EMAILS: string;
  LAB_TTL_HOURS: string;
  PBKDF2_ITERATIONS: string;
}

export type SqlParam = string | number | null;
export type Row = Record<string, string | number | null>;

/** 学習者ごとの SQLite（Durable Object）へのクライアント */
export interface LabDb {
  all<T = Row>(sql: string, params?: SqlParam[]): Promise<T[]>;
  first<T = Row>(sql: string, params?: SqlParam[]): Promise<T | null>;
  run(sql: string, params?: SqlParam[]): Promise<{ changes: number }>;
  /** 学習データを初期状態に戻す */
  reset(): Promise<void>;
}

export type AppEnv = {
  Bindings: Env;
  Variables: {
    db: LabDb;
    /** Cloudflare Access で認証されたメールアドレス（ローカル開発では null） */
    accessEmail: string | null;
    /** 学習者キー（Access のメールのハッシュ、またはローカルの lab_id Cookie） */
    learner: string;
    /** この接続で SameSite=None; Secure の Cookie を使ってよいか（https または localhost） */
    crossSiteCookies: boolean;
  };
};
