import { Hono } from "hono";
import type { AppEnv, Env } from "./env";
import { accessGate } from "./lab/access";
import { applyLabGuard } from "./lab/guard";
import { learnerContext } from "./lab/learner";
import { exercises } from "./lab/registry";
import { shell } from "./lab/shell";

// strict: false … /x/<id>/vuln と /x/<id>/vuln/ のどちらでも同じページを返す
const app = new Hono<AppEnv>({ strict: false });

// 1. Cloudflare Access の JWT 検証（本番は fail-closed）
app.use("*", accessGate());
// 2. 学習者ごとのDBを割り当てる
app.use("*", learnerContext());

app.route("/", shell);

for (const ex of exercises) {
  app.route(`/x/${ex.id}/vuln`, ex.vuln);
  app.route(`/x/${ex.id}/fixed`, ex.fixed);
  if (ex.attacker) app.route(`/attacker/${ex.id}`, ex.attacker);
}

app.notFound((c) => c.text("Not found", 404));

app.onError((err, c) => {
  console.error(err);
  return c.text(
    c.env.ENVIRONMENT === "development" ? `Internal error: ${err.message}` : "Internal error",
    500,
  );
});

export { app };
export { LabDO } from "./lab/db";

// ラボガード（CSP・リダイレクト制限・noindex）は、Access の拒否レスポンスも含めて全レスポンスの最も外側にかける
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return applyLabGuard(request, await app.fetch(request, env, ctx));
  },
} satisfies ExportedHandler<Env>;
