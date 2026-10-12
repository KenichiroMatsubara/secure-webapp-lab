// cloudflare:workers の `env` / `exports.default` に型を付ける
import type { Env as LabEnv } from "../src/env";

declare global {
  namespace Cloudflare {
    interface Env extends LabEnv {}
    interface GlobalProps {
      mainModule: typeof import("../src/index");
      durableNamespaces: "LabDO";
    }
  }
}
export {};
