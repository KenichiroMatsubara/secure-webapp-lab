import { exports } from "cloudflare:workers";

/**
 * テスト用の簡易ブラウザ。Cookie を覚えて、リダイレクトは手動で追う。
 * Cookie の Path / Domain は無視する（演習ごとに Cookie 名を変えてあるので衝突しない）。
 */
export class Browser {
  jar = new Map<string, string>();
  constructor(public base = "http://lab.test") {}

  private store(res: Response) {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(";").map((s) => s.trim());
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq);
      const value = pair.slice(eq + 1);
      const maxAge = attrs.find((a) => /^max-age=/i.test(a));
      if (value === "" || (maxAge && Number(maxAge.split("=")[1]) <= 0)) this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  cookie(name: string): string | undefined {
    return this.jar.get(name);
  }

  async request(path: string, init: RequestInit & { headers?: Record<string, string> } = {}): Promise<Response> {
    const headers: Record<string, string> = { ...(init.headers ?? {}) };
    if (this.jar.size && !("Cookie" in headers)) {
      headers["Cookie"] = [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
    }
    const url = path.startsWith("http") ? path : this.base + path;
    const res = await exports.default.fetch(url, { redirect: "manual", ...init, headers });
    this.store(res);
    return res;
  }

  get(path: string, headers: Record<string, string> = {}) {
    return this.request(path, { headers });
  }

  /** application/x-www-form-urlencoded の POST。同一オリジンからの送信として Sec-Fetch-Site を付ける */
  post(path: string, form: Record<string, string> = {}, headers: Record<string, string> = {}) {
    return this.request(path, {
      method: "POST",
      body: new URLSearchParams(form).toString(),
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Sec-Fetch-Site": "same-origin",
        ...headers,
      },
    });
  }

  async text(path: string): Promise<string> {
    return (await this.get(path)).text();
  }
}
