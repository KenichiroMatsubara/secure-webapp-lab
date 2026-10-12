/**
 * 擬似シェル（OS コマンドインジェクションの演習用）。
 *
 * 実際のシェルやコマンドは一切呼ばない。文字列を解析して、用意したダミーのコマンドを JavaScript で「実行したふり」をするだけ。
 * Cloudflare Workers にはシェルがないので、同じ原理（文字列連結 → シェルが解釈）を純粋な JavaScript で再現している。
 *
 * 対応する文法（POSIX sh のごく一部）:
 *   - 区切り   ; & 改行 / && / || / パイプ |
 *   - 展開     $(...) と `...`（入れ子可）、$VAR ${VAR} $?
 *   - 引用     '...'（何も展開しない）、"..."（$ と ` だけ展開、語分割しない）、バックスラッシュ
 *   - その他   # コメント、リダイレクト（> >> < 2> 2>&1）は解釈するが、/dev/null 以外へは書かない
 *
 * 対応するコマンド: ping echo cat ls whoami id pwd uname env cd。rm など破壊的なものは「実行しません」と表示するだけ。
 *
 * 暴走を防ぐ上限（ShellLimits）: コマンドラインの長さ、$( ) の入れ子の深さ、実行するコマンド数、出力の大きさ。
 */
import { labVfs, resolvePath, type Vfs } from "./vfs";

export interface ShellLimits {
  /** コマンドラインの最大文字数 */
  maxLineLength: number;
  /** $( ) / バッククォートの入れ子の最大の深さ */
  maxDepth: number;
  /** 1 回の run で実行するコマンドの最大数（$( ) の中も数える） */
  maxCommands: number;
  /** 出力の最大文字数（$( ) で取り込む文字列にも適用） */
  maxOutput: number;
}

export const DEFAULT_LIMITS: ShellLimits = { maxLineLength: 1000, maxDepth: 4, maxCommands: 50, maxOutput: 8192 };

export interface ExecutedCommand {
  argv: string[];
  exitCode: number;
}

export interface ShellResult {
  /** 画面に出る出力（標準出力と標準エラーを実行順に並べたもの） */
  output: string;
  exitCode: number;
  /** 実際に実行された（ように扱われた）コマンド。$( ) の中身は外側より先に並ぶ */
  executed: ExecutedCommand[];
  /** 構文エラーの内容（実行は一切しない）。なければ null */
  syntaxError: string | null;
  /** 上限に達して打ち切った理由。なければ null */
  limitReason: string | null;
}

export const NOT_EXECUTED = "(擬似環境のため実行しません)";

// ---------------------------------------------------------------- 構文木

type DqPart = { t: "lit"; s: string } | { t: "sub"; list: ListNode } | { t: "var"; name: string };
type Seg =
  | { t: "lit"; s: string }
  | { t: "sq"; s: string }
  | { t: "dq"; parts: DqPart[] }
  | { t: "sub"; list: ListNode }
  | { t: "var"; name: string };

interface Word {
  segs: Seg[];
}

interface Redir {
  op: ">" | ">>" | "<";
  fd: number | null;
  target: Word | null;
  /** `>&2` のような複製の宛先 */
  dupTo: number | null;
}

interface SimpleCmd {
  words: Word[];
  redirs: Redir[];
}

type Pipeline = SimpleCmd[];

interface ListNode {
  first: Pipeline;
  rest: { op: ";" | "&&" | "||"; pipeline: Pipeline }[];
}

class SyntaxErr extends Error {}
class LimitErr extends Error {}

const BLANK = new Set([" ", "\t"]);
const WORD_STOP = new Set([" ", "\t", "\n", ";", "&", "|", "<", ">", "(", ")"]);

// ---------------------------------------------------------------- パーサー

class Parser {
  private i = 0;

  constructor(
    private src: string,
    private depth: number,
    private lim: ShellLimits,
  ) {}

  /** 入力全体を 1 つのコマンド列として解析する */
  parseTop(): ListNode {
    const list = this.parseList(null);
    if (this.i < this.src.length) throw new SyntaxErr(this.unexpected());
    return list;
  }

  private peek(o = 0): string {
    return this.src[this.i + o] ?? "";
  }

  private eof(): boolean {
    return this.i >= this.src.length;
  }

  private unexpected(): string {
    if (this.eof()) return "syntax error: unexpected end of file";
    const c = this.peek();
    const tok = c === "\n" ? "newline" : c === "&" && this.peek(1) === "&" ? "&&" : c === "|" && this.peek(1) === "|" ? "||" : c;
    return `syntax error near unexpected token \`${tok}'`;
  }

  private skipBlank(): void {
    while (BLANK.has(this.peek())) this.i++;
    // 単語の先頭にある # から行末まではコメント
    if (this.peek() === "#") while (!this.eof() && this.peek() !== "\n") this.i++;
  }

  private skipBlankAndNewlines(): void {
    for (;;) {
      this.skipBlank();
      if (this.peek() === "\n") this.i++;
      else return;
    }
  }

  private parseList(term: ")" | null): ListNode {
    this.skipBlankAndNewlines();
    if (this.eof() || (term !== null && this.peek() === term)) return { first: [], rest: [] };
    const first = this.parsePipeline();
    const rest: ListNode["rest"] = [];
    for (;;) {
      this.skipBlank();
      if (this.eof() || (term !== null && this.peek() === term)) break;
      const op = this.readListOp();
      if (op === null) throw new SyntaxErr(this.unexpected());
      this.skipBlankAndNewlines();
      if (this.eof() || (term !== null && this.peek() === term)) {
        if (op === ";") break; // 行末の ; は許される
        throw new SyntaxErr(this.unexpected());
      }
      rest.push({ op, pipeline: this.parsePipeline() });
    }
    return { first, rest };
  }

  private readListOp(): ";" | "&&" | "||" | null {
    const c = this.peek();
    if (c === ";") {
      this.i++;
      return ";";
    }
    if (c === "\n") {
      this.i++;
      return ";";
    }
    if (c === "&") {
      if (this.peek(1) === "&") {
        this.i += 2;
        return "&&";
      }
      this.i++; // バックグラウンド実行 → 擬似環境では順番に実行する
      return ";";
    }
    if (c === "|" && this.peek(1) === "|") {
      this.i += 2;
      return "||";
    }
    return null;
  }

  private parsePipeline(): Pipeline {
    const cmds: SimpleCmd[] = [this.parseCommand()];
    for (;;) {
      this.skipBlank();
      if (this.peek() === "|" && this.peek(1) !== "|") {
        this.i++;
        this.skipBlankAndNewlines();
        cmds.push(this.parseCommand());
      } else return cmds;
    }
  }

  private parseCommand(): SimpleCmd {
    const words: Word[] = [];
    const redirs: Redir[] = [];
    for (;;) {
      this.skipBlank();
      const c = this.peek();
      if (c === "" || c === "\n" || c === ";" || c === "&" || c === "|" || c === ")") break;
      if (c === "(") throw new SyntaxErr(this.unexpected());
      if (c === "<" || c === ">") {
        redirs.push(this.parseRedirect(null));
        continue;
      }
      // `2>` のように、数字だけの語の直後に < > が続けばファイル記述子の指定
      const m = /^\d+/.exec(this.src.slice(this.i));
      if (m && (this.src[this.i + m[0].length] === ">" || this.src[this.i + m[0].length] === "<")) {
        this.i += m[0].length;
        redirs.push(this.parseRedirect(Number(m[0])));
        continue;
      }
      words.push(this.parseWord());
    }
    if (words.length === 0 && redirs.length === 0) throw new SyntaxErr(this.unexpected());
    return { words, redirs };
  }

  private parseRedirect(fd: number | null): Redir {
    const c = this.peek();
    if (c === "<" && this.peek(1) === "<") throw new SyntaxErr("ヒアドキュメント（<<）は擬似シェルでは未対応です");
    const op: Redir["op"] = c === "<" ? "<" : this.peek(1) === ">" ? ">>" : ">";
    this.i += op.length;
    if (op !== "<" && this.peek() === "&" && /\d/.test(this.peek(1))) {
      this.i++;
      let n = "";
      while (/\d/.test(this.peek())) n += this.src[this.i++];
      return { op, fd, target: null, dupTo: Number(n) };
    }
    this.skipBlank();
    if (this.eof() || WORD_STOP.has(this.peek())) throw new SyntaxErr(this.unexpected());
    return { op, fd, target: this.parseWord(), dupTo: null };
  }

  private enter(): void {
    this.depth++;
    if (this.depth > this.lim.maxDepth) {
      throw new SyntaxErr(`コマンド置換の入れ子が深すぎます（上限 ${this.lim.maxDepth}）`);
    }
  }

  private parseWord(): Word {
    const segs: Seg[] = [];
    let lit = "";
    const flush = () => {
      if (lit) segs.push({ t: "lit", s: lit });
      lit = "";
    };
    while (!this.eof()) {
      const c = this.peek();
      if (WORD_STOP.has(c)) break;
      if (c === "\\") {
        const n = this.peek(1);
        if (n === "") {
          lit += "\\";
          this.i++;
        } else if (n === "\n") this.i += 2; // 行継続
        else {
          lit += n;
          this.i += 2;
        }
      } else if (c === "'") {
        const end = this.src.indexOf("'", this.i + 1);
        if (end === -1) throw new SyntaxErr("syntax error: unterminated quoted string (')");
        flush();
        segs.push({ t: "sq", s: this.src.slice(this.i + 1, end) });
        this.i = end + 1;
      } else if (c === '"') {
        flush();
        segs.push(this.parseDouble());
      } else if (c === "$") {
        const d = this.parseDollar();
        if (d === null) {
          lit += "$";
          this.i++;
        } else {
          flush();
          segs.push(d);
        }
      } else if (c === "`") {
        flush();
        segs.push({ t: "sub", list: this.parseBackticks() });
      } else {
        lit += c;
        this.i++;
      }
    }
    flush();
    return { segs };
  }

  private parseDouble(): Seg {
    this.i++; // 開きの "
    const parts: DqPart[] = [];
    let lit = "";
    const flush = () => {
      if (lit) parts.push({ t: "lit", s: lit });
      lit = "";
    };
    for (;;) {
      if (this.eof()) throw new SyntaxErr('syntax error: unterminated quoted string (")');
      const c = this.peek();
      if (c === '"') {
        this.i++;
        break;
      }
      if (c === "\\") {
        const n = this.peek(1);
        if (n === "$" || n === "`" || n === '"' || n === "\\") {
          lit += n;
          this.i += 2;
        } else if (n === "\n") this.i += 2;
        else {
          lit += "\\";
          this.i++;
        }
      } else if (c === "$") {
        const d = this.parseDollar();
        if (d === null) {
          lit += "$";
          this.i++;
        } else {
          flush();
          parts.push(d as DqPart);
        }
      } else if (c === "`") {
        flush();
        parts.push({ t: "sub", list: this.parseBackticks() });
      } else {
        lit += c;
        this.i++;
      }
    }
    flush();
    return { t: "dq", parts };
  }

  /** `$` から始まる展開。展開にならない `$`（行末や記号の前）は null を返す（呼び出し側が文字として扱う） */
  private parseDollar(): { t: "sub"; list: ListNode } | { t: "var"; name: string } | null {
    const n = this.peek(1);
    if (n === "(") {
      this.i += 2;
      this.enter();
      const list = this.parseList(")");
      if (this.peek() !== ")") throw new SyntaxErr("syntax error: unexpected end of file (`)' が見つかりません)");
      this.i++;
      this.depth--;
      return { t: "sub", list };
    }
    if (n === "{") {
      const end = this.src.indexOf("}", this.i + 2);
      const name = end === -1 ? "" : this.src.slice(this.i + 2, end);
      if (end === -1 || !/^([A-Za-z_][A-Za-z0-9_]*|\?)$/.test(name)) throw new SyntaxErr("syntax error: bad substitution");
      this.i = end + 1;
      return { t: "var", name };
    }
    if (n === "?") {
      this.i += 2;
      return { t: "var", name: "?" };
    }
    const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(this.src.slice(this.i + 1));
    if (m) {
      this.i += 1 + m[0].length;
      return { t: "var", name: m[0] };
    }
    if (/\d/.test(n)) {
      this.i += 2; // $0〜$9（位置パラメータ）は空
      return { t: "var", name: "" };
    }
    return null;
  }

  private parseBackticks(): ListNode {
    let j = this.i + 1;
    let inner = "";
    for (;;) {
      if (j >= this.src.length) throw new SyntaxErr("syntax error: unterminated quoted string (`)");
      const c = this.src[j];
      if (c === "`") break;
      if (c === "\\" && /[$`\\]/.test(this.src[j + 1] ?? "")) {
        inner += this.src[j + 1];
        j += 2;
        continue;
      }
      inner += c;
      j++;
    }
    this.i = j + 1;
    this.enter();
    const sub = new Parser(inner, this.depth, this.lim).parseTop();
    this.depth--;
    return sub;
  }
}

// ---------------------------------------------------------------- 実行

const ENV: Record<string, string> = {
  APP_ENV: "lab",
  API_KEY: "lab-fake-api-key-0000",
  DB_PASSWORD: "lab-fake-password",
  HOME: "/home/labuser",
  HOSTNAME: "lab-sandbox",
  LANG: "C.UTF-8",
  PATH: "/usr/local/bin:/usr/bin:/bin",
  PWD: "/app",
  SESSION_SECRET: "lab-fake-session-secret",
  SHELL: "/bin/sh",
  USER: "labuser",
};

/** 実行せずに「実行しません」と表示するだけのコマンド（破壊的、またはネットワーク・別プロセスに関わるもの） */
const BLOCKED = new Set([
  "rm", "rmdir", "mv", "cp", "ln", "dd", "mkdir", "touch", "chmod", "chown", "tee", "kill", "pkill", "shutdown", "reboot",
  "sleep", "curl", "wget", "nc", "ncat", "telnet", "ssh", "scp", "sudo", "su", "bash", "sh", "zsh", "python", "python3",
  "perl", "ruby", "node", "php", "tar", "git", "crontab",
]);

const HOSTS: Record<string, string> = {
  "example.com": "192.0.2.10",
  "www.example.com": "192.0.2.10",
  localhost: "127.0.0.1",
  "127.0.0.1": "127.0.0.1",
};

interface CmdResult {
  stdout: string;
  stderr: string;
  code: number;
}

const ok = (stdout: string): CmdResult => ({ stdout, stderr: "", code: 0 });
const fail = (stderr: string, code = 1): CmdResult => ({ stdout: "", stderr, code });

/** 値に空白や記号があるときだけ '...' で囲む（表示用） */
export function shellQuote(arg: string): string {
  if (arg === "") return "''";
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** PHP の escapeshellarg 相当。常に '...' で囲み、中の ' を '\'' にする。シェルへ渡す1つの引数として安全にするための道具 */
export function escapeShellArg(arg: string): string {
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** argv を読みやすい 1 行にする（表示用） */
export function formatCommand(argv: string[]): string {
  return argv.map(shellQuote).join(" ");
}

class Interp {
  steps = 0;
  out: string[] = [];
  outLen = 0;
  executed: ExecutedCommand[] = [];
  lastStatus = 0;
  cwd = "/app";

  constructor(
    private vfs: Vfs,
    private lim: ShellLimits,
  ) {}

  // ---- 出力

  /** 画面への出力。上限を超えたら、入る分だけ出して打ち切る */
  emit(s: string): void {
    if (!s) return;
    const room = this.lim.maxOutput - this.outLen;
    if (s.length > room) {
      if (room > 0) this.out.push(s.slice(0, room));
      this.outLen = this.lim.maxOutput;
      throw new LimitErr(`出力が ${this.lim.maxOutput} 文字の上限を超えた`);
    }
    this.out.push(s);
    this.outLen += s.length;
  }

  private step(): void {
    if (++this.steps > this.lim.maxCommands) {
      throw new LimitErr(`実行するコマンドが ${this.lim.maxCommands} 個の上限を超えた`);
    }
  }

  // ---- 構文木の実行

  runList(list: ListNode, sink: (s: string) => void): number {
    if (list.first.length === 0) return (this.lastStatus = 0);
    let code = this.runPipeline(list.first, sink);
    for (const { op, pipeline } of list.rest) {
      if (op === ";" || (op === "&&" && code === 0) || (op === "||" && code !== 0)) {
        code = this.runPipeline(pipeline, sink);
      }
    }
    return code;
  }

  private runPipeline(p: Pipeline, sink: (s: string) => void): number {
    let stdin = "";
    let code = 0;
    for (let k = 0; k < p.length; k++) {
      const r = this.runSimple(p[k], stdin);
      code = r.code;
      if (k === p.length - 1) sink(r.stdout);
      else stdin = r.stdout;
    }
    return (this.lastStatus = code);
  }

  /** `$(...)` の実行結果（標準出力）。末尾の改行は取り除く */
  private runSub(list: ListNode): string {
    let buf = "";
    const saved = this.lastStatus;
    this.runList(list, (s) => {
      buf += s;
      if (buf.length > this.lim.maxOutput) throw new LimitErr(`コマンド置換の出力が ${this.lim.maxOutput} 文字の上限を超えた`);
    });
    this.lastStatus = saved;
    return buf.replace(/\n+$/, "");
  }

  private variable(name: string): string {
    if (name === "?") return String(this.lastStatus);
    return Object.hasOwn(ENV, name) ? ENV[name] : "";
  }

  /** 語の展開。引用符の外の展開結果だけが空白で分割される（"$(…)" は分割されない） */
  private expandWord(w: Word): string[] {
    const fields: string[] = [];
    let cur: string | null = null;
    const addSplit = (text: string) => {
      text.split(/[ \t\n]+/).forEach((part, idx) => {
        if (idx > 0) {
          if (cur !== null) fields.push(cur);
          cur = null;
        }
        if (part !== "") cur = (cur ?? "") + part;
      });
    };
    for (const seg of w.segs) {
      if (seg.t === "lit" || seg.t === "sq") cur = (cur ?? "") + seg.s;
      else if (seg.t === "dq") {
        let s = "";
        for (const p of seg.parts) s += p.t === "lit" ? p.s : p.t === "var" ? this.variable(p.name) : this.runSub(p.list);
        cur = (cur ?? "") + s;
      } else if (seg.t === "var") addSplit(this.variable(seg.name));
      else addSplit(this.runSub(seg.list));
    }
    if (cur !== null) fields.push(cur);
    return fields;
  }

  private runSimple(cmd: SimpleCmd, stdinIn: string): CmdResult {
    const argv = cmd.words.flatMap((w) => this.expandWord(w));
    let stdin = stdinIn;
    let discardOut = false;
    let discardErr = false;
    let errToOut = false;
    let outToErr = false;
    const notes: string[] = [];

    for (const r of cmd.redirs) {
      const fd = r.fd ?? (r.op === "<" ? 0 : 1);
      if (r.dupTo !== null) {
        if (fd === 2 && r.dupTo === 1) errToOut = true;
        if (fd === 1 && r.dupTo === 2) outToErr = true;
        continue;
      }
      const target = this.expandWord(r.target!)[0] ?? "";
      if (r.op === "<") {
        const f = this.vfs.read(resolvePath(this.cwd, target));
        if (!f.ok) {
          this.emit(`sh: 1: cannot open ${target}: No such file\n`);
          return fail("", 2);
        }
        stdin = f.content;
      } else if (target === "/dev/null") {
        if (fd === 2) discardErr = true;
        else discardOut = true;
      } else {
        notes.push(`sh: ${target}: ${NOT_EXECUTED.slice(1, -1)}（ファイルへは書き込みません）\n`);
        if (fd === 2) discardErr = true;
        else discardOut = true;
      }
    }

    let res: CmdResult;
    if (argv.length === 0) res = ok("");
    else {
      this.step();
      res = this.builtin(argv, stdin);
      this.executed.push({ argv, exitCode: res.code });
    }

    let stdout = res.stdout;
    let stderr = res.stderr;
    if (errToOut) {
      stdout += stderr;
      stderr = "";
    }
    if (outToErr) {
      stderr += stdout;
      stdout = "";
    }
    if (discardOut) stdout = "";
    if (discardErr) stderr = "";
    this.emit(stderr + notes.join(""));
    return { stdout, stderr: "", code: res.code };
  }

  // ---- コマンド

  /** 1 つのコマンドを argv のまま実行する（シェルの解釈なし） */
  builtin(argv: string[], stdin: string): CmdResult {
    const raw = argv[0];
    const m = /^\/(?:usr\/)?(?:local\/)?s?bin\/([^/]+)$/.exec(raw);
    const name = m ? m[1] : raw;
    const args = argv.slice(1);
    switch (name) {
      case "echo":
        return this.echo(args);
      case "cat":
        return this.cat(args, stdin);
      case "ls":
        return this.ls(args);
      case "ping":
        return this.ping(args);
      case "whoami":
        return ok("labuser\n");
      case "id":
        return ok("uid=1000(labuser) gid=1000(labuser) groups=1000(labuser)\n");
      case "pwd":
        return ok(this.cwd + "\n");
      case "uname":
        return this.uname(args);
      case "env":
        return args.length ? ok(`env: ${NOT_EXECUTED}\n`) : ok(Object.entries(ENV).map(([k, v]) => `${k}=${v}\n`).join(""));
      case "cd":
        return this.cd(args);
      default:
        if (BLOCKED.has(name)) return ok(`${name}: ${NOT_EXECUTED}\n`);
        return fail(`sh: 1: ${raw}: not found\n`, 127);
    }
  }

  private echo(args: string[]): CmdResult {
    let nl = true;
    let a = args;
    while (a.length && /^-[neE]+$/.test(a[0])) {
      if (a[0].includes("n")) nl = false;
      a = a.slice(1);
    }
    return ok(a.join(" ") + (nl ? "\n" : ""));
  }

  private cat(args: string[], stdin: string): CmdResult {
    const files: string[] = [];
    let endOpts = false;
    for (const a of args) {
      if (!endOpts && a === "--") endOpts = true;
      else if (!endOpts && a.startsWith("-") && a !== "-") return fail(`cat: invalid option -- '${a.replace(/^-+/, "")[0] ?? ""}'\n`, 1);
      else files.push(a);
    }
    if (files.length === 0) return ok(stdin);
    let stdout = "";
    let stderr = "";
    let code = 0;
    for (const f of files) {
      if (f === "-") {
        stdout += stdin;
        continue;
      }
      const r = this.vfs.read(resolvePath(this.cwd, f));
      if (r.ok) stdout += r.content;
      else {
        code = 1;
        const why = r.code === "ENOENT" ? "No such file or directory" : r.code === "EISDIR" ? "Is a directory" : "Invalid argument";
        stderr += `cat: ${f}: ${why}\n`;
      }
    }
    return { stdout, stderr, code };
  }

  private ls(args: string[]): CmdResult {
    let long = false;
    let all = false;
    const paths: string[] = [];
    let endOpts = false;
    for (const a of args) {
      if (!endOpts && a === "--") endOpts = true;
      else if (!endOpts && a.startsWith("-") && a.length > 1) {
        for (const ch of a.slice(1)) {
          if (ch === "l") long = true;
          else if (ch === "a") all = true;
          else if (!"1hF".includes(ch)) return fail(`ls: invalid option -- '${ch}'\n`, 2);
        }
      } else paths.push(a);
    }
    if (paths.length === 0) paths.push(".");
    let stdout = "";
    let stderr = "";
    let code = 0;
    const row = (name: string, dir: boolean, size: number) =>
      long ? `${dir ? "drwxr-xr-x 2" : "-rw-r--r-- 1"} labuser labuser ${String(dir ? 4096 : size).padStart(5)} Jan  1 00:00 ${name}\n` : `${name}\n`;
    paths.forEach((p, idx) => {
      const abs = resolvePath(this.cwd, p);
      const names = this.vfs.list(abs);
      if (names) {
        if (paths.length > 1) stdout += (idx > 0 ? "\n" : "") + `${p}:\n`;
        const entries = all ? [".", "..", ...names] : names;
        for (const n of entries) {
          const child = abs === "/" ? "/" + n : abs + "/" + n;
          stdout += row(n, n === "." || n === ".." || this.vfs.isDir(child), this.vfs.size(child));
        }
      } else if (this.vfs.isFile(abs)) stdout += row(p, false, this.vfs.size(abs));
      else {
        code = 2;
        stderr += `ls: cannot access '${p}': No such file or directory\n`;
      }
    });
    return { stdout, stderr, code };
  }

  private uname(args: string[]): CmdResult {
    if (args.includes("-a")) return ok("Linux lab-sandbox 6.1.0-lab #1 SMP x86_64 GNU/Linux\n");
    if (args.includes("-r")) return ok("6.1.0-lab\n");
    if (args.includes("-m")) return ok("x86_64\n");
    return ok("Linux\n");
  }

  private cd(args: string[]): CmdResult {
    const target = resolvePath(this.cwd, args[0] ?? "/home/labuser");
    if (!this.vfs.isDir(target)) return fail(`sh: 1: cd: can't cd to ${args[0] ?? ""}\n`, 2);
    this.cwd = target;
    return ok("");
  }

  private ping(args: string[]): CmdResult {
    const usage = "Usage: ping [-c count] [-q] [-n] destination\n";
    let count = 4;
    const hosts: string[] = [];
    let endOpts = false;
    for (let k = 0; k < args.length; k++) {
      const a = args[k];
      if (endOpts || !a.startsWith("-") || a === "-") {
        hosts.push(a);
        continue;
      }
      if (a === "--") {
        endOpts = true;
        continue;
      }
      if (a.startsWith("--")) return fail(`ping: unrecognized option '${a}'\n${usage}`, 2);
      const flag = a[1];
      if ("qn46v".includes(flag) && a.length === 2) continue;
      if ("cwWis".includes(flag)) {
        const val = a.length > 2 ? a.slice(2) : (args[++k] ?? "");
        if (flag === "c") {
          if (!/^\d+$/.test(val) || Number(val) < 1) return fail(`ping: invalid argument: '${val}'\n`, 2);
          count = Number(val);
        } else if (!/^\d+$/.test(val)) return fail(`ping: invalid argument: '${val}'\n`, 2);
        continue;
      }
      if (flag === "f") return fail("ping: flood ping is only available to root（擬似環境）\n", 2);
      return fail(`ping: invalid option -- '${flag}'\n${usage}`, 2);
    }
    if (hosts.length === 0) return fail(`ping: usage error: Destination address required\n${usage}`, 2);

    let stdout = "";
    let stderr = "";
    let code = 0;
    for (const host of hosts) {
      const ip = Object.hasOwn(HOSTS, host.toLowerCase()) ? HOSTS[host.toLowerCase()] : undefined;
      if (!ip) {
        stderr += `ping: unknown host ${host}\n`;
        code = 2;
        continue;
      }
      const shown = Math.min(count, 4);
      stdout += `PING ${host} (${ip}) 56(84) bytes of data.\n`;
      for (let n = 1; n <= shown; n++) stdout += `64 bytes from ${ip}: icmp_seq=${n} ttl=64 time=0.${40 + n} ms\n`;
      if (count > shown) stdout += `(擬似環境のため ${shown} 回分だけ表示します。実際の ping なら約 ${count - 1} 秒かかります)\n`;
      stdout += `\n--- ${host} ping statistics ---\n${count} packets transmitted, ${count} received, 0% packet loss, time ${(count - 1) * 1000}ms\n`;
    }
    return { stdout, stderr, code };
  }
}

export class FakeShell {
  private vfs: Vfs;
  private lim: ShellLimits;

  constructor(opts: { vfs?: Vfs; limits?: Partial<ShellLimits> } = {}) {
    this.vfs = opts.vfs ?? labVfs;
    this.lim = { ...DEFAULT_LIMITS, ...opts.limits };
  }

  private finish(it: Interp, exitCode: number, syntaxError: string | null, limitReason: string | null): ShellResult {
    let output = it.out.join("");
    if (limitReason) output += `${output && !output.endsWith("\n") ? "\n" : ""}[擬似シェル] ${limitReason}ため、実行を打ち切りました\n`;
    if (syntaxError) output = `sh: 1: ${syntaxError}\n`;
    return { output, exitCode, executed: it.executed, syntaxError, limitReason };
  }

  /** シェルに 1 行を渡して実行する（`sh -c "<line>"` の模擬）。ここが「文字列をシェルが解釈する」危険な入口 */
  run(commandLine: string): ShellResult {
    const it = new Interp(this.vfs, this.lim);
    if (commandLine.length > this.lim.maxLineLength) {
      return this.finish(it, 2, `コマンドラインが長すぎます（上限 ${this.lim.maxLineLength} 文字）`, null);
    }
    let list: ListNode;
    try {
      list = new Parser(commandLine, 0, this.lim).parseTop();
    } catch (e) {
      if (e instanceof SyntaxErr) return this.finish(it, 2, e.message, null);
      throw e;
    }
    try {
      const code = it.runList(list, (s) => it.emit(s));
      return this.finish(it, code, null, null);
    } catch (e) {
      if (e instanceof LimitErr) return this.finish(it, 1, null, e.message);
      throw e;
    }
  }

  /**
   * argv をそのまま 1 つのコマンドとして実行する（`execFile` の模擬）。シェルを通さないので、
   * 引数に `;` `$(...)` などが入っていても、ただの文字列として渡るだけ。
   */
  execFile(argv: string[]): ShellResult {
    const it = new Interp(this.vfs, this.lim);
    if (argv.length === 0) return this.finish(it, 2, "実行するコマンドがありません", null);
    try {
      it.steps = 1;
      const r = it.builtin(argv, "");
      it.executed.push({ argv, exitCode: r.code });
      it.emit(r.stderr);
      it.emit(r.stdout);
      return this.finish(it, r.code, null, null);
    } catch (e) {
      if (e instanceof LimitErr) return this.finish(it, 1, null, e.message);
      throw e;
    }
  }
}
