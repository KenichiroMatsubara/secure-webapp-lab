import { describe, expect, it } from "vitest";
import { FakeShell, escapeShellArg, formatCommand, shellQuote } from "../src/lab/fakeshell";

const sh = new FakeShell();
const argvs = (line: string) => sh.run(line).executed.map((e) => e.argv);

describe("擬似シェル: 基本のコマンド", () => {
  it("echo / pwd / whoami / id / uname はダミーの固定出力を返す", () => {
    expect(sh.run("echo hello  world").output).toBe("hello world\n");
    expect(sh.run("echo -n hi").output).toBe("hi");
    expect(sh.run("pwd").output).toBe("/app\n");
    expect(sh.run("whoami").output).toBe("labuser\n");
    expect(sh.run("id").output).toContain("uid=1000(labuser)");
    expect(sh.run("uname -a").output).toContain("Linux lab-sandbox");
  });

  it("env にはダミーの秘密が並ぶ（実在の値ではない）", () => {
    const out = sh.run("env").output;
    expect(out).toContain("DB_PASSWORD=lab-fake-password");
    expect(out).toContain("USER=labuser");
  });

  it("cat / ls は仮想ファイルシステムを読む", () => {
    expect(sh.run("cat /app/config/secrets.env").output).toContain("DB_PASSWORD=lab-fake-password");
    expect(sh.run("cat /etc/passwd").output).toContain("labuser:x:1000");
    expect(sh.run("ls /app").output).toBe("config\npublic\nsrc\n");
    expect(sh.run("ls /app/public/docs").output).toBe("guide.txt\nreadme.txt\n");
    expect(sh.run("ls -l /app/config").output).toContain("secrets.env");
    expect(sh.run("cat ../etc/passwd").output).toContain("root:x:0:0"); // cwd は /app
  });

  it("存在しないファイル・コマンドはエラーと終了コード", () => {
    const r = sh.run("cat /nope");
    expect(r.output).toBe("cat: /nope: No such file or directory\n");
    expect(r.exitCode).toBe(1);
    const u = sh.run("frobnicate --now");
    expect(u.output).toContain("frobnicate: not found");
    expect(u.exitCode).toBe(127);
    expect(sh.run("cat /app").output).toContain("Is a directory");
    expect(sh.run("ls /nope").exitCode).toBe(2);
  });

  it("絶対パスで呼んだ /bin/ls なども同じコマンドとして扱う", () => {
    expect(sh.run("/bin/ls /app").output).toContain("config");
    expect(sh.run("/tmp/evil").exitCode).toBe(127);
  });

  it("cd は同じ行の後続コマンドの作業ディレクトリを変える", () => {
    expect(sh.run("cd /app/config && pwd && ls").output).toBe("/app/config\nsecrets.env\n");
    expect(sh.run("cd /nope").exitCode).toBe(2);
  });

  it("prototype のプロパティ名（constructor など）を環境変数やホスト名として引かない", () => {
    expect(sh.run("echo [$constructor]").output).toBe("[]\n");
    expect(sh.run("ping -c 1 constructor").output).toContain("unknown host constructor");
    expect(sh.run("ping -c 1 __proto__").output).toContain("unknown host");
  });
});

describe("擬似シェル: ping", () => {
  it("example.com と localhost だけ成功する", () => {
    const ok1 = sh.run("ping -c 1 example.com");
    expect(ok1.exitCode).toBe(0);
    expect(ok1.output).toContain("PING example.com (192.0.2.10)");
    expect(ok1.output).toContain("1 packets transmitted, 1 received");
    expect(sh.run("ping -c 1 localhost").output).toContain("127.0.0.1");
  });

  it("それ以外のホストは unknown host", () => {
    const r = sh.run("ping -c 1 nothere.example");
    expect(r.exitCode).toBe(2);
    expect(r.output).toBe("ping: unknown host nothere.example\n");
  });

  it("引数のエラー: ホストなし・不正な回数・不明なオプション", () => {
    expect(sh.run("ping").output).toContain("Destination address required");
    expect(sh.run("ping -c abc localhost").output).toContain("invalid argument: 'abc'");
    expect(sh.run("ping -c 0 localhost").exitCode).toBe(2);
    expect(sh.run("ping -x localhost").output).toContain("invalid option -- 'x'");
    expect(sh.run("ping --foo localhost").output).toContain("unrecognized option '--foo'");
  });

  it("-c の値は後ろのものが勝つ（引数インジェクションで回数を書き換えられる）", () => {
    const r = sh.run("ping -c 1 -c 5000 localhost");
    expect(r.output).toContain("5000 packets transmitted");
    expect(r.output).toContain("約 4999 秒");
    // 画面に出す行数は上限がある
    expect(r.output.split("\n").filter((l) => l.startsWith("64 bytes")).length).toBe(4);
  });

  it("-- 以降はオプションとして解釈しない（ホスト名として扱う）", () => {
    const r = sh.run("ping -c 1 -- -c");
    expect(r.output).toBe("ping: unknown host -c\n");
  });
});

describe("擬似シェル: メタ文字", () => {
  it("; は前のコマンドの結果によらず次を実行する", () => {
    expect(argvs("false-cmd; echo b")).toEqual([["false-cmd"], ["echo", "b"]]);
    const r = sh.run("ping -c 1 localhost; cat /app/config/secrets.env");
    expect(r.output).toContain("PING localhost");
    expect(r.output).toContain("DB_PASSWORD=lab-fake-password");
  });

  it("&& は直前が成功したときだけ、|| は失敗したときだけ次を実行する", () => {
    expect(argvs("ping -c 1 localhost && id")).toHaveLength(2);
    expect(argvs("ping -c 1 nothere.example && id")).toHaveLength(1);
    expect(argvs("ping -c 1 nothere.example || id")).toHaveLength(2);
    expect(argvs("ping -c 1 localhost || id")).toHaveLength(1);
    // a || b && c は左結合: a が成功なら b は飛ばして c を実行
    expect(argvs("echo a || echo b && echo c").map((a) => a[1])).toEqual(["a", "c"]);
    // a && b || c: a が失敗なら b を飛ばして c
    expect(argvs("nope && echo b || echo c").map((a) => a[0])).toEqual(["nope", "echo"]);
  });

  it("| は左の標準出力を右の標準入力につなぐ（右が cat なら出力が通る、ls なら左の出力は捨てられる）", () => {
    expect(sh.run("echo piped | cat").output).toBe("piped\n");
    const r = sh.run("ping -c 1 localhost | ls /app");
    expect(r.output).toBe("config\npublic\nsrc\n");
    expect(r.executed).toHaveLength(2);
  });

  it("& や改行も区切りとして働く", () => {
    expect(sh.run("echo a & echo b").output).toBe("a\nb\n");
    expect(sh.run("echo a\necho b").output).toBe("a\nb\n");
  });

  it("$(...) とバッククォートはコマンドの結果に置き換わる", () => {
    expect(sh.run("echo $(whoami)").output).toBe("labuser\n");
    expect(sh.run("echo `whoami`").output).toBe("labuser\n");
    expect(sh.run("echo user=$(whoami)!").output).toBe("user=labuser!\n");
    // 置換の中身が先に実行され、その結果が外側の引数になる
    const r = sh.run("ping -c 1 $(whoami)");
    expect(r.executed.map((e) => e.argv[0])).toEqual(["whoami", "ping"]);
    expect(r.executed[1].argv).toEqual(["ping", "-c", "1", "labuser"]);
    expect(r.output).toContain("ping: unknown host labuser");
  });

  it("入れ子の置換と、置換結果の語分割", () => {
    expect(sh.run("echo $(echo $(echo deep))").output).toBe("deep\n");
    expect(sh.run('echo "a  b" $(echo c   d)').output).toBe("a  b c d\n");
    expect(argvs("echo $(echo c   d)")[1]).toEqual(["echo", "c", "d"]); // 引用符なし → 2 語
    expect(argvs(`echo "$(echo 'c   d')"`)[1]).toEqual(["echo", "c   d"]); // 引用符あり → 1 語（空白も保たれる）
    expect(argvs("echo x$(echo 1 2)y")[1]).toEqual(["echo", "x1", "2y"]);
  });

  it("リダイレクト: /dev/null へは捨てる、それ以外へは書かない、< は仮想ファイルを読む", () => {
    expect(sh.run("echo hidden > /dev/null").output).toBe("");
    expect(sh.run("cat /nope 2>/dev/null").output).toBe("");
    expect(sh.run("cat /nope 2>&1 | cat").output).toBe("cat: /nope: No such file or directory\n");
    const w = sh.run("echo x > /tmp/out");
    expect(w.output).toContain("/tmp/out");
    expect(w.output).toContain("書き込みません");
    expect(sh.run("cat < /etc/passwd").output).toContain("root:x:0:0");
    expect(sh.run("cat < /nope").output).toContain("cannot open /nope");
  });

  it("# 以降はコメント（コマンドインジェクションで後ろを無効化する定番）", () => {
    expect(argvs("ping -c 1 localhost; id # ; whoami").map((a) => a[0])).toEqual(["ping", "id"]);
    expect(sh.run("echo a#b").output).toBe("a#b\n"); // 語の途中の # は文字
  });

  it("$? と $VAR", () => {
    expect(sh.run("nope; echo $?").output).toContain("127");
    expect(sh.run("echo $USER ${HOME}").output).toBe("labuser /home/labuser\n");
    expect(sh.run("echo $UNDEFINED_VAR|cat").output).toBe("\n");
  });
});

describe("擬似シェル: クォート", () => {
  it("シングルクォートの中ではメタ文字も展開も効かない", () => {
    const r = sh.run("echo '; id && $(whoami) `id` $USER'");
    expect(r.output).toBe("; id && $(whoami) `id` $USER\n");
    expect(r.executed).toHaveLength(1);
  });

  it("ダブルクォートの中では ; && | は効かないが、$( ) とバッククォートと $VAR は効く", () => {
    expect(sh.run('echo "a; id && b | c"').executed).toHaveLength(1);
    expect(sh.run('echo "a; id"').output).toBe("a; id\n");
    expect(sh.run('echo "$(whoami)"').output).toBe("labuser\n");
    expect(sh.run('echo "`whoami`"').output).toBe("labuser\n");
    expect(sh.run('echo "$USER"').output).toBe("labuser\n");
  });

  it("バックスラッシュで 1 文字だけ無効化できる", () => {
    expect(sh.run("echo \\; \\$HOME \\`id").output).toBe("; $HOME `id\n");
    expect(sh.run('echo "\\$(whoami) \\" \\\\"').output).toBe('$(whoami) " \\\n');
  });

  it("引用符でつないだ語は 1 つの語になり、空文字列も引数として残る", () => {
    expect(argvs(`echo 'a b'"c d"e`)[0]).toEqual(["echo", "a bc de"]);
    expect(argvs(`echo "" x`)[0]).toEqual(["echo", "", "x"]);
  });

  it("引数のホスト名を引用符で囲むと ; は区切りにならない（escapeshellarg 相当）", () => {
    const evil = "localhost; cat /app/config/secrets.env";
    const r = sh.run("ping -c 1 " + escapeShellArg(evil));
    expect(r.executed).toHaveLength(1);
    expect(r.output).toContain("unknown host localhost; cat /app/config/secrets.env");
    expect(r.output).not.toContain("DB_PASSWORD");
    // シングルクォートを含む値も 1 つの引数に収まる
    const q = sh.run("echo " + escapeShellArg("it's; id"));
    expect(q.output).toBe("it's; id\n");
    expect(q.executed).toHaveLength(1);
  });

  it("ただし引用符は「-」で始まる値（引数インジェクション）を防げない", () => {
    const r = sh.run("ping -c 1 " + escapeShellArg("-c 5000"));
    // 1 つの引数 "-c 5000" になるが、ping はそれをオプションとして解釈してしまう
    expect(r.executed[0].argv).toEqual(["ping", "-c", "1", "-c 5000"]);
    expect(r.output).toContain("invalid argument");
    const r2 = sh.run("ping -c 1 " + escapeShellArg("-c5000") + " localhost");
    expect(r2.executed[0].argv).toEqual(["ping", "-c", "1", "-c5000", "localhost"]);
    expect(r2.output).toContain("5000 packets transmitted"); // 引用符を付けても回数を書き換えられた
  });
});

describe("擬似シェル: 破壊的コマンド・構文エラー", () => {
  it("rm などは実行せず、実行しない旨だけを表示する", () => {
    for (const c of ["rm -rf /app", "mv /app/a /app/b", "curl http://evil.example/x", "chmod 777 /etc/passwd", "bash -c id", "sleep 100"]) {
      const r = sh.run(c);
      expect(r.output).toContain("(擬似環境のため実行しません)");
      expect(r.exitCode).toBe(0);
    }
    // ファイルは消えていない
    expect(sh.run("rm /etc/passwd; cat /etc/passwd").output).toContain("root:x:0:0");
  });

  it("構文エラーのときは何も実行しない", () => {
    for (const line of ["echo a; ; echo b", "echo (", "echo a &&", "| echo", "echo a )", "echo 'unterminated", 'echo "unterminated', "echo $(echo", "echo `id", "ls >", "cat <<EOF"]) {
      const r = sh.run(line);
      expect(r.syntaxError, line).not.toBeNull();
      expect(r.executed, line).toHaveLength(0);
      expect(r.exitCode, line).toBe(2);
    }
    expect(sh.run("echo a; ; echo b").output).toContain("near unexpected token `;'");
  });

  it("末尾の ; や空行・空白だけの入力はエラーにならない", () => {
    expect(sh.run("echo a;").output).toBe("a\n");
    expect(sh.run("   ").output).toBe("");
    expect(sh.run("").exitCode).toBe(0);
    expect(sh.run("echo $()").output).toBe("\n");
  });
});

describe("擬似シェル: 暴走を防ぐ上限", () => {
  it("コマンドラインが長すぎると実行しない", () => {
    const r = sh.run("echo " + "a".repeat(1000));
    expect(r.syntaxError).toContain("長すぎます");
    expect(r.executed).toHaveLength(0);
    expect(new FakeShell({ limits: { maxLineLength: 10 } }).run("echo 123456789").syntaxError).not.toBeNull();
  });

  it("$( ) の入れ子は上限まで（既定 4）。超えたら構文エラーで何も実行しない", () => {
    const nest = (n: number) => "echo ".concat("$(echo ".repeat(n), "x", ")".repeat(n));
    expect(sh.run(nest(4)).output).toBe("x\n");
    const r = sh.run(nest(5));
    expect(r.syntaxError).toContain("入れ子が深すぎます");
    expect(r.executed).toHaveLength(0);
    // バッククォートも同じ上限
    let bt = "x";
    for (let i = 0; i < 6; i++) bt = "echo `" + bt.replace(/[`\\$]/g, "\\$&") + "`";
    expect(sh.run(bt).syntaxError).toContain("入れ子が深すぎます");
  });

  it("実行するコマンドの数に上限がある（$( ) の中も数える）", () => {
    const r = sh.run(Array(60).fill("echo a").join("; "));
    expect(r.limitReason).toContain("50 個の上限");
    expect(r.executed).toHaveLength(50);
    expect(r.output).toContain("実行を打ち切りました");
    const s = new FakeShell({ limits: { maxCommands: 3 } }).run("echo $(echo $(echo $(echo x)))");
    expect(s.limitReason).not.toBeNull();
  });

  it("出力の大きさに上限がある", () => {
    const small = new FakeShell({ limits: { maxOutput: 50 } });
    const r = small.run("cat /etc/passwd /etc/passwd /etc/passwd");
    expect(r.limitReason).toContain("50 文字の上限");
    expect(r.output.length).toBeLessThan(50 + 100);
    expect(r.output).toContain("実行を打ち切りました");
    // $( ) で取り込む文字列にも上限がある
    const s = small.run('echo "$(cat /etc/passwd /etc/passwd)"');
    expect(s.limitReason).not.toBeNull();
    // 既定の上限（8192）でも、大量の出力は打ち切られる
    const big = sh.run("cat" + " /etc/passwd".repeat(70));
    expect(big.output.length).toBeLessThanOrEqual(8192 + 200);
    expect(big.limitReason).not.toBeNull();
  });
});

describe("擬似シェル: execFile（シェルを通さない実行）", () => {
  it("引数の ; や $( ) はただの文字列として渡る", () => {
    const r = new FakeShell().execFile(["ping", "-c", "1", "localhost; cat /app/config/secrets.env"]);
    expect(r.executed).toHaveLength(1);
    expect(r.output).toBe("ping: unknown host localhost; cat /app/config/secrets.env\n");
    expect(r.output).not.toContain("DB_PASSWORD");
    const e = sh.execFile(["echo", "$(whoami)", "&&", "id"]);
    expect(e.output).toBe("$(whoami) && id\n");
  });

  it("正しいホストなら通常どおり実行できる", () => {
    const r = sh.execFile(["ping", "-c", "1", "--", "example.com"]);
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("PING example.com");
  });

  it("シェルを通さなくても、「-」で始まる引数はコマンド自身がオプションとして解釈する", () => {
    const r = sh.execFile(["ping", "-c", "1", "-c5000", "localhost"]);
    expect(r.output).toContain("5000 packets transmitted");
    // -- を挟めばオプション解釈を止められる
    expect(sh.execFile(["ping", "-c", "1", "--", "-c5000"]).output).toBe("ping: unknown host -c5000\n");
  });

  it("空の argv はエラー、破壊的コマンドは実行しない", () => {
    expect(sh.execFile([]).syntaxError).not.toBeNull();
    expect(sh.execFile(["rm", "-rf", "/"]).output).toContain("(擬似環境のため実行しません)");
  });
});

describe("表示用ヘルパー", () => {
  it("shellQuote / formatCommand", () => {
    expect(shellQuote("abc-1.2/x")).toBe("abc-1.2/x");
    expect(shellQuote("a b")).toBe("'a b'");
    expect(shellQuote("")).toBe("''");
    expect(shellQuote("it's")).toBe(`'it'\\''s'`);
    expect(formatCommand(["ping", "-c", "1", "a;b"])).toBe("ping -c 1 'a;b'");
    expect(escapeShellArg("abc")).toBe("'abc'");
  });
});
