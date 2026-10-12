/** 共有 CSS / JS。外部のCDNやフォントは使わない（ラボは外部と通信しない） */

export const labCss = /* css */ `
:root{
  --bg:#f7f7f5; --surface:#ffffff; --ink:#1d1f23; --muted:#5d6470; --line:#dcdfe4;
  --accent:#2457d6; --accent-ink:#ffffff;
  --vuln:#b42318; --vuln-bg:#fef0ee; --fixed:#0a7a45; --fixed-bg:#e8f6ee;
  --code-bg:#f0f1f4; --hl:#fff1c2; --add:#e3f6e8; --del:#fde8e6;
  --font:-apple-system,BlinkMacSystemFont,"Hiragino Sans","Hiragino Kaku Gothic ProN","Noto Sans JP","Yu Gothic",Meiryo,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Noto Sans Mono CJK JP",monospace;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#16181c; --surface:#1e2127; --ink:#e8eaee; --muted:#9aa3b0; --line:#343942;
    --accent:#7aa2ff; --accent-ink:#0d1220;
    --vuln:#ff8f84; --vuln-bg:#3a1f1c; --fixed:#6fd8a0; --fixed-bg:#16301f;
    --code-bg:#262a31; --hl:#4a3f12; --add:#17331f; --del:#3d1f1d;
  }
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.75 var(--font);}
a{color:var(--accent)}
code,pre{font-family:var(--mono);font-size:.9em}
code{background:var(--code-bg);padding:.1em .35em;border-radius:4px;word-break:break-all}
pre{background:var(--code-bg);padding:12px 14px;border-radius:8px;overflow:auto;line-height:1.55;margin:.6em 0}
pre code{background:none;padding:0;word-break:normal}
h1,h2,h3{line-height:1.35}
h1{font-size:1.7rem;margin:.2em 0 .4em}
h2{font-size:1.3rem;margin:2em 0 .6em;padding-bottom:.25em;border-bottom:2px solid var(--line)}
h3{font-size:1.05rem;margin:1.4em 0 .4em}
.wrap{max-width:960px;margin:0 auto;padding:0 16px}
.site-header{background:var(--surface);border-bottom:1px solid var(--line)}
.site-header .wrap{display:flex;gap:16px;align-items:center;flex-wrap:wrap;padding-top:10px;padding-bottom:10px}
.site-header .brand{font-weight:700;color:var(--ink);text-decoration:none}
.site-header nav{margin-left:auto;display:flex;gap:14px;font-size:.92rem}
.site-footer{margin:56px 0 32px;color:var(--muted);font-size:.85rem}
.lede{color:var(--muted);margin:.2em 0 1.2em}
.notice{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);padding:10px 14px;border-radius:6px;margin:1em 0}
.notice--warn{border-left-color:var(--vuln)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column;gap:6px}
.card h3{margin:0;font-size:1.05rem}
.card p{margin:0;color:var(--muted);font-size:.9rem}
.card .meta{display:flex;gap:8px;flex-wrap:wrap;font-size:.78rem;color:var(--muted)}
.card .links{margin-top:auto;display:flex;gap:10px;flex-wrap:wrap;padding-top:6px;font-size:.9rem}
.tag{border:1px solid var(--line);border-radius:999px;padding:0 8px}
.tag--done{border-color:var(--fixed);color:var(--fixed)}
.btn,button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);padding:6px 14px}
.btn--ghost,button.ghost{background:transparent;color:var(--accent)}
button.danger{background:var(--vuln);border-color:var(--vuln);color:#fff}
.copy{font-size:.75rem;padding:1px 8px;margin-left:8px}
input[type=text],input[type=password],input[type=email],input[type=search],input:not([type]),textarea,select{font:inherit;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--ink);max-width:100%}
label{display:block;margin:.6em 0 .2em;font-size:.9rem;color:var(--muted)}
table.data{border-collapse:collapse;margin:.6em 0;width:100%;font-size:.9rem}
table.data th,table.data td{border:1px solid var(--line);padding:4px 10px;text-align:left;vertical-align:top}
table.data th{background:var(--code-bg)}
.steps{counter-reset:s;list-style:none;padding:0}
.step{counter-increment:s;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:12px 16px;margin:12px 0}
.step>h3{margin:0 0 .3em}
.step>h3::before{content:counter(s);display:inline-block;min-width:1.7em;height:1.7em;line-height:1.7em;text-align:center;border-radius:50%;background:var(--accent);color:var(--accent-ink);margin-right:.5em;font-size:.9rem}
.payload{display:flex;align-items:baseline;gap:6px;flex-wrap:wrap;margin:.3em 0}
.payload .lbl{font-size:.8rem;color:var(--muted)}
.payload .note{font-size:.8rem;color:var(--muted)}
.code{position:relative}
.code .ln{display:block;white-space:pre}
.code .ln.hl{background:var(--hl);box-shadow:-14px 0 0 var(--hl),14px 0 0 var(--hl)}
.diff .add{display:block;background:var(--add)}
.diff .del{display:block;background:var(--del)}
.diff .hunk{display:block;color:var(--muted)}
.diff .ctx{display:block}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:760px){.pair{grid-template-columns:1fr}}
.pair h4{margin:.2em 0}
details.qa{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:8px 0}
details.qa summary{cursor:pointer;font-weight:600}
.toc{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:8px 18px;font-size:.92rem}
.toc ol{margin:.3em 0;padding-left:1.2em}
.badge{display:inline-block;font-size:.75rem;padding:0 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.badge--vuln{color:var(--vuln);border-color:var(--vuln);background:var(--vuln-bg)}
.badge--fixed{color:var(--fixed);border-color:var(--fixed);background:var(--fixed-bg)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}
.progress{display:flex;gap:18px;flex-wrap:wrap;align-items:center;margin:1.2em 0;padding:10px 14px;background:var(--surface);border:1px solid var(--line);border-radius:8px}
.progress label{margin:0;color:var(--ink);display:flex;gap:6px;align-items:center}

/* 演習ページ（脆弱版・修正版）の外枠 */
.ex-banner{display:flex;gap:10px 16px;align-items:center;flex-wrap:wrap;padding:8px 16px;font-size:.88rem;border-bottom:3px solid}
.ex-banner nav{margin-left:auto;display:flex;gap:14px}
.ex-banner--vuln{background:var(--vuln-bg);color:var(--vuln);border-color:var(--vuln)}
.ex-banner--fixed{background:var(--fixed-bg);color:var(--fixed);border-color:var(--fixed)}
.ex-banner a{color:inherit}
.ex-main{max-width:820px;margin:0 auto;padding:16px}
.ex-main fieldset{border:1px solid var(--line);border-radius:8px;margin:1em 0}
.ex-main legend{color:var(--muted);font-size:.85rem}
.result{background:var(--surface);border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:1em 0}
.sql{background:var(--code-bg);padding:8px 12px;border-radius:6px;font-family:var(--mono);font-size:.85rem;white-space:pre-wrap;word-break:break-all}
.ok{color:var(--fixed);font-weight:600}
.ng{color:var(--vuln);font-weight:600}
`;

export const labJs = /* js */ `
document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy]");
  if (!b) return;
  var text = b.getAttribute("data-copy");
  var done = function () {
    var old = b.textContent;
    b.textContent = "コピーしました";
    setTimeout(function () { b.textContent = old; }, 1200);
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done, function () {});
  }
});
`;
