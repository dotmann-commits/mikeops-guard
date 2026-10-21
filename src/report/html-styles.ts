export const HTML_STYLES = `
:root {
  --bg: #f6f7f9; --panel: #ffffff; --text: #16191f; --muted: #5b6472; --border: #e1e5eb;
  --critical: #b42318; --high: #d1491b; --medium: #b7791f; --low: #2f6fb5; --info: #667085;
  --ok: #2e7d4f; --accent: #1f3a5f;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1216; --panel: #171b21; --text: #e6e9ee; --muted: #9aa4b2; --border: #2a313b;
    --critical: #f97066; --high: #f38744; --medium: #f5c451; --low: #6aa8f0; --info: #98a2b3;
    --ok: #5cc98a; --accent: #8fb4e3;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1080px; margin: 0 auto; padding: 32px 16px 64px; }
header { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 16px; align-items: flex-end; margin-bottom: 24px; }
h1 { margin: 0; font-size: 26px; letter-spacing: -0.01em; }
h2 { font-size: 18px; margin: 32px 0 12px; }
.meta { color: var(--muted); font-size: 13px; }
.meta code { font-size: 12px; overflow-wrap: anywhere; }
.verdict { padding: 6px 14px; border-radius: 999px; font-weight: 600; font-size: 14px; color: #fff; }
.verdict.pass { background: var(--ok); }
.verdict.fail { background: var(--critical); }
.verdict.warn { background: var(--medium); color: #1f1300; }
.coverage { border-left: 4px solid var(--medium); padding: 8px 12px; margin: 12px 0; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 28px; font-weight: 700; font-variant-numeric: tabular-nums; }
.card .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; }
.sev-critical { color: var(--critical); } .sev-high { color: var(--high); } .sev-medium { color: var(--medium); }
.sev-low { color: var(--low); } .sev-info { color: var(--info); }
/* Wide tables scroll inside their box so the page never scrolls sideways on phones. */
.table-wrap { overflow-x: auto; }
table { width: 100%; min-width: 520px; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
th, td { overflow-wrap: anywhere; text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 14px; }
th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
tr:last-child td { border-bottom: 0; }
.status { font-weight: 600; } .status-ok { color: var(--ok); } .status-skipped { color: var(--muted); } .status-failed { color: var(--critical); }
.filters { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
.filters label { background: var(--panel); border: 1px solid var(--border); border-radius: 999px; padding: 4px 12px; font-size: 13px; cursor: pointer; }
.finding { background: var(--panel); border: 1px solid var(--border); border-left: 4px solid var(--info); border-radius: 8px; padding: 14px 16px; margin-bottom: 10px; }
.finding[data-severity="critical"] { border-left-color: var(--critical); }
.finding[data-severity="high"] { border-left-color: var(--high); }
.finding[data-severity="medium"] { border-left-color: var(--medium); }
.finding[data-severity="low"] { border-left-color: var(--low); }
.finding h3 { margin: 0 0 4px; font-size: 15px; }
.finding .where { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--muted); overflow-wrap: anywhere; }
.finding p { margin: 8px 0 0; overflow-wrap: anywhere; }
.finding h3, .meta { overflow-wrap: anywhere; }
.finding .fix { border-top: 1px dashed var(--border); padding-top: 8px; }
.finding .ai { background: var(--bg); border-radius: 6px; padding: 8px 10px; white-space: pre-wrap; }
.badge { display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; margin-right: 6px; }
.refs { font-size: 13px; overflow-wrap: anywhere; }
a { color: var(--accent); }
.empty { color: var(--muted); padding: 24px; text-align: center; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }

`;
