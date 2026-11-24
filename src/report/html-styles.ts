export const HTML_STYLES = `
:root {
  --bg: #f1f4f2; --panel: #ffffff; --text: #111713; --muted: #5b665f; --border: #d9e1dc;
  --critical: #b42318; --high: #d1491b; --medium: #b7791f; --low: #2f6fb5; --info: #667085;
  --ok: #177245; --accent: #087a50; --accent-soft: #dff7eb; --grid: rgba(8, 122, 80, 0.08);
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #07100d; --panel: #0d1914; --text: #e9f4ee; --muted: #93a79c; --border: #20352b;
    --critical: #f97066; --high: #f38744; --medium: #f5c451; --low: #6aa8f0; --info: #98a2b3;
    --ok: #63e6a4; --accent: #63f5b2; --accent-soft: #122b20; --grid: rgba(99, 245, 178, 0.06);
  }
}
* { box-sizing: border-box; }
body { margin: 0; background-color: var(--bg); background-image: linear-gradient(var(--grid) 1px, transparent 1px), linear-gradient(90deg, var(--grid) 1px, transparent 1px); background-size: 40px 40px; color: var(--text); font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 1160px; margin: 0 auto; padding: 40px 20px 72px; }
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
.scope { background: var(--accent-soft); border: 1px solid var(--accent); border-radius: 8px; padding: 10px 14px; overflow-wrap: anywhere; }
.grade-panel { display: grid; grid-template-columns: 148px 1fr; gap: 28px; align-items: center; margin: 24px 0; padding: 22px 26px; background: linear-gradient(120deg, var(--panel), var(--accent-soft)); border: 1px solid var(--border); border-top: 4px solid var(--accent); border-radius: 14px; box-shadow: 0 18px 48px rgba(0, 0, 0, 0.12); }
.grade-panel h2 { margin: 2px 0 4px; font-size: 25px; }
.grade-panel p { margin: 0; color: var(--muted); max-width: 760px; }
.eyebrow { color: var(--accent); font-size: 11px; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
.grade-ring { --grade-color: var(--accent); width: 126px; height: 126px; display: grid; place-content: center; text-align: center; border-radius: 50%; border: 1px solid var(--grade-color); background: radial-gradient(circle at center, var(--panel) 57%, transparent 59%), conic-gradient(var(--grade-color) 0 var(--grade-score), var(--border) var(--grade-score) 100%); box-shadow: inset 0 0 0 7px var(--panel), 0 0 30px var(--grid); }
.grade-f, .grade-d { --grade-color: var(--critical); }
.grade-c { --grade-color: var(--medium); }
.grade-a, .grade-b { --grade-color: var(--ok); }
.grade-letter { display: block; font-size: 50px; line-height: .9; font-weight: 850; letter-spacing: -.06em; }
.grade-score { display: block; margin-top: 7px; color: var(--muted); font: 11px/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
.cards { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; }
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
.time-col, .findings-col { white-space: nowrap; }
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
.attack-paths { display: grid; gap: 16px; }
.attack-path { background: linear-gradient(145deg, var(--panel), var(--accent-soft)); border: 1px solid var(--border); border-radius: 14px; padding: 20px; overflow-x: auto; box-shadow: 0 12px 32px rgba(0, 0, 0, .08); }
.attack-path h3 { margin: 0; font-size: 16px; }
.attack-path p { color: var(--muted); margin: 8px 0; }
.attack-graph { display: block; width: 100%; min-width: 700px; height: auto; margin: 8px 0 2px; color: var(--accent); }
.attack-connectors { stroke: currentColor; stroke-width: 3; stroke-dasharray: 8 7; fill: none; }
.attack-graph marker path { fill: var(--accent); }
.attack-node circle { fill: var(--panel); stroke: var(--accent); stroke-width: 3; }
.attack-node text { text-anchor: middle; fill: var(--text); font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
.attack-node .node-index { fill: var(--accent); font-size: 11px; font-weight: 800; letter-spacing: .15em; }
.attack-node .node-label { font-size: 13px; font-weight: 750; }
.attack-node .node-file { fill: var(--muted); font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; }
.attack-path ol { display: flex; flex-wrap: wrap; gap: 8px; list-style: none; padding: 0; margin: 10px 0 0; }
.attack-path li { flex: 1 1 180px; border-left: 3px solid var(--accent); background: var(--bg); padding: 8px 10px; border-radius: 6px; }
.attack-path li span { display: block; color: var(--muted); font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
.attack-path li .stage-location { overflow-wrap: normal; }
.attack-path li .stage-rule { margin-top: 3px; color: var(--accent); font-size: 11px; }
a { color: var(--accent); }
a:focus-visible, input:focus-visible { outline: 3px solid var(--accent); outline-offset: 3px; }
.empty { color: var(--muted); padding: 24px; text-align: center; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; }

@media (max-width: 900px) {
  .cards { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 600px) {
  main { padding: 24px 12px 48px; }
  .grade-panel { grid-template-columns: 1fr; padding: 20px; }
  .grade-ring { width: 108px; height: 108px; }
}
@media (max-width: 420px) {
  .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media print {
  body { background: #fff; color: #111; }
  main { max-width: none; padding: 0; }
  .grade-panel, .attack-path, .card, .finding { box-shadow: none; break-inside: avoid; }
  .filters { display: none; }
}

`;
