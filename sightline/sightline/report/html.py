"""Self-contained HTML report (no external assets, works offline, safe to email)."""

from __future__ import annotations

import html
import json

from sightline import __version__
from sightline.models import ScanResult
from sightline.report.common import patch_plan


def _plan_data(result: ScanResult) -> list[dict]:
    return [
        {
            "host": p.label,
            "command": p.command,
            "findings": p.findings_resolved,
            "items": [
                {
                    "package": i.package,
                    "fixed": i.fixed_version,
                    "findings": i.findings,
                    "kev": i.kev,
                    "priority": i.top_priority,
                }
                for i in p.items
            ],
        }
        for p in patch_plan(result)
    ]


def render_html(result: ScanResult) -> str:
    payload = result.to_dict()
    payload["plan"] = _plan_data(result)
    payload["generator"] = f"Sightline {__version__}"
    data = json.dumps(payload).replace("</", "<\\/")
    title = html.escape(f"Sightline report - {result.name or result.scan_id}")
    return TEMPLATE.replace("__TITLE__", title).replace("__DATA__", data)


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root {
  --bg: #f6f7f9; --panel: #ffffff; --ink: #14171c; --muted: #5d6673; --line: #e3e6eb;
  --accent: #3355dd; --chip: #eef1f5;
  --crit: #c0262d; --high: #e0561b; --med: #b98900; --low: #2f74c0; --info: #7a8391;
  --now: #c0262d; --soon: #d06a00; --plan: #2f74c0; --mon: #7a8391; --ok: #1f8a4c;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0f1216; --panel: #171b21; --ink: #e8ebf0; --muted: #98a2b3; --line: #262c35;
    --accent: #7b96ff; --chip: #222831;
    --crit: #ff5a5f; --high: #ff8a3d; --med: #e6b422; --low: #5aa2f0; --info: #8b95a5;
    --now: #ff5a5f; --soon: #ff9d2e; --plan: #5aa2f0; --mon: #8b95a5; --ok: #3ccf7a;
  }
}
:root[data-theme="dark"] {
  --bg: #0f1216; --panel: #171b21; --ink: #e8ebf0; --muted: #98a2b3; --line: #262c35;
  --accent: #7b96ff; --chip: #222831;
  --crit: #ff5a5f; --high: #ff8a3d; --med: #e6b422; --low: #5aa2f0; --info: #8b95a5;
  --now: #ff5a5f; --soon: #ff9d2e; --plan: #5aa2f0; --mon: #8b95a5; --ok: #3ccf7a;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
.wrap { max-width: 1240px; margin: 0 auto; padding: 24px 16px 64px; }
header { display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: baseline; justify-content: space-between; }
h1 { font-size: 22px; margin: 0; letter-spacing: -0.01em; }
h1 .brand { color: var(--accent); }
h2 { font-size: 16px; margin: 32px 0 12px; display: flex; align-items: center; gap: 8px; }
h2 .count { font-weight: 500; color: var(--muted); }
.meta { color: var(--muted); font-size: 13px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 20px; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.tile .n { font-size: 28px; font-weight: 700; line-height: 1.1; font-variant-numeric: tabular-nums; }
.tile .l { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; margin-top: 4px; }
.tile.now .n { color: var(--now); } .tile.soon .n { color: var(--soon); }
.tile.kev .n { color: var(--crit); } .tile.fixed .n { color: var(--ok); }
.bar { display: flex; height: 10px; border-radius: 6px; overflow: hidden; background: var(--chip); margin-top: 16px; }
.bar span { display: block; height: 100%; }
.legend { display: flex; gap: 16px; flex-wrap: wrap; color: var(--muted); font-size: 12px; margin-top: 8px; }
.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; }
.cards { display: grid; gap: 10px; }
.card { background: var(--panel); border: 1px solid var(--line); border-left: 4px solid var(--now); border-radius: 10px; padding: 12px 16px; }
.card .t { font-weight: 600; }
.card .s { color: var(--muted); font-size: 13px; margin-top: 2px; word-break: break-word; }
.card .fix { margin-top: 8px; font-size: 13px; }
.badge { display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 7px; border-radius: 999px;
  background: var(--chip); color: var(--muted); white-space: nowrap; vertical-align: 1px; }
.badge.sev-critical { background: var(--crit); color: #fff; } .badge.sev-high { background: var(--high); color: #fff; }
.badge.sev-medium { background: var(--med); color: #fff; } .badge.sev-low { background: var(--low); color: #fff; }
.badge.p-fix-now { color: var(--now); border: 1px solid currentColor; background: transparent; }
.badge.p-fix-soon { color: var(--soon); border: 1px solid currentColor; background: transparent; }
.badge.p-plan { color: var(--plan); border: 1px solid currentColor; background: transparent; }
.badge.p-monitor { color: var(--mon); border: 1px solid currentColor; background: transparent; }
.badge.kev { background: var(--crit); color: #fff; } .badge.new { background: var(--accent); color: #fff; }
.badge.ok { background: var(--ok); color: #fff; }
code, .mono { font-family: var(--mono); font-size: 12.5px; }
pre.cmd { margin: 8px 0 0; padding: 10px 12px; background: var(--chip); border-radius: 8px; overflow-x: auto;
  font-family: var(--mono); font-size: 12.5px; white-space: pre-wrap; word-break: break-all; }
.filters { display: flex; flex-wrap: wrap; gap: 8px; padding: 12px; border-bottom: 1px solid var(--line); }
.filters input, .filters select { font: inherit; color: var(--ink); background: var(--bg); border: 1px solid var(--line);
  border-radius: 8px; padding: 6px 10px; min-width: 0; }
.filters input[type=search] { flex: 1 1 220px; }
.filters label { display: flex; align-items: center; gap: 6px; color: var(--muted); font-size: 13px; }
.tbl-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 12px; color: var(--muted); font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
  cursor: pointer; user-select: none; white-space: nowrap; }
tr.row { cursor: pointer; } tr.row:hover td { background: color-mix(in srgb, var(--accent) 5%, transparent); }
td.risk { font-weight: 700; font-variant-numeric: tabular-nums; }
td.title { min-width: 280px; }
tr.detail td { background: var(--bg); padding: 14px 16px 18px; }
.kv { display: grid; grid-template-columns: 130px 1fr; gap: 4px 16px; font-size: 13px; }
.kv dt { color: var(--muted); } .kv dd { margin: 0; word-break: break-word; }
.more[hidden] { display: none; }
.more { display: block; margin: 12px auto; font: inherit; padding: 8px 16px; border-radius: 8px; border: 1px solid var(--line);
  background: var(--panel); color: var(--ink); cursor: pointer; }
.hosts { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 12px; }
.host { padding: 14px 16px; }
.host .h { display: flex; justify-content: space-between; gap: 8px; }
.host .h b { font-size: 15px; }
.host .sub { color: var(--muted); font-size: 13px; }
.host ul { margin: 8px 0 0; padding-left: 18px; font-size: 13px; }
.host .err { color: var(--crit); font-size: 13px; margin-top: 6px; }
.host .note { color: var(--muted); font-size: 12px; margin-top: 4px; }
.sevcounts { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 8px; }
.empty { padding: 28px; text-align: center; color: var(--muted); }
a { color: var(--accent); }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; }
.theme { font: inherit; font-size: 12px; background: transparent; color: var(--muted); border: 1px solid var(--line);
  border-radius: 999px; padding: 3px 10px; cursor: pointer; }
@media (max-width: 640px) { .kv { grid-template-columns: 1fr; } td.title { min-width: 200px; } }
</style>
</head>
<body>
<div class="wrap" id="app"></div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function () {
  const D = JSON.parse(document.getElementById('data').textContent);
  const PRIO = ['fix-now', 'fix-soon', 'plan', 'monitor'];
  const PL = {'fix-now': 'Fix now', 'fix-soon': 'Fix this week', 'plan': 'Plan a fix', 'monitor': 'Monitor'};
  const PC = {'fix-now': 'var(--now)', 'fix-soon': 'var(--soon)', 'plan': 'var(--plan)', 'monitor': 'var(--mon)'};
  const SEV = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmtDate = s => { if (!s) return ''; const d = new Date(s); return isNaN(d) ? s : d.toLocaleString(); };
  const dur = () => { const a = new Date(D.started), b = new Date(D.finished); const s = Math.round((b - a) / 1000);
    return isNaN(s) ? '' : (s < 90 ? s + 's' : Math.round(s / 60) + ' min'); };
  const F = D.findings, S = D.summary, hasPrev = !!D.previous_scan_id;
  const hostName = {}; D.hosts.forEach(h => hostName[h.address] = h.hostname);
  const cveLink = c => `<a href="https://nvd.nist.gov/vuln/detail/${esc(c)}" target="_blank" rel="noopener">${esc(c)}</a>`;
  const where = f => esc(f.host) + (f.port ? ':' + f.port : '');
  const flags = f => (f.kev ? ' <span class="badge kev" title="CISA Known Exploited Vulnerability">KEV</span>' : '') +
    (hasPrev && f.status === 'new' ? ' <span class="badge new">NEW</span>' : '') +
    (f.confidence && f.confidence !== 'confirmed' ? ` <span class="badge" title="detection confidence">${esc(f.confidence)}</span>` : '');

  const pc = {}; PRIO.forEach(p => pc[p] = F.filter(f => f.priority === p).length);
  let h = `<header><h1><span class="brand">Sightline</span> &nbsp;${esc(D.name || D.scan_id)}</h1>
    <div class="meta">${esc(fmtDate(D.started))}${dur() ? ' &middot; ' + dur() : ''} &middot; scan ${esc(D.scan_id)}
    &nbsp;<button class="theme" id="theme">Theme</button></div></header>
    <div class="meta">Targets: ${D.targets.map(esc).join(', ')}</div>
    <div class="tiles">
      <div class="tile"><div class="n">${S.hosts_alive}<span class="meta" style="font-size:14px;font-weight:500"> / ${S.hosts_scanned}</span></div><div class="l">Hosts up</div></div>
      <div class="tile"><div class="n">${S.hosts_credentialed}</div><div class="l">Credentialed</div></div>
      <div class="tile now"><div class="n">${pc['fix-now']}</div><div class="l">Fix now</div></div>
      <div class="tile soon"><div class="n">${pc['fix-soon']}</div><div class="l">Fix this week</div></div>
      <div class="tile kev"><div class="n">${S.kev}</div><div class="l">Known exploited</div></div>
      ${hasPrev ? `<div class="tile"><div class="n">${S.new}</div><div class="l">New since last scan</div></div>
      <div class="tile fixed"><div class="n">${S.fixed}</div><div class="l">Fixed since last scan</div></div>`
      : `<div class="tile"><div class="n">${F.length}</div><div class="l">Total findings</div></div>`}
    </div>`;
  if (F.length) {
    h += '<div class="bar">' + PRIO.map(p => pc[p] ? `<span style="width:${pc[p] / F.length * 100}%;background:${PC[p]}" title="${PL[p]}: ${pc[p]}"></span>` : '').join('') + '</div>';
    h += '<div class="legend">' + PRIO.map(p => `<span><i style="background:${PC[p]}"></i>${PL[p]} ${pc[p]}</span>`).join('') + '</div>';
  }

  const top = F.filter(f => f.priority === 'fix-now').slice(0, 12);
  if (top.length) {
    h += `<h2>Fix first <span class="count">${pc['fix-now']}</span></h2><div class="cards">` + top.map(f => `
      <div class="card"><div class="t">${esc(f.title)}${flags(f)}</div>
      <div class="s"><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span> &nbsp;${where(f)}${hostName[f.host] ? ' (' + esc(hostName[f.host]) + ')' : ''}
      &middot; risk ${f.risk}${f.evidence ? ' &middot; ' + esc(f.evidence) : ''}</div>
      <div class="fix"><b>Fix:</b> ${esc(f.remediation)}</div></div>`).join('') + '</div>';
  }

  if (D.plan && D.plan.length) {
    h += `<h2>Patch plan <span class="count">one command per host</span></h2><div class="cards">` + D.plan.map(p => `
      <div class="card" style="border-left-color:var(--accent)"><div class="t">${esc(p.host)}</div>
      <div class="s">Resolves ${p.findings} findings across ${p.items.length} packages: ${p.items.slice(0, 12).map(i =>
        `${esc(i.package)}${i.kev ? ' <span class="badge kev">KEV</span>' : ''}`).join(', ')}${p.items.length > 12 ? ', ...' : ''}</div>
      <pre class="cmd">${esc(p.command)}</pre></div>`).join('') + '</div>';
  }

  const hosts = [...new Set(F.map(f => f.host))];
  h += `<h2>All findings <span class="count" id="fcount"></span></h2>
    <div class="panel"><div class="filters">
      <input type="search" id="q" placeholder="Search title, CVE, package, host...">
      <select id="fp"><option value="">All priorities</option>${PRIO.map(p => `<option value="${p}">${PL[p]}</option>`).join('')}</select>
      <select id="fs"><option value="">All severities</option>${SEV.map(s => `<option>${s}</option>`).join('')}</select>
      <select id="fc"><option value="">All types</option><option value="network">Network exposure</option><option value="package">Vulnerable package</option><option value="config">Configuration</option></select>
      <select id="fh"><option value="">All hosts</option>${hosts.map(x => `<option value="${esc(x)}">${esc(x)}${hostName[x] ? ' (' + esc(hostName[x]) + ')' : ''}</option>`).join('')}</select>
      <label><input type="checkbox" id="ff"> Fix available</label>
      ${hasPrev ? '<label><input type="checkbox" id="fn"> New only</label>' : ''}
    </div><div class="tbl-wrap"><table><thead><tr>
      <th data-k="risk">Risk</th><th data-k="priority">Priority</th><th data-k="severity">Severity</th>
      <th data-k="host">Host</th><th data-k="title">Finding</th><th data-k="fixed_version">Fix</th>
    </tr></thead><tbody id="tb"></tbody></table></div><button class="more" id="more" hidden>Show more</button></div>`;

  h += `<h2>Hosts <span class="count">${D.hosts.filter(x => x.alive).length} up</span></h2><div class="hosts">`;
  D.hosts.filter(x => x.alive || (x.errors && x.errors.length)).forEach(x => {
    const hf = F.filter(f => f.host === x.address);
    const sc = {}; hf.forEach(f => sc[f.severity] = (sc[f.severity] || 0) + 1);
    h += `<div class="panel host"><div class="h"><div><b>${esc(x.address)}</b>${x.hostname ? ' <span class="sub">' + esc(x.hostname) + '</span>' : ''}</div>
      ${x.credentialed ? '<span class="badge ok">credentialed</span>' : '<span class="badge">network only</span>'}</div>
      <div class="sub">${esc(x.os_name || 'OS unknown')}${x.kernel ? ' &middot; kernel ' + esc(x.kernel) : ''}${x.package_count ? ' &middot; ' + x.package_count + ' packages' : ''}</div>
      <div class="sevcounts">${SEV.filter(s => sc[s]).map(s => `<span class="badge sev-${s}">${sc[s]} ${s}</span>`).join('') || '<span class="badge ok">no findings</span>'}</div>
      ${x.services && x.services.length ? '<ul>' + x.services.map(s => `<li><span class="mono">${s.port}/${esc(s.proto)}</span> ${esc(s.name)}${s.product ? ' &middot; ' + esc(s.product + ' ' + (s.version || '')) : ''}${s.tls ? ' <span class="badge">TLS</span>' : ''}</li>`).join('') + '</ul>' : ''}
      ${(x.errors || []).map(e => `<div class="err">${esc(e)}</div>`).join('')}
      ${(x.notes || []).filter(n => !n.startsWith('check ')).map(n => `<div class="note">${esc(n)}</div>`).join('')}
    </div>`;
  });
  h += '</div>';

  if (D.fixed && D.fixed.length) {
    h += `<h2>Fixed since last scan <span class="count">${D.fixed.length}</span></h2><div class="panel"><div class="tbl-wrap"><table><tbody>` +
      D.fixed.map(f => `<tr><td><span class="badge ok">fixed</span></td><td>${where(f)}</td><td>${esc(f.title)}</td></tr>`).join('') + '</tbody></table></div></div>';
  }
  const vdb = D.vulndb || {};
  h += `<footer>Generated by ${esc(D.generator)}. Vulnerability data: OSV.dev distro advisories${vdb.osv_updated ? ' (updated ' + esc(fmtDate(vdb.osv_updated)) + ')' : ''},
    CISA KEV${vdb.kev_updated ? ' (' + esc(fmtDate(vdb.kev_updated)) + ')' : ''}, FIRST EPSS${vdb.epss_updated ? ' (' + esc(fmtDate(vdb.epss_updated)) + ')' : ''}.
    Risk combines severity, exploitation (KEV/EPSS), network exposure and fix availability.</footer>`;
  document.getElementById('app').innerHTML = h;

  const themeBtn = document.getElementById('theme');
  themeBtn.onclick = () => { const r = document.documentElement; const dark = getComputedStyle(r).getPropertyValue('--bg').trim() === '#0f1216';
    r.dataset.theme = dark ? 'light' : 'dark'; };

  let sortKey = 'risk', sortDir = -1, shown = 150, open = new Set();
  const $ = id => document.getElementById(id);
  const sevRank = s => SEV.indexOf(s), prioRank = p => PRIO.indexOf(p);
  function filtered() {
    const q = $('q').value.trim().toLowerCase(), fp = $('fp').value, fs = $('fs').value, fc = $('fc').value,
      fh = $('fh').value, ff = $('ff').checked, fn = $('fn') && $('fn').checked;
    let rows = F.filter(f => (!fp || f.priority === fp) && (!fs || f.severity === fs) && (!fc || f.category === fc) &&
      (!fh || f.host === fh) && (!ff || f.fixed_version || f.category !== 'package') && (!fn || f.status === 'new') &&
      (!q || [f.title, f.host, f.package, f.advisory, (f.cves || []).join(' '), f.check_id, hostName[f.host]].join(' ').toLowerCase().includes(q)));
    rows.sort((a, b) => {
      let x = a[sortKey], y = b[sortKey];
      if (sortKey === 'severity') { x = -sevRank(x); y = -sevRank(y); }
      if (sortKey === 'priority') { x = -prioRank(x); y = -prioRank(y); }
      if (x == null) x = ''; if (y == null) y = '';
      return (x > y ? 1 : x < y ? -1 : 0) * sortDir || b.risk - a.risk;
    });
    return rows;
  }
  function detail(f) {
    const items = [
      ['Where', where(f) + (hostName[f.host] ? ' (' + esc(hostName[f.host]) + ')' : '')],
      ['Check', `<span class="mono">${esc(f.check_id)}</span>${f.advisory ? ' &middot; ' + esc(f.advisory) : ''}`],
      f.package ? ['Package', `${esc((f.binaries || []).join(', ') || f.package)} <span class="mono">${esc(f.installed_version || '')}</span>`] : null,
      f.fixed_version ? ['Fixed in', `<span class="mono">${esc(f.fixed_version)}</span>`] : (f.category === 'package' ? ['Fixed in', 'No fix released yet'] : null),
      f.cves && f.cves.length ? ['CVEs', f.cves.slice(0, 30).map(cveLink).join(', ') + (f.cves.length > 30 ? ' ...' : '')] : null,
      ['Scoring', `risk ${f.risk} &middot; ${esc(f.severity)}${f.cvss != null ? ' &middot; CVSS ' + f.cvss : ''}${f.epss != null ? ' &middot; EPSS ' + (f.epss * 100).toFixed(1) + '%' : ''}${f.kev ? ' &middot; in CISA KEV' : ''}${f.exposed ? ' &middot; network-exposed' : ''}`],
      f.evidence ? ['Evidence', esc(f.evidence)] : null,
      f.description ? ['Details', esc(f.description).replace(/\n/g, '<br>')] : null,
      ['Remediation', esc(f.remediation)],
      f.references && f.references.length ? ['References', f.references.slice(0, 6).map(r => `<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`).join('<br>')] : null,
    ].filter(Boolean);
    return '<dl class="kv">' + items.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('') + '</dl>';
  }
  function draw() {
    const rows = filtered();
    $('fcount').textContent = rows.length === F.length ? F.length : rows.length + ' of ' + F.length;
    if (!rows.length) { $('tb').innerHTML = `<tr><td colspan="6" class="empty">${F.length ? 'No findings match these filters.' : 'No findings. Nice work.'}</td></tr>`; $('more').hidden = true; return; }
    $('tb').innerHTML = rows.slice(0, shown).map(f => `
      <tr class="row" data-k="${esc(f.key)}"><td class="risk">${Number(f.risk).toFixed(1)}</td>
      <td><span class="badge p-${esc(f.priority)}">${PL[f.priority] || ''}</span></td>
      <td><span class="badge sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td class="mono">${where(f)}</td><td class="title">${esc(f.title)}${flags(f)}</td>
      <td class="mono">${f.fixed_version ? esc(f.fixed_version) : (f.category === 'package' ? '<span class="meta">none yet</span>' : '')}</td></tr>
      ${open.has(f.key) ? `<tr class="detail"><td colspan="6">${detail(f)}</td></tr>` : ''}`).join('');
    $('more').hidden = rows.length <= shown;
    $('more').textContent = `Show more (${rows.length - shown} remaining)`;
  }
  ['q', 'fp', 'fs', 'fc', 'fh', 'ff', 'fn'].forEach(id => { const el = $(id); if (el) el.addEventListener('input', () => { shown = 150; draw(); }); });
  $('more').onclick = () => { shown += 300; draw(); };
  $('tb').addEventListener('click', e => { const tr = e.target.closest('tr.row'); if (!tr || e.target.closest('a')) return;
    const k = tr.dataset.k; open.has(k) ? open.delete(k) : open.add(k); draw(); });
  document.querySelectorAll('th[data-k]').forEach(th => th.onclick = () => {
    const k = th.dataset.k; sortDir = sortKey === k ? -sortDir : (k === 'host' || k === 'title' ? 1 : -1); sortKey = k; draw(); });
  draw();
})();
</script>
</body>
</html>
"""
