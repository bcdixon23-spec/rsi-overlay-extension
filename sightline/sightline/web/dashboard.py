"""Dashboard page served at / by `sightline serve`."""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sightline Dashboard</title>
<style>
:root { --bg:#f6f7f9; --panel:#fff; --ink:#14171c; --muted:#5d6673; --line:#e3e6eb; --accent:#3355dd; --chip:#eef1f5;
  --now:#c0262d; --soon:#d06a00; --plan:#2f74c0; --mon:#7a8391; --ok:#1f8a4c; --mono: ui-monospace, Menlo, Consolas, monospace; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1216; --panel:#171b21; --ink:#e8ebf0; --muted:#98a2b3; --line:#262c35;
  --accent:#7b96ff; --chip:#222831; --now:#ff5a5f; --soon:#ff9d2e; --plan:#5aa2f0; --mon:#8b95a5; --ok:#3ccf7a; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
.wrap { max-width:1200px; margin:0 auto; padding:24px 16px 64px; }
h1 { font-size:22px; margin:0 0 4px; } h1 span { color:var(--accent); }
h2 { font-size:16px; margin:28px 0 12px; }
.muted { color:var(--muted); font-size:13px; }
.grid { display:grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap:16px; }
@media (max-width: 860px) { .grid { grid-template-columns: 1fr; } }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:16px; }
label { display:block; font-size:13px; color:var(--muted); margin:10px 0 4px; }
input[type=text], select { width:100%; font:inherit; color:var(--ink); background:var(--bg); border:1px solid var(--line); border-radius:8px; padding:8px 10px; }
.row { display:grid; grid-template-columns: 1fr 1fr; gap:12px; }
@media (max-width: 560px) { .row { grid-template-columns: 1fr; } }
.check { display:flex; gap:8px; align-items:center; color:var(--ink); font-size:14px; margin-top:10px; }
button { font:inherit; border-radius:8px; border:1px solid var(--line); background:var(--panel); color:var(--ink); padding:8px 14px; cursor:pointer; }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; margin-top:14px; }
details summary { cursor:pointer; color:var(--muted); font-size:13px; margin-top:12px; }
.log { font-family:var(--mono); font-size:12px; background:var(--chip); border-radius:8px; padding:10px; max-height:220px; overflow:auto; white-space:pre-wrap; margin-top:8px; }
.job { border-top:1px solid var(--line); padding-top:10px; margin-top:10px; } .job:first-child { border:0; margin:0; padding:0; }
.badge { display:inline-block; font-size:11px; font-weight:600; padding:1px 8px; border-radius:999px; background:var(--chip); color:var(--muted); }
.b-now { color:var(--now); } .b-soon { color:var(--soon); } .b-ok { background:var(--ok); color:#fff; } .b-run { background:var(--accent); color:#fff; } .b-fail { background:var(--now); color:#fff; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }
th { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }
td.num { font-variant-numeric:tabular-nums; text-align:right; } th.num { text-align:right; }
td.name { white-space:normal; min-width:160px; }
.tbl { overflow-x:auto; }
a { color:var(--accent); text-decoration:none; } a:hover { text-decoration:underline; }
.err { color:var(--now); font-size:13px; margin-top:8px; }
.kv { display:grid; grid-template-columns:auto 1fr; gap:4px 12px; font-size:13px; } .kv b { font-variant-numeric:tabular-nums; }
</style>
</head>
<body>
<div class="wrap">
  <h1><span>Sightline</span> dashboard</h1>
  <div class="muted">Agentless vulnerability and exposure scanning. Only scan systems you own or are authorized to test.</div>
  <div class="grid">
    <div>
      <h2>New scan</h2>
      <form class="panel" id="form">
        <label for="targets">Targets</label>
        <input type="text" id="targets" placeholder="192.168.1.0/24, web01.internal, 10.0.0.5-40">
        <div class="row">
          <div><label for="name">Name (optional)</label><input type="text" id="name" placeholder="Office network"></div>
          <div><label for="ports">Ports</label><select id="ports"><option value="default">Common exposure ports (~75)</option><option value="1-1024">1-1024</option><option value="all">All 65535</option></select></div>
        </div>
        <div class="check"><input type="checkbox" id="local"><label for="local" style="margin:0;color:inherit">Also run a credentialed scan of this machine</label></div>
        <details><summary>Credentialed scanning over SSH</summary>
          <div class="row">
            <div><label for="ssh_user">SSH user</label><input type="text" id="ssh_user" placeholder="ops"></div>
            <div><label for="ssh_key">SSH key path</label><input type="text" id="ssh_key" placeholder="~/.ssh/id_ed25519"></div>
          </div>
          <div class="check"><input type="checkbox" id="sudo"><label for="sudo" style="margin:0;color:inherit">Use sudo -n for full configuration coverage</label></div>
        </details>
        <button class="primary" type="submit">Start scan</button>
        <div class="err" id="ferr"></div>
      </form>
    </div>
    <div>
      <h2>Activity</h2>
      <div class="panel" id="jobs"><div class="muted">No scans running.</div></div>
      <h2>Vulnerability data</h2>
      <div class="panel" id="db"><div class="muted">Loading...</div></div>
    </div>
  </div>
  <h2>Scan history</h2>
  <div class="panel tbl"><table>
    <thead><tr><th>Started</th><th>Name</th><th class="num">Hosts</th><th class="num">Fix now</th><th class="num">Fix soon</th><th class="num">Total</th><th class="num">New</th><th class="num">Fixed</th><th></th></tr></thead>
    <tbody id="scans"><tr><td colspan="9" class="muted">Loading...</td></tr></tbody>
  </table></div>
</div>
<script>
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const api = (path, opts = {}) => fetch(path, Object.assign({credentials: 'same-origin'}, opts)).then(r => r.json().then(j => r.ok ? j : Promise.reject(j.error || r.statusText)));
const when = s => s ? new Date(s).toLocaleString() : '';
async function loadScans() {
  const rows = await api('/api/scans');
  document.getElementById('scans').innerHTML = rows.length ? rows.map(r => {
    const s = r.summary || {}, p = s.by_priority || {};
    return `<tr><td>${esc(when(r.started))}</td><td class="name">${esc(r.name)}</td><td class="num">${s.hosts_alive ?? ''}</td>
      <td class="num"><span class="b-now">${p['fix-now'] || 0}</span></td><td class="num"><span class="b-soon">${p['fix-soon'] || 0}</span></td>
      <td class="num">${s.findings ?? ''}</td><td class="num">${s.new ?? ''}</td><td class="num">${s.fixed ?? ''}</td>
      <td><a href="/scans/${encodeURIComponent(r.id)}" target="_blank">Report</a> &middot; <a href="/api/scans/${encodeURIComponent(r.id)}" target="_blank">JSON</a>
      &middot; <a href="#" data-del="${esc(r.id)}">Delete</a></td></tr>`;
  }).join('') : '<tr><td colspan="9" class="muted">No scans yet - start one above.</td></tr>';
}
async function loadJobs() {
  const jobs = await api('/api/jobs');
  const el = document.getElementById('jobs');
  if (!jobs.length) { el.innerHTML = '<div class="muted">No scans started from this dashboard yet.</div>'; return false; }
  el.innerHTML = jobs.slice(0, 5).map(j => `<div class="job">
    <span class="badge ${j.status === 'running' ? 'b-run' : j.status === 'done' ? 'b-ok' : 'b-fail'}">${esc(j.status)}</span>
    <b>${esc(j.targets.join(', '))}</b> <span class="muted">${esc(when(j.started))}</span>
    ${j.scan_id ? ` &middot; <a href="/scans/${encodeURIComponent(j.scan_id)}" target="_blank">open report</a>` : ''}
    ${j.error ? `<div class="err">${esc(j.error)}</div>` : ''}
    ${j.status === 'running' ? `<div class="log">${esc(j.log.slice(-60).join('\n'))}</div>` : ''}</div>`).join('');
  return jobs.some(j => j.status === 'running');
}
async function loadDb() {
  const d = await api('/api/db');
  const rel = (d.releases || []).map(r => `${esc(r[0])} ${esc(r[1])}`).join(', ');
  document.getElementById('db').innerHTML = `<div class="kv">
    <span>Advisories</span><b>${d.advisories}</b><span>Known exploited</span><b>${d.kev}</b><span>EPSS scores</span><b>${d.epss}</b>
    <span>Updated</span><span>${esc(when(d.osv_updated) || 'never')}</span><span>Coverage</span><span>${rel || 'none yet - fetched on first credentialed scan'}</span></div>`;
}
let polling = null;
async function tick() {
  const running = await loadJobs().catch(() => false);
  if (!running && polling) { clearInterval(polling); polling = null; loadScans(); loadDb(); }
}
document.getElementById('form').addEventListener('submit', async e => {
  e.preventDefault();
  const v = id => document.getElementById(id);
  v('ferr').textContent = '';
  try {
    await api('/api/scans', {method: 'POST', headers: {'Content-Type': 'application/json', 'X-Sightline': '1'},
      body: JSON.stringify({targets: v('targets').value, name: v('name').value, ports: v('ports').value, local: v('local').checked,
        ssh_user: v('ssh_user').value, ssh_key: v('ssh_key').value, sudo: v('sudo').checked})});
    if (!polling) polling = setInterval(tick, 1500);
    tick();
  } catch (err) { v('ferr').textContent = err; }
});
document.getElementById('scans').addEventListener('click', async e => {
  const id = e.target.dataset && e.target.dataset.del; if (!id) return; e.preventDefault();
  if (!confirm('Delete scan ' + id + '?')) return;
  await api('/api/scans/' + encodeURIComponent(id), {method: 'DELETE', headers: {'X-Sightline': '1'}}); loadScans();
});
loadScans(); loadDb(); tick().then(() => { if (!polling) polling = setInterval(tick, 1500); });
</script>
</body>
</html>
"""
