// GitHub Security Overlay content script (FEATURE 3).
//
// On any github.com/<owner>/<repo> page it injects a Sentinel card showing the
// repo's real trust posture: it asks the background worker for the signed-in
// user's synced scans (GET /api/extension/scans) and matches the current repo.
// If the repo has been scanned it renders trust score, grade, agent/MCP counts,
// critical findings and latest-scan time; otherwise it offers a one-click
// "Scan with Sentinel" that runs the real /api/agent-scan and re-renders.

import { createOverlay, escapeHtml, sevColor } from '../shared/ui';
import { getSettings } from '../shared/storage';
import { send } from '../shared/messages';
import type { SyncedScan, Severity } from '../shared/types';

const RESERVED = new Set([
  'settings', 'marketplace', 'notifications', 'explore', 'topics', 'collections',
  'sponsors', 'features', 'about', 'pricing', 'login', 'join', 'new', 'orgs',
  'organizations', 'dashboard', 'search', 'apps', 'codespaces', 'account',
]);

function currentRepo(): { owner: string; repo: string } | null {
  const parts = location.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const [owner, repo] = parts;
  if (RESERVED.has(owner.toLowerCase())) return null;
  if (repo.includes('.') && /\.(json|md)$/i.test(repo)) return null;
  return { owner, repo: repo.replace(/\.git$/, '') };
}

function gradeColor(grade: string | null): string {
  switch ((grade ?? '').toUpperCase()) {
    case 'A': return '#3fb950';
    case 'B': return '#84cc16';
    case 'C': return '#eab308';
    case 'D': return '#f97316';
    default: return '#ef4444';
  }
}

function trustSeverity(trust: number): Severity {
  if (trust >= 90) return 'low';
  if (trust >= 70) return 'medium';
  if (trust >= 50) return 'high';
  return 'critical';
}

const overlay = createOverlay('sentinel-github-overlay');
overlay.host.style.cssText =
  'all: initial; position: fixed; z-index: 2147483600; bottom: 18px; right: 18px; width: 320px;';

let collapsed = false;

function shell(inner: string): string {
  return `
    <div style="background:linear-gradient(160deg,#0b1220,#060b18);border:1px solid rgba(56,189,248,0.25);
      border-radius:16px;box-shadow:0 18px 50px rgba(0,0,0,0.55);overflow:hidden;font-family:ui-sans-serif,system-ui;">
      <div id="hdr" style="display:flex;align-items:center;gap:8px;padding:11px 13px;cursor:pointer;
        background:rgba(255,255,255,0.02);border-bottom:1px solid rgba(255,255,255,0.06);">
        <div style="width:22px;height:22px;border-radius:7px;background:linear-gradient(135deg,#22d3ee,#0ea5e9);
          display:flex;align-items:center;justify-content:center;font-size:13px;">🛡️</div>
        <span style="font:800 13px ui-sans-serif;color:#fff;flex:1;">Sentinel</span>
        <span style="font:600 11px ui-sans-serif;color:#64748b;">${collapsed ? '▴' : '▾'}</span>
      </div>
      <div id="body" style="display:${collapsed ? 'none' : 'block'};padding:13px;">${inner}</div>
    </div>`;
}

function stat(label: string, value: string, color = '#e8eef6'): string {
  return `<div style="flex:1;text-align:center;">
    <div style="font:800 17px ui-sans-serif;color:${color};">${value}</div>
    <div style="font:600 10px ui-sans-serif;color:#64748b;text-transform:uppercase;letter-spacing:0.04em;">${label}</div>
  </div>`;
}

function renderScanned(repo: { owner: string; repo: string }, scan: SyncedScan): void {
  const sev = trustSeverity(scan.trustScore);
  overlay.mount.innerHTML = shell(`
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
      <div style="position:relative;width:62px;height:62px;border-radius:999px;flex-shrink:0;
        background:conic-gradient(${sevColor(sev)} ${scan.trustScore * 3.6}deg, rgba(255,255,255,0.08) 0);
        display:flex;align-items:center;justify-content:center;">
        <div style="width:48px;height:48px;border-radius:999px;background:#0b1220;display:flex;flex-direction:column;align-items:center;justify-content:center;">
          <span style="font:800 18px ui-sans-serif;color:${sevColor(sev)};">${scan.trustScore}</span>
          <span style="font:600 8px ui-sans-serif;color:#64748b;">TRUST</span>
        </div>
      </div>
      <div>
        <div style="font:700 13px ui-sans-serif;color:#e8eef6;">${escapeHtml(repo.owner)}/${escapeHtml(repo.repo)}</div>
        <div style="display:inline-flex;align-items:center;gap:6px;margin-top:5px;">
          <span style="font:800 12px ui-sans-serif;padding:3px 9px;border-radius:7px;color:#04121f;background:${gradeColor(scan.grade)};">Grade ${escapeHtml(scan.grade ?? '—')}</span>
        </div>
      </div>
    </div>
    <div style="display:flex;gap:6px;padding:11px;border-radius:12px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);margin-bottom:11px;">
      ${stat('Agents', String(scan.agentsCount), '#a371f7')}
      ${stat('MCP', String(scan.mcpCount), '#56d4dd')}
      ${stat('Findings', String(scan.findingsCount), scan.findingsCount > 0 ? '#f97316' : '#3fb950')}
    </div>
    <div style="font:500 11px ui-sans-serif;color:#64748b;margin-bottom:11px;">
      Latest scan ${new Date(scan.createdAt).toLocaleString()} · via ${escapeHtml(scan.source)}
    </div>
    <div style="display:flex;gap:7px;">
      <button id="rescan" style="flex:1;padding:9px;border:none;border-radius:10px;cursor:pointer;font:700 12px ui-sans-serif;background:linear-gradient(135deg,#22d3ee,#0ea5e9);color:#04121f;">Re-scan</button>
      <button id="dash" style="flex:1;padding:9px;border-radius:10px;cursor:pointer;font:700 12px ui-sans-serif;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);color:#e8eef6;">Dashboard</button>
    </div>`);
  wireHeader(repo);
  overlay.mount.querySelector('#rescan')?.addEventListener('click', () => runScan(repo));
  overlay.mount.querySelector('#dash')?.addEventListener('click', () =>
    send({ type: 'OPEN_DASHBOARD', path: '/agent-security' }).catch(() => undefined),
  );
}

function renderUnscanned(repo: { owner: string; repo: string }, signedIn: boolean): void {
  overlay.mount.innerHTML = shell(`
    <div style="font:700 13px ui-sans-serif;color:#e8eef6;margin-bottom:6px;">${escapeHtml(repo.owner)}/${escapeHtml(repo.repo)}</div>
    <p style="margin:0 0 12px;font:400 12px/1.5 ui-sans-serif;color:#94a3b8;">
      ${signedIn ? 'This repository hasn’t been scanned yet. Run Sentinel’s agent-security analysis to get a trust score, agent/MCP inventory and findings.' : 'Connect your Sentinel account to scan this repository for AI-agent &amp; MCP risk.'}
    </p>
    <button id="act" style="width:100%;padding:11px;border:none;border-radius:11px;cursor:pointer;font:700 13px ui-sans-serif;background:linear-gradient(135deg,#22d3ee,#0ea5e9);color:#04121f;">
      ${signedIn ? 'Scan with Sentinel' : 'Connect & scan'}
    </button>`);
  wireHeader(repo);
  overlay.mount.querySelector('#act')?.addEventListener('click', async () => {
    if (!signedIn) {
      await send({ type: 'OPEN_DASHBOARD', path: '/connect/extension' }).catch(() => undefined);
      return;
    }
    runScan(repo);
  });
}

function renderLoading(label: string): void {
  overlay.mount.innerHTML = shell(`
    <div style="display:flex;align-items:center;gap:10px;padding:6px 0;">
      <div style="width:18px;height:18px;border:2px solid rgba(255,255,255,0.15);border-top-color:#22d3ee;border-radius:999px;animation:sentinel-spin 0.8s linear infinite;"></div>
      <span style="font:600 12px ui-sans-serif;color:#94a3b8;">${escapeHtml(label)}</span>
    </div>
    <style>@keyframes sentinel-spin{to{transform:rotate(360deg)}}</style>`);
  wireHeader(currentRepo());
}

function renderError(repo: { owner: string; repo: string }, msg: string): void {
  overlay.mount.innerHTML = shell(`
    <div style="font:700 12px ui-sans-serif;color:#fca5a5;margin-bottom:6px;">Couldn’t load Sentinel</div>
    <p style="margin:0 0 10px;font:400 12px/1.5 ui-sans-serif;color:#94a3b8;">${escapeHtml(msg)}</p>
    <button id="retry" style="width:100%;padding:9px;border-radius:10px;cursor:pointer;font:700 12px ui-sans-serif;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);color:#e8eef6;">Retry</button>`);
  wireHeader(repo);
  overlay.mount.querySelector('#retry')?.addEventListener('click', () => load(repo));
}

function wireHeader(repo: { owner: string; repo: string } | null): void {
  overlay.mount.querySelector('#hdr')?.addEventListener('click', () => {
    collapsed = !collapsed;
    const body = overlay.mount.querySelector('#body') as HTMLElement | null;
    if (body) body.style.display = collapsed ? 'none' : 'block';
    const caret = overlay.mount.querySelector('#hdr span:last-child');
    if (caret) caret.textContent = collapsed ? '▴' : '▾';
    void repo;
  });
}

async function runScan(repo: { owner: string; repo: string }): Promise<void> {
  renderLoading(`Scanning ${repo.owner}/${repo.repo}…`);
  try {
    const res = await send({ type: 'API_AGENT_SCAN', repoUrl: `https://github.com/${repo.owner}/${repo.repo}` });
    const trust = Math.max(0, 100 - res.result.riskScore);
    renderScanned(repo, {
      id: 'live',
      repo: `${repo.owner}/${repo.repo}`,
      commitSha: res.repo.commitSha,
      trustScore: trust,
      riskScore: res.result.riskScore,
      grade: res.result.grade,
      findingsCount: res.result.findings.length,
      agentsCount: res.result.agents.length,
      mcpCount: res.result.mcpServers.length,
      source: 'extension',
      createdAt: new Date().toISOString(),
    });
  } catch (e) {
    renderError(repo, e instanceof Error ? e.message : String(e));
  }
}

async function load(repo: { owner: string; repo: string }): Promise<void> {
  const settings = await getSettings();
  if (!settings.githubOverlay) {
    overlay.host.style.display = 'none';
    return;
  }
  overlay.host.style.display = 'block';
  renderLoading('Checking Sentinel…');
  try {
    const state = await send({ type: 'GET_STATE' });
    if (!state.signedIn) {
      renderUnscanned(repo, false);
      return;
    }
    const match = state.scans.find((s) => s.repo.toLowerCase() === `${repo.owner}/${repo.repo}`.toLowerCase());
    if (match) renderScanned(repo, match);
    else renderUnscanned(repo, true);
  } catch (e) {
    renderError(repo, e instanceof Error ? e.message : String(e));
  }
}

// GitHub is a SPA — re-evaluate the repo on client-side navigation.
let lastPath = '';
function tick(): void {
  if (location.pathname === lastPath) return;
  lastPath = location.pathname;
  const repo = currentRepo();
  if (repo) void load(repo);
  else overlay.host.style.display = 'none';
}
const obs = new MutationObserver(() => tick());
obs.observe(document.body, { childList: true, subtree: true });
tick();
