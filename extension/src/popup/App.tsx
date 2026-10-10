// Toolbar popup (FEATURE 9). A compact mission-control summary for the current
// tab + account: trust score, current-site risk, detected agents/MCP, active
// findings, recent alerts, and quick actions — all backed by real data from the
// background worker (synced scans, live page scan, notifications).

import { useEffect, useState } from 'react';
import {
  Bot, Boxes, ShieldAlert, Activity, ExternalLink, PanelRight, RefreshCw,
  Search, FileText, Settings as SettingsIcon, LogOut, Bell, Loader2, KeyRound,
} from 'lucide-react';
import { send } from '../shared/messages';
import type { BackgroundState, PageScan } from '../shared/messages';
import type { Settings } from '../shared/types';
import { Logo, ScoreRing, Card, Stat, Btn, SevBadge, relTime, sevColor, trustSeverity } from '../ui/components';

export function App() {
  const [state, setState] = useState<BackgroundState | null>(null);
  const [page, setPage] = useState<PageScan | null>(null);
  const [pageLoading, setPageLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [showCode, setShowCode] = useState(false);
  const [code, setCode] = useState('');
  const [err, setErr] = useState<string | null>(null);

  const refresh = async () => setState(await send({ type: 'GET_STATE' }));

  useEffect(() => {
    void refresh();
    send({ type: 'ANALYZE_ACTIVE_PAGE' })
      .then(setPage)
      .catch(() => undefined)
      .finally(() => setPageLoading(false));
  }, []);

  const latest = state?.scans[0] ?? null;
  const trust = latest?.trustScore ?? null;
  const siteRisk = page ? Math.max(0, ...page.agents.map((a) => a.riskScore), ...page.mcp.map((m) => m.riskScore)) : 0;

  const signIn = async () => {
    setErr(null);
    setBusy('signin');
    try {
      await send({ type: 'SIGN_IN' });
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const signInCode = async () => {
    setErr(null);
    setBusy('signin');
    try {
      await send({ type: 'SIGN_IN_CODE', token: code.trim() });
      setShowCode(false);
      setCode('');
      await refresh();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const openSidePanel = async () => {
    // Must run inside the user gesture, so open directly from the popup.
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.windowId != null) await chrome.sidePanel.open({ windowId: tab.windowId });
      window.close();
    } catch {
      await send({ type: 'OPEN_SIDE_PANEL' }).catch(() => undefined);
    }
  };

  const analyzePage = async () => {
    setPageLoading(true);
    try {
      setPage(await send({ type: 'ANALYZE_ACTIVE_PAGE' }));
    } finally {
      setPageLoading(false);
    }
  };

  return (
    <div className="bg-app text-strong fade-in" style={{ padding: 14, minHeight: 200 }}>
      {/* Header */}
      <div className="flex items-center gap-2" style={{ marginBottom: 12 }}>
        <Logo size={26} />
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 800, fontSize: 15 }}>Sentinel</div>
          <div className="text-faint" style={{ fontSize: 10.5 }}>AI Security Assistant</div>
        </div>
        {state?.signedIn ? (
          <button title={state.account?.email ?? 'Account'} onClick={() => send({ type: 'SIGN_OUT' }).then(refresh)}
            className="btn-ghost flex items-center gap-1" style={{ padding: '5px 9px', fontSize: 11 }}>
            <LogOut size={12} /> {state.account?.email?.split('@')[0] ?? 'Account'}
          </button>
        ) : null}
      </div>

      {err ? <div className="sev-critical fade-in" style={{ fontSize: 11, padding: '7px 10px', borderRadius: 9, marginBottom: 10 }}>{err}</div> : null}

      {/* Signed-out connect card */}
      {state && !state.signedIn ? (
        <Card className="fade-in" style={{ marginBottom: 12 }}>
          <div className="flex items-center gap-2" style={{ marginBottom: 8 }}>
            <ShieldAlert size={16} color="#7dd3fc" />
            <span style={{ fontWeight: 700, fontSize: 13 }}>Connect your account</span>
          </div>
          <p className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.5, margin: '0 0 10px' }}>
            Sign in to sync scans, run cloud analysis, and use the Security Copilot. Prompt Shield &amp; secret detection work without an account.
          </p>
          <div className="flex gap-2">
            <Btn variant="brand" onClick={signIn} disabled={busy === 'signin'} className="flex items-center justify-center gap-1" >
              {busy === 'signin' ? <Loader2 size={13} className="spin" /> : null} Connect
            </Btn>
            <Btn onClick={() => setShowCode((v) => !v)} className="flex items-center gap-1"><KeyRound size={13} /> Paste code</Btn>
          </div>
          {showCode ? (
            <div className="flex gap-2" style={{ marginTop: 8 }}>
              <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="sk_sentinel_…"
                style={{ flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 9, padding: '7px 9px', color: '#e8eef6', fontSize: 11, fontFamily: 'ui-monospace' }} />
              <Btn variant="brand" onClick={signInCode}>Go</Btn>
            </div>
          ) : null}
        </Card>
      ) : null}

      {/* Trust + site risk */}
      <div className="flex gap-2" style={{ marginBottom: 10 }}>
        <Card className="flex items-center gap-3" >
          {trust !== null ? <ScoreRing score={trust} size={72} /> : (
            <div className="flex flex-col items-center justify-center" style={{ width: 72, height: 72 }}>
              <ShieldAlert size={22} color="#64748b" />
              <span className="text-faint" style={{ fontSize: 9, marginTop: 4 }}>No scans</span>
            </div>
          )}
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: '#94a3b8' }}>Latest repo</div>
            <div style={{ fontSize: 12, fontWeight: 700 }}>{latest?.repo ?? '—'}</div>
            {latest ? <div className="text-faint" style={{ fontSize: 10, marginTop: 3 }}>Grade {latest.grade ?? '—'} · {relTime(latest.createdAt)}</div> : null}
          </div>
        </Card>
      </div>

      {/* Current site */}
      <Card style={{ marginBottom: 10 }}>
        <div className="flex items-center gap-2" style={{ marginBottom: 8 }}>
          <Activity size={14} color="#7dd3fc" />
          <span style={{ fontWeight: 700, fontSize: 12.5, flex: 1 }}>Current site</span>
          {pageLoading ? <Loader2 size={13} className="spin" color="#64748b" /> : (
            <span style={{ fontSize: 10.5, fontWeight: 700, color: sevColor[trustSeverity(100 - siteRisk)] }}>
              {siteRisk === 0 ? 'Clean' : `Risk ${siteRisk}`}
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <Stat value={page?.agents.length ?? 0} label="Agents" color="#a371f7" />
          <Stat value={page?.mcp.length ?? 0} label="MCP" color="#56d4dd" />
          <Stat value={latest?.findingsCount ?? 0} label="Findings" color={(latest?.findingsCount ?? 0) > 0 ? '#f97316' : '#3fb950'} />
        </div>
        {page && page.agents.length > 0 ? (
          <div className="flex flex-wrap gap-1" style={{ marginTop: 9 }}>
            {page.agents.slice(0, 4).map((a, i) => (
              <span key={i} className="flex items-center gap-1" style={{ fontSize: 10, padding: '3px 7px', borderRadius: 6, background: 'rgba(163,113,247,0.14)', border: '1px solid rgba(163,113,247,0.35)', color: '#d6bcfa' }}>
                <Bot size={10} /> {a.framework}
              </span>
            ))}
          </div>
        ) : null}
      </Card>

      {/* Recent alerts */}
      <Card style={{ marginBottom: 10 }}>
        <div className="flex items-center gap-2" style={{ marginBottom: 8 }}>
          <Bell size={14} color="#7dd3fc" />
          <span style={{ fontWeight: 700, fontSize: 12.5, flex: 1 }}>Recent alerts</span>
          {state && state.unread > 0 ? <span className="sev-critical" style={{ fontSize: 10, padding: '1px 7px', borderRadius: 999 }}>{state.unread}</span> : null}
        </div>
        {state && state.notifications.length > 0 ? (
          <div className="flex flex-col gap-2">
            {state.notifications.slice(0, 3).map((n) => (
              <div key={n.id} className="flex items-start gap-2">
                <SevBadge sev={n.severity} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11.5, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{n.title}</div>
                  <div className="text-faint" style={{ fontSize: 10 }}>{relTime(n.createdAt)}</div>
                </div>
              </div>
            ))}
          </div>
        ) : <div className="text-faint" style={{ fontSize: 11 }}>No alerts yet.</div>}
      </Card>

      {/* Quick actions */}
      <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 7 }}>
        <Btn onClick={analyzePage} className="flex items-center justify-center gap-1"><Search size={13} /> Analyze page</Btn>
        <Btn onClick={openSidePanel} className="flex items-center justify-center gap-1"><PanelRight size={13} /> Side panel</Btn>
        <Btn onClick={() => send({ type: 'OPEN_DASHBOARD', path: '/agent-security' })} className="flex items-center justify-center gap-1"><RefreshCw size={13} /> Run scan</Btn>
        <Btn onClick={() => send({ type: 'OPEN_DASHBOARD', path: '/results' })} className="flex items-center justify-center gap-1"><FileText size={13} /> Findings</Btn>
        <Btn onClick={() => send({ type: 'OPEN_DASHBOARD', path: '/dashboard' })} className="flex items-center justify-center gap-1"><ExternalLink size={13} /> Dashboard</Btn>
        <Btn onClick={() => setShowSettings((v) => !v)} className="flex items-center justify-center gap-1"><SettingsIcon size={13} /> Settings</Btn>
      </div>

      {showSettings && state ? <SettingsPanel settings={state.settings} onChange={refresh} /> : null}

      <div className="text-faint" style={{ fontSize: 9.5, textAlign: 'center', marginTop: 12 }}>
        <Boxes size={9} style={{ display: 'inline', verticalAlign: 'middle' }} /> Detection runs locally · synced to your Sentinel dashboard
      </div>
    </div>
  );
}

function SettingsPanel({ settings, onChange }: { settings: Settings; onChange: () => void }) {
  const [s, setS] = useState(settings);
  const toggle = async (key: keyof Settings) => {
    if (typeof s[key] !== 'boolean') return;
    const next = { ...s, [key]: !s[key] };
    setS(next);
    await send({ type: 'SET_SETTINGS', settings: { [key]: next[key] } });
    onChange();
  };
  const setUrl = async (url: string) => {
    setS({ ...s, dashboardUrl: url });
    await send({ type: 'SET_SETTINGS', settings: { dashboardUrl: url } });
    onChange();
  };
  const rows: [keyof Settings, string][] = [
    ['promptShield', 'Prompt Shield'],
    ['secretGuard', 'Secret leak prevention'],
    ['githubOverlay', 'GitHub overlay'],
    ['notifications', 'Notifications'],
  ];
  return (
    <Card className="fade-in" style={{ marginTop: 10 }}>
      {rows.map(([k, label]) => (
        <label key={k} className="flex items-center justify-between" style={{ padding: '5px 0', fontSize: 12 }}>
          <span>{label}</span>
          <input type="checkbox" checked={Boolean(s[k])} onChange={() => toggle(k)} />
        </label>
      ))}
      <div style={{ marginTop: 6 }}>
        <div className="text-faint" style={{ fontSize: 10, marginBottom: 4 }}>Dashboard URL</div>
        <input value={s.dashboardUrl} onChange={(e) => setUrl(e.target.value)}
          style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 8, padding: '6px 8px', color: '#e8eef6', fontSize: 11, fontFamily: 'ui-monospace' }} />
      </div>
    </Card>
  );
}
