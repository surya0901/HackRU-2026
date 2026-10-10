// Side Panel (FEATURE 7 + 10) — a mini Heimdall dashboard with the Security
// Copilot. Tabs: Overview, Findings, Agents, MCP, Notifications, Activity,
// Copilot, Recent Scans. Every panel is backed by real data: synced scans from
// the dashboard, the live page agent/MCP scan, right-click analysis results, and
// the Anthropic-backed copilot grounded in the user's actual scan history.

import { useEffect, useRef, useState } from 'react';
import {
  LayoutGrid, Bug, Bot, Boxes, Bell, Activity as ActivityIcon, MessageSquare, History,
  Send, Loader2, ExternalLink, ShieldCheck, Trash2, RefreshCw,
} from 'lucide-react';
import { send } from '../shared/messages';
import type { BackgroundState, PageScan, AnalyzeResult, AnalyzeMode, CopilotTurn } from '../shared/messages';
import type { HeimdallNotification } from '../shared/types';
import { Logo, ScoreRing, Card, Stat, Btn, SevBadge, relTime, sevColor } from '../ui/components';

type Tab = 'overview' | 'findings' | 'agents' | 'mcp' | 'notifications' | 'activity' | 'copilot' | 'scans';

interface StoredAnalysis {
  mode: AnalyzeMode;
  content: string;
  result: AnalyzeResult | null;
  error?: string;
  ts: number;
}

const TABS: { id: Tab; label: string; icon: typeof Bug }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutGrid },
  { id: 'findings', label: 'Findings', icon: Bug },
  { id: 'agents', label: 'Agents', icon: Bot },
  { id: 'mcp', label: 'MCP', icon: Boxes },
  { id: 'copilot', label: 'Copilot', icon: MessageSquare },
  { id: 'notifications', label: 'Alerts', icon: Bell },
  { id: 'activity', label: 'Activity', icon: ActivityIcon },
  { id: 'scans', label: 'Scans', icon: History },
];

export function App() {
  const [tab, setTab] = useState<Tab>('overview');
  const [state, setState] = useState<BackgroundState | null>(null);
  const [page, setPage] = useState<PageScan | null>(null);
  const [analysis, setAnalysis] = useState<StoredAnalysis | null>(null);

  const refresh = async () => setState(await send({ type: 'GET_STATE' }));

  useEffect(() => {
    void refresh();
    send({ type: 'ANALYZE_ACTIVE_PAGE' }).then(setPage).catch(() => undefined);
    chrome.storage.local.get('heimdall.lastAnalysis').then((o) => {
      const a = o['heimdall.lastAnalysis'] as StoredAnalysis | undefined;
      if (a) {
        setAnalysis(a);
        setTab('findings');
      }
    });
    const onChange = (changes: { [k: string]: chrome.storage.StorageChange }, area: string) => {
      if (area === 'local' && changes['heimdall.lastAnalysis']) {
        setAnalysis(changes['heimdall.lastAnalysis'].newValue as StoredAnalysis);
        setTab('findings');
      }
      if (area === 'local' && changes['heimdall.notifications']) void refresh();
    };
    chrome.storage.onChanged.addListener(onChange);
    return () => chrome.storage.onChanged.removeListener(onChange);
  }, []);

  const latest = state?.scans[0] ?? null;

  return (
    <div className="bg-app text-strong" style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      {/* Header */}
      <div className="flex items-center gap-2" style={{ padding: '12px 14px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        <Logo size={24} />
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 800, fontSize: 14 }}>Heimdall</div>
          <div className="text-faint" style={{ fontSize: 10 }}>{state?.account?.email ?? (state?.signedIn ? 'Connected' : 'Not connected')}</div>
        </div>
        <button className="btn-ghost" style={{ padding: 7 }} onClick={refresh} title="Refresh"><RefreshCw size={13} /></button>
      </div>

      {/* Tabs */}
      <div className="flex" style={{ padding: '8px 8px 0', gap: 4, overflowX: 'auto', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          const badge = t.id === 'notifications' ? state?.unread ?? 0 : 0;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className="flex items-center gap-1"
              style={{
                position: 'relative', padding: '7px 10px', fontSize: 11.5, fontWeight: 600, whiteSpace: 'nowrap',
                color: active ? '#e8eef6' : '#64748b', borderBottom: active ? '2px solid #22d3ee' : '2px solid transparent',
                background: 'transparent', cursor: 'pointer',
              }}>
              <Icon size={13} /> {t.label}
              {badge > 0 ? <span className="sev-critical" style={{ fontSize: 9, padding: '0 5px', borderRadius: 999, marginLeft: 2 }}>{badge}</span> : null}
            </button>
          );
        })}
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 14 }} className="fade-in">
        {!state ? <Loading /> : null}
        {state && tab === 'overview' ? <Overview state={state} page={page} /> : null}
        {state && tab === 'findings' ? <Findings analysis={analysis} latest={latest} /> : null}
        {state && tab === 'agents' ? <Agents page={page} /> : null}
        {state && tab === 'mcp' ? <Mcp page={page} /> : null}
        {state && tab === 'copilot' ? <Copilot signedIn={state.signedIn} /> : null}
        {state && tab === 'notifications' ? <Notifications state={state} onChange={refresh} /> : null}
        {state && tab === 'activity' ? <ActivityFeed state={state} /> : null}
        {state && tab === 'scans' ? <Scans state={state} /> : null}
      </div>
    </div>
  );
}

function Loading() {
  return <div className="flex items-center gap-2 text-muted" style={{ fontSize: 12 }}><Loader2 size={14} className="spin" /> Loading…</div>;
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="text-faint" style={{ fontSize: 12, textAlign: 'center', padding: '24px 8px' }}>{children}</div>;
}

function Overview({ state, page }: { state: BackgroundState; page: PageScan | null }) {
  const latest = state.scans[0] ?? null;
  const siteRisk = page ? Math.max(0, ...page.agents.map((a) => a.riskScore), ...page.mcp.map((m) => m.riskScore), ...page.findings.map((f) => ({ critical: 90, high: 70, medium: 45, low: 20, info: 5 }[f.severity]))) : 0;
  return (
    <div className="flex flex-col gap-3">
      <Card className="flex items-center gap-4">
        {latest ? <ScoreRing score={latest.trustScore} /> : <ScoreRing score={0} label="N/A" />}
        <div>
          <div style={{ fontSize: 13, fontWeight: 700 }}>{latest?.repo ?? 'No scans yet'}</div>
          {latest ? (
            <>
              <div className="text-muted" style={{ fontSize: 11, marginTop: 3 }}>Grade {latest.grade ?? '—'} · risk {latest.riskScore}</div>
              <div className="text-faint" style={{ fontSize: 10, marginTop: 2 }}>{relTime(latest.createdAt)} · {latest.source}</div>
            </>
          ) : <div className="text-faint" style={{ fontSize: 11, marginTop: 3 }}>Scan a repo from the dashboard or GitHub overlay.</div>}
        </div>
      </Card>

      <Card>
        <SectionTitle icon={<ActivityIcon size={13} color="#7dd3fc" />} text="This page" right={`Risk ${siteRisk}`} />
        <div className="flex gap-2" style={{ marginTop: 8 }}>
          <Stat value={page?.agents.length ?? 0} label="Agents" color="#a371f7" />
          <Stat value={page?.mcp.length ?? 0} label="MCP" color="#56d4dd" />
          <Stat value={page?.findings.length ?? 0} label="Web signals" color="#f97316" />
        </div>
        <div className="text-faint" style={{ fontSize: 10, marginTop: 8, wordBreak: 'break-all' }}>{page?.origin ?? ''}</div>
        {page ? <div className="text-faint" style={{ fontSize: 10, marginTop: 6 }}>
          {page.verification.baselineTs ? `${page.verification.fixed.length} fixed · ${page.verification.added.length} new · ${page.verification.changed.length} evidence changed · ${page.verification.unchanged.length} unchanged` : 'Baseline saved for before/after verification'}
          <br />Passive DOM evidence only; headers, CORS and extension access can limit coverage.
        </div> : null}
        {page?.findings.slice(0, 3).map((finding) => <div key={finding.id} style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,0.08)' }}>
          <div className="flex items-center gap-2"><SevBadge sev={finding.severity} /><span style={{ fontSize: 11.5, fontWeight: 700 }}>{finding.title}</span></div>
          <div className="text-faint" style={{ fontSize: 10, marginTop: 4, wordBreak: 'break-word' }}>Evidence: {finding.evidence}</div>
        </div>)}
      </Card>

      <Card>
        <SectionTitle icon={<ShieldCheck size={13} color="#86efac" />} text="Protection" />
        <div className="flex flex-col gap-1" style={{ marginTop: 6, fontSize: 12 }}>
          <Toggle label="Passive website scan" on />
          <Toggle label="GitHub overlay" on={state.settings.githubOverlay} />
          <Toggle label="Notifications" on={state.settings.notifications} />
        </div>
      </Card>

      <Btn variant="brand" onClick={() => send({ type: 'OPEN_DASHBOARD', path: '/agent-security' })} className="flex items-center justify-center gap-1">
        <ExternalLink size={13} /> Open full dashboard
      </Btn>
    </div>
  );
}

function Toggle({ label, on }: { label: string; on: boolean }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted">{label}</span>
      <span style={{ fontSize: 10, fontWeight: 700, color: on ? '#86efac' : '#64748b' }}>{on ? 'ON' : 'OFF'}</span>
    </div>
  );
}

function SectionTitle({ icon, text, right }: { icon: React.ReactNode; text: string; right?: string }) {
  return (
    <div className="flex items-center gap-2">
      {icon}
      <span style={{ fontWeight: 700, fontSize: 12.5, flex: 1 }}>{text}</span>
      {right ? <span className="text-faint" style={{ fontSize: 11, fontWeight: 700 }}>{right}</span> : null}
    </div>
  );
}

function Findings({ analysis, latest }: { analysis: StoredAnalysis | null; latest: BackgroundState['scans'][number] | null }) {
  if (analysis?.result) {
    const r = analysis.result;
    return (
      <div className="flex flex-col gap-3">
        <Card>
          <div className="flex items-center gap-2" style={{ marginBottom: 6 }}>
            <SevBadge sev={r.severity} />
            <span style={{ fontWeight: 700, fontSize: 13 }}>Right-click analysis</span>
            {r.poweredByAnthropic ? <span className="text-faint" style={{ fontSize: 9, marginLeft: 'auto' }}>Claude</span> : null}
          </div>
          <p className="text-muted" style={{ fontSize: 12, lineHeight: 1.5, margin: 0 }}>{r.summary}</p>
        </Card>
        {r.findings.map((f, i) => (
          <Card key={i}>
            <div className="flex items-center gap-2" style={{ marginBottom: 5 }}>
              <SevBadge sev={f.severity} />
              <span style={{ fontWeight: 700, fontSize: 12.5 }}>{f.title}</span>
            </div>
            <p className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.5, margin: 0 }}>{f.detail}</p>
          </Card>
        ))}
        {r.fix ? (
          <Card>
            <div style={{ fontWeight: 700, fontSize: 12.5, marginBottom: 6, color: '#86efac' }}>Suggested secure fix</div>
            <pre style={{ margin: 0, fontSize: 11, lineHeight: 1.5, color: '#cbd5e1', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'ui-monospace' }}>{r.fix}</pre>
          </Card>
        ) : null}
      </div>
    );
  }
  if (analysis && !analysis.result) {
    return analysis.error
      ? <Card><div className="sev-critical" style={{ fontSize: 12, padding: 8, borderRadius: 8 }}>{analysis.error}</div></Card>
      : <div className="flex items-center gap-2 text-muted" style={{ fontSize: 12 }}><Loader2 size={14} className="spin" /> Analyzing selection…</div>;
  }
  return (
    <Empty>
      {latest ? <>Latest scan <b>{latest.repo}</b> has <b>{latest.findingsCount}</b> findings.<br />Open the dashboard for full detail, or right-click any code on a page → <i>Analyze with Heimdall</i>.</>
        : <>Highlight code, JSON, YAML or a stack trace on any page, right-click → <i>Analyze with Heimdall</i> to see findings here.</>}
    </Empty>
  );
}

function Agents({ page }: { page: PageScan | null }) {
  if (!page) return <Loading />;
  if (page.agents.length === 0) return <Empty>No AI agents or SDKs detected on this page.</Empty>;
  return (
    <div className="flex flex-col gap-3">
      {page.agents.map((a, i) => (
        <Card key={i}>
          <div className="flex items-center gap-2" style={{ marginBottom: 6 }}>
            <Bot size={15} color="#a371f7" />
            <span style={{ fontWeight: 700, fontSize: 13, flex: 1 }}>{a.framework}</span>
            <span style={{ fontSize: 10, fontWeight: 700, color: sevColor[a.riskScore >= 60 ? 'high' : a.riskScore >= 40 ? 'medium' : 'low'] }}>Risk {a.riskScore}</span>
          </div>
          <div className="flex flex-wrap gap-1" style={{ marginBottom: 6 }}>
            {a.capabilities.map((c) => (
              <span key={c} style={{ fontSize: 10, padding: '2px 7px', borderRadius: 6, background: 'rgba(56,189,248,0.12)', border: '1px solid rgba(56,189,248,0.3)', color: '#7dd3fc' }}>{c}</span>
            ))}
          </div>
          <div className="text-faint" style={{ fontSize: 10, fontFamily: 'ui-monospace', wordBreak: 'break-all' }}>evidence: {a.evidence}</div>
        </Card>
      ))}
    </div>
  );
}

function Mcp({ page }: { page: PageScan | null }) {
  if (!page) return <Loading />;
  if (page.mcp.length === 0) return <Empty>No MCP servers or tool manifests found on this origin.</Empty>;
  return (
    <div className="flex flex-col gap-3">
      {page.mcp.map((m, i) => (
        <Card key={i}>
          <div className="flex items-center gap-2" style={{ marginBottom: 6 }}>
            <Boxes size={15} color="#56d4dd" />
            <span style={{ fontWeight: 700, fontSize: 12.5, flex: 1, textTransform: 'uppercase' }}>{m.kind}</span>
            <span style={{ fontSize: 10, fontWeight: 700, color: sevColor[m.riskScore >= 60 ? 'high' : m.riskScore >= 40 ? 'medium' : 'low'] }}>Risk {m.riskScore}</span>
          </div>
          <div className="flex gap-2" style={{ marginBottom: 6 }}>
            <Stat value={m.toolCount ?? '?'} label="Tools" color="#56d4dd" />
            <Stat value={m.authenticated === null ? '?' : m.authenticated ? 'Yes' : 'No'} label="Auth" color={m.authenticated ? '#3fb950' : '#f97316'} />
          </div>
          <div className="text-faint" style={{ fontSize: 10, fontFamily: 'ui-monospace', wordBreak: 'break-all' }}>{m.url}</div>
        </Card>
      ))}
    </div>
  );
}

const SUGGESTED = [
  'Is this repository safe?',
  'What is MCP and why does it matter?',
  'Explain my latest critical finding.',
  'How do I fix a prompt-injection risk?',
];

function Copilot({ signedIn }: { signedIn: boolean }) {
  const [history, setHistory] = useState<CopilotTurn[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [history, busy]);

  const ask = async (q: string) => {
    if (!q.trim() || busy) return;
    setErr(null);
    const next: CopilotTurn[] = [...history, { role: 'user', content: q.trim() }];
    setHistory(next);
    setInput('');
    setBusy(true);
    try {
      const { reply } = await send({ type: 'API_COPILOT', history: next });
      setHistory([...next, { role: 'assistant', content: reply }]);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!signedIn) return <Empty>Connect your Heimdall account (from the popup) to use the Security Copilot. It answers using your real scan findings.</Empty>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ flex: 1, overflowY: 'auto' }} className="flex flex-col gap-2">
        {history.length === 0 ? (
          <div className="flex flex-col gap-2">
            <div className="text-muted" style={{ fontSize: 12, lineHeight: 1.5 }}>Ask Heimdall about your findings, agents, MCP servers, or how to fix something. Answers are grounded in your real scans.</div>
            {SUGGESTED.map((s) => (
              <button key={s} onClick={() => ask(s)} className="glass glass-hover" style={{ textAlign: 'left', padding: '9px 11px', fontSize: 12, color: '#cbd5e1', cursor: 'pointer' }}>{s}</button>
            ))}
          </div>
        ) : null}
        {history.map((m, i) => (
          <div key={i} style={{ alignSelf: m.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '92%' }}>
            <div style={{
              padding: '9px 11px', borderRadius: 12, fontSize: 12, lineHeight: 1.5, whiteSpace: 'pre-wrap',
              background: m.role === 'user' ? 'linear-gradient(135deg,#22d3ee,#0ea5e9)' : 'rgba(255,255,255,0.04)',
              color: m.role === 'user' ? '#04121f' : '#e8eef6',
              border: m.role === 'user' ? 'none' : '1px solid rgba(255,255,255,0.08)',
            }}>{m.content}</div>
          </div>
        ))}
        {busy ? <div className="flex items-center gap-2 text-muted" style={{ fontSize: 12 }}><Loader2 size={13} className="spin" /> Thinking…</div> : null}
        {err ? <div className="sev-critical" style={{ fontSize: 11, padding: 8, borderRadius: 8 }}>{err}</div> : null}
        <div ref={endRef} />
      </div>
      <div className="flex gap-2" style={{ marginTop: 10 }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') ask(input); }}
          placeholder="Ask the Security Copilot…"
          style={{ flex: 1, background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 11, padding: '9px 11px', color: '#e8eef6', fontSize: 12 }} />
        <button onClick={() => ask(input)} disabled={busy} className="btn-brand" style={{ padding: '0 12px', cursor: 'pointer' }}><Send size={14} /></button>
      </div>
    </div>
  );
}

function Notifications({ state, onChange }: { state: BackgroundState; onChange: () => void }) {
  const clear = async () => { await send({ type: 'CLEAR_NOTIFICATIONS' }); onChange(); };
  const markAll = async () => { await send({ type: 'MARK_READ' }); onChange(); };
  if (state.notifications.length === 0) return <Empty>No notifications yet. You’ll be alerted on secret leaks, prompt injections, MCP exposure, completed scans and trust changes.</Empty>;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex gap-2" style={{ marginBottom: 4 }}>
        <Btn onClick={markAll} className="flex items-center gap-1" style={{ flex: 1, justifyContent: 'center' }}>Mark all read</Btn>
        <Btn onClick={clear} className="flex items-center gap-1" style={{ flex: 1, justifyContent: 'center' }}><Trash2 size={12} /> Clear</Btn>
      </div>
      {state.notifications.map((n) => <NotifRow key={n.id} n={n} />)}
    </div>
  );
}

function NotifRow({ n }: { n: HeimdallNotification }) {
  return (
    <Card style={{ opacity: n.read ? 0.6 : 1, borderLeft: `3px solid ${sevColor[n.severity]}` }}>
      <div className="flex items-center gap-2" style={{ marginBottom: 4 }}>
        <SevBadge sev={n.severity} />
        <span style={{ fontWeight: 700, fontSize: 12 }}>{n.title}</span>
        <span className="text-faint" style={{ fontSize: 10, marginLeft: 'auto' }}>{relTime(n.createdAt)}</span>
      </div>
      <p className="text-muted" style={{ fontSize: 11.5, lineHeight: 1.45, margin: 0 }}>{n.body}</p>
      {n.url ? <button onClick={() => send({ type: 'OPEN_DASHBOARD', path: '/dashboard' })} className="text-faint flex items-center gap-1" style={{ fontSize: 10, marginTop: 6, background: 'transparent', cursor: 'pointer' }}><ExternalLink size={10} /> Open</button> : null}
    </Card>
  );
}

function ActivityFeed({ state }: { state: BackgroundState }) {
  const items = [
    ...state.notifications.map((n) => ({ ts: n.createdAt, label: n.title, sub: n.body, sev: n.severity })),
    ...state.scans.map((s) => ({ ts: new Date(s.createdAt).getTime(), label: `Scanned ${s.repo}`, sub: `Trust ${s.trustScore} · ${s.findingsCount} findings`, sev: (s.trustScore >= 70 ? 'low' : s.trustScore >= 50 ? 'high' : 'critical') as HeimdallNotification['severity'] })),
  ].sort((a, b) => b.ts - a.ts).slice(0, 40);
  if (items.length === 0) return <Empty>No activity yet.</Empty>;
  return (
    <div className="flex flex-col" style={{ gap: 0 }}>
      {items.map((it, i) => (
        <div key={i} className="flex gap-3" style={{ paddingBottom: 14, position: 'relative' }}>
          <div style={{ position: 'relative', width: 10, flexShrink: 0 }}>
            <span style={{ position: 'absolute', top: 4, left: 1, width: 8, height: 8, borderRadius: 999, background: sevColor[it.sev] }} />
            {i < items.length - 1 ? <span style={{ position: 'absolute', top: 14, left: 4, bottom: -4, width: 1, background: 'rgba(255,255,255,0.08)' }} /> : null}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="flex items-center gap-2">
              <span style={{ fontSize: 12, fontWeight: 600 }}>{it.label}</span>
              <span className="text-faint" style={{ fontSize: 10, marginLeft: 'auto' }}>{relTime(it.ts)}</span>
            </div>
            <div className="text-faint" style={{ fontSize: 11, lineHeight: 1.4 }}>{it.sub}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function Scans({ state }: { state: BackgroundState }) {
  if (!state.signedIn) return <Empty>Connect your account to see synced scans.</Empty>;
  if (state.scans.length === 0) return <Empty>No scans yet. Run one from the GitHub overlay or the dashboard.</Empty>;
  return (
    <div className="flex flex-col gap-2">
      {state.scans.map((s) => (
        <Card key={s.id} className="flex items-center gap-3">
          <ScoreRing score={s.trustScore} size={52} />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12.5, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.repo}</div>
            <div className="text-faint" style={{ fontSize: 10.5, marginTop: 2 }}>Grade {s.grade ?? '—'} · {s.agentsCount} agents · {s.mcpCount} MCP · {s.findingsCount} findings</div>
            <div className="text-faint" style={{ fontSize: 10, marginTop: 2 }}>{relTime(s.createdAt)} · {s.source}</div>
          </div>
        </Card>
      ))}
    </div>
  );
}
