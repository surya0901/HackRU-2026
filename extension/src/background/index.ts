// Heimdall background service worker — the extension's privileged core.
//
// Responsibilities:
//   • The ONLY context that holds the connection token and calls the dashboard
//     API (content scripts and pages can never reach the token).
//   • Typed message router for every surface (popup, side panel, content).
//   • Context menus for right-click security analysis (FEATURE 4).
//   • Browser notifications with action buttons (FEATURE 8).
//   • Side Panel wiring (FEATURE 7 + 10).
//   • Caches live page agent/MCP scans per tab (FEATURE 5 + 6).

import * as api from '../shared/api';
import { signInInteractive, signInWithCode, signOut, dashboardUrl } from '../shared/auth';
import {
  getSettings,
  saveSettings,
  getNotifications,
  saveNotifications,
  getToken,
  getCachedEmail,
  setCachedEmail,
} from '../shared/storage';
import type {
  Account,
  HeimdallNotification,
  Severity,
} from '../shared/types';
import type {
  Msg,
  ResultMap,
  Envelope,
  BackgroundState,
  NotifyInput,
  PageScan,
} from '../shared/messages';

const LAST_ANALYSIS_KEY = 'heimdall.lastAnalysis';

// In-memory caches (reset when the worker is recycled — fine, they re-populate).
const pageScans = new Map<number, PageScan>();
const pageScanWaiters = new Map<number, ((scan: PageScan) => void)[]>();

// ---------------------------------------------------------------------------
// Notifications (FEATURE 8)
// ---------------------------------------------------------------------------
const SEV_ICON_TINT: Record<Severity, string> = {
  critical: '🛑',
  high: '🟠',
  medium: '🟡',
  low: '🟢',
  info: '🔵',
};

async function recordNotification(input: NotifyInput): Promise<string> {
  const settings = await getSettings();
  const id = crypto.randomUUID();
  const notif: HeimdallNotification = {
    id,
    type: input.type,
    severity: input.severity,
    title: input.title,
    body: input.body,
    url: input.url,
    read: false,
    createdAt: Date.now(),
  };
  const list = [notif, ...(await getNotifications())];
  await saveNotifications(list);
  await refreshBadge();

  if (settings.notifications) {
    chrome.notifications.create(`heimdall:${id}`, {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
      title: `${SEV_ICON_TINT[input.severity]} ${input.title}`,
      message: input.body,
      priority: input.severity === 'critical' || input.severity === 'high' ? 2 : 1,
      buttons: [{ title: 'Open Dashboard' }, { title: 'Dismiss' }],
    });
  }
  return id;
}

async function refreshBadge(): Promise<void> {
  const unread = (await getNotifications()).filter((n) => !n.read).length;
  await chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
  await chrome.action.setBadgeText({ text: unread > 0 ? String(Math.min(unread, 99)) : '' });
}

chrome.notifications.onButtonClicked.addListener(async (notifId, btnIdx) => {
  if (!notifId.startsWith('heimdall:')) return;
  const id = notifId.slice('heimdall:'.length);
  if (btnIdx === 0) {
    const list = await getNotifications();
    const n = list.find((x) => x.id === id);
    await openDashboard(n?.url ? new URL(n.url).pathname : '/dashboard');
  }
  chrome.notifications.clear(notifId);
});

chrome.notifications.onClicked.addListener(async (notifId) => {
  if (!notifId.startsWith('heimdall:')) return;
  await chrome.action.openPopup().catch(() => openDashboard('/dashboard'));
  chrome.notifications.clear(notifId);
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
async function openDashboard(path = '/dashboard'): Promise<void> {
  const base = await dashboardUrl();
  await chrome.tabs.create({ url: `${base}${path.startsWith('/') ? path : `/${path}`}` });
}

async function resolveAccount(): Promise<Account | null> {
  if (!(await getToken())) return null;
  try {
    const acc = await api.getAccount();
    await setCachedEmail(acc.email);
    return acc;
  } catch {
    // Offline / transient — fall back to cached identity so UI still shows it.
    const email = await getCachedEmail();
    return email ? { userId: 'cached', email, name: null } : null;
  }
}

async function buildState(): Promise<BackgroundState> {
  const [settings, notifications, signedIn] = await Promise.all([
    getSettings(),
    getNotifications(),
    getToken().then((t) => t !== null),
  ]);
  const account = signedIn ? await resolveAccount() : null;
  let scans: BackgroundState['scans'] = [];
  if (signedIn) {
    try {
      scans = await api.listScans();
    } catch {
      scans = [];
    }
  }
  return {
    account,
    signedIn,
    settings,
    scans,
    notifications,
    unread: notifications.filter((n) => !n.read).length,
  };
}

async function activeTab(): Promise<chrome.tabs.Tab | undefined> {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab;
}

/** Ensure the page-scan content script has run on a tab, then return its result. */
async function analyzeActivePage(): Promise<PageScan> {
  const tab = await activeTab();
  if (!tab?.id || !tab.url || !/^https?:/.test(tab.url)) {
    return { origin: tab?.url ?? '', agents: [], mcp: [], findings: [], limitations: ['This browser page cannot be scanned.'], verification: { baselineTs: null, added: [], fixed: [], changed: [], unchanged: [] }, ts: Date.now() };
  }
  const tabId = tab.id;
  const cached = pageScans.get(tabId);
  if (cached && Date.now() - cached.ts < 15_000) return cached;

  const waiter = new Promise<PageScan>((resolve) => {
    const arr = pageScanWaiters.get(tabId) ?? [];
    arr.push(resolve);
    pageScanWaiters.set(tabId, arr);
  });
  try {
    await chrome.scripting.executeScript({ target: { tabId }, files: ['content-pagescan.js'] });
  } catch {
    // No host permission yet / restricted page — return whatever we have.
    return cached ?? { origin: new URL(tab.url).origin, agents: [], mcp: [], findings: [], limitations: ['The extension could not access this page. Grant site access and retry.'], verification: { baselineTs: null, added: [], fixed: [], changed: [], unchanged: [] }, ts: Date.now() };
  }
  const timeout = new Promise<PageScan>((resolve) =>
    setTimeout(() => resolve(cached ?? { origin: new URL(tab.url!).origin, agents: [], mcp: [], findings: [], limitations: ['The passive page scan timed out before evidence was returned.'], verification: { baselineTs: null, added: [], fixed: [], changed: [], unchanged: [] }, ts: Date.now() }), 9000),
  );
  return Promise.race([waiter, timeout]);
}

// ---------------------------------------------------------------------------
// Context menus (FEATURE 4)
// ---------------------------------------------------------------------------
const MENU = {
  analyze: 'heimdall-analyze',
  explain: 'heimdall-explain',
  fix: 'heimdall-fix',
  save: 'heimdall-save',
  dashboard: 'heimdall-dashboard',
} as const;

function installContextMenus(): void {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: MENU.analyze, title: 'Analyze with Heimdall', contexts: ['selection'] });
    chrome.contextMenus.create({ id: MENU.explain, title: 'Explain vulnerability', contexts: ['selection'] });
    chrome.contextMenus.create({ id: MENU.fix, title: 'Generate secure fix', contexts: ['selection'] });
    chrome.contextMenus.create({ id: MENU.save, title: 'Save as finding', contexts: ['selection'] });
    chrome.contextMenus.create({ id: 'sep', type: 'separator', contexts: ['selection'] });
    chrome.contextMenus.create({ id: MENU.dashboard, title: 'Open Heimdall dashboard', contexts: ['selection', 'page', 'action'] });
  });
}

chrome.runtime.onInstalled.addListener(() => {
  installContextMenus();
  refreshBadge();
});
chrome.runtime.onStartup.addListener(() => {
  installContextMenus();
  refreshBadge();
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const selection = (info.selectionText ?? '').trim();
  if (info.menuItemId === MENU.dashboard) {
    await openDashboard('/dashboard');
    return;
  }
  if (!selection) return;

  if (info.menuItemId === MENU.save) {
    await recordNotification({
      type: 'critical-finding',
      severity: 'info',
      title: 'Finding saved',
      body: selection.slice(0, 160),
      url: tab?.url,
    });
    return;
  }

  const mode = info.menuItemId === MENU.explain ? 'explain' : info.menuItemId === MENU.fix ? 'fix' : 'analyze';
  if (!(await getToken())) {
    await recordNotification({
      type: 'critical-finding',
      severity: 'info',
      title: 'Connect Heimdall to analyze',
      body: 'Open the Heimdall popup and connect your account to run AI-powered analysis.',
    });
    return;
  }

  // Stash a "pending" marker, open the side panel, then fill in the result.
  await chrome.storage.local.set({ [LAST_ANALYSIS_KEY]: { mode, content: selection, result: null, ts: Date.now() } });
  if (tab?.id) await chrome.sidePanel.open({ tabId: tab.id }).catch(() => undefined);

  try {
    const result = await api.analyze(selection, mode);
    await chrome.storage.local.set({ [LAST_ANALYSIS_KEY]: { mode, content: selection, result, ts: Date.now() } });
    if (result.severity === 'critical' || result.severity === 'high') {
      await recordNotification({
        type: 'critical-finding',
        severity: result.severity,
        title: `Heimdall: ${result.severity} issue in selection`,
        body: result.summary.slice(0, 160),
      });
    }
  } catch (e) {
    await chrome.storage.local.set({
      [LAST_ANALYSIS_KEY]: { mode, content: selection, result: null, error: String(e instanceof Error ? e.message : e), ts: Date.now() },
    });
  }
});

// ---------------------------------------------------------------------------
// Side panel: open on toolbar action is handled by the popup; allow programmatic
// open from menus. Also let the panel open per-tab.
// ---------------------------------------------------------------------------
chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => undefined);

chrome.tabs.onRemoved.addListener((tabId) => {
  pageScans.delete(tabId);
  pageScanWaiters.delete(tabId);
});

// ---------------------------------------------------------------------------
// Message router
// ---------------------------------------------------------------------------
async function handle(msg: Msg, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (msg.type) {
    case 'GET_STATE':
      return buildState();
    case 'API_ME':
      return resolveAccount();
    case 'API_SCANS':
      return api.listScans();
    case 'API_AGENT_SCAN': {
      const res = await api.agentScan(msg.repoUrl);
      await recordNotification({
        type: 'scan-complete',
        severity: res.result.riskScore >= 50 ? 'high' : 'info',
        title: `Scan complete: ${res.repo.owner}/${res.repo.repo}`,
        body: `Trust ${Math.max(0, 100 - res.result.riskScore)} · ${res.result.findings.length} findings · ${res.result.agents.length} agents · ${res.result.mcpServers.length} MCP`,
      });
      return res;
    }
    case 'API_ANALYZE':
      return api.analyze(msg.content, msg.mode, msg.language);
    case 'API_COPILOT':
      return api.copilot(msg.history);
    case 'SIGN_IN': {
      await signInInteractive();
      return { account: await resolveAccount() };
    }
    case 'SIGN_IN_CODE': {
      await signInWithCode(msg.token);
      return { account: await resolveAccount() };
    }
    case 'SIGN_OUT':
      await signOut();
      await refreshBadge();
      return { ok: true };
    case 'GET_SETTINGS':
      return getSettings();
    case 'SET_SETTINGS':
      return saveSettings(msg.settings);
    case 'NOTIFY':
      return { id: await recordNotification(msg.notification) };
    case 'GET_NOTIFICATIONS':
      return getNotifications();
    case 'MARK_READ': {
      const list = await getNotifications();
      for (const n of list) if (!msg.id || n.id === msg.id) n.read = true;
      await saveNotifications(list);
      await refreshBadge();
      return { ok: true };
    }
    case 'CLEAR_NOTIFICATIONS':
      await saveNotifications([]);
      await refreshBadge();
      return { ok: true };
    case 'OPEN_DASHBOARD':
      await openDashboard(msg.path);
      return { ok: true };
    case 'OPEN_SIDE_PANEL': {
      const tab = await activeTab();
      if (tab?.id) await chrome.sidePanel.open({ tabId: tab.id });
      return { ok: true };
    }
    case 'ANALYZE_ACTIVE_PAGE':
      return analyzeActivePage();
    case 'GET_PAGE_SCAN': {
      const tab = await activeTab();
      return (tab?.id && pageScans.get(tab.id)) || null;
    }
    case 'PAGE_SCAN_RESULT': {
      const tabId = sender.tab?.id;
      if (typeof tabId === 'number') {
        pageScans.set(tabId, msg.scan);
        const waiters = pageScanWaiters.get(tabId) ?? [];
        waiters.forEach((w) => w(msg.scan));
        pageScanWaiters.delete(tabId);
        // Proactively surface a high MCP/agent risk as a notification.
        const worstMcp = Math.max(0, ...msg.scan.mcp.map((m) => m.riskScore));
        if (worstMcp >= 60) {
          await recordNotification({
            type: 'mcp-exposure',
            severity: worstMcp >= 75 ? 'high' : 'medium',
            title: 'Exposed MCP / tool surface detected',
            body: `${new URL(msg.scan.origin).host} exposes ${msg.scan.mcp.length} tool endpoint(s).`,
            url: msg.scan.origin,
          });
        }
      }
      return { ok: true };
    }
    default:
      return { ok: true };
  }
}

chrome.runtime.onMessage.addListener((msg: Msg, sender, sendResponse) => {
  handle(msg, sender)
    .then((data) => sendResponse({ ok: true, data } satisfies Envelope<unknown>))
    .catch((e) => sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) } satisfies Envelope<never>));
  return true; // async response
});

// Keep the badge current when notifications change from any context.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes['heimdall.notifications']) void refreshBadge();
});

export type { ResultMap };
