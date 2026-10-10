// Typed runtime-message protocol between content scripts / popup / side panel
// (senders) and the background service worker (the only context that holds the
// connection token and talks to the dashboard). Centralizing it keeps every
// surface in sync and the messaging "secure by construction": untrusted page
// scripts can't reach the token, only message the worker.

import type {
  Account,
  SyncedScan,
  AgentScanResponse,
  Settings,
  HeimdallNotification,
  NotificationType,
  Severity,
  DetectedPageAgent,
  DetectedMcp,
  WebsiteFinding,
  WebsiteVerification,
} from './types';

/** Live agent/MCP detection result for a single page (FEATURE 5 + 6). */
export interface PageScan {
  origin: string;
  agents: DetectedPageAgent[];
  mcp: DetectedMcp[];
  findings: WebsiteFinding[];
  limitations: string[];
  verification: WebsiteVerification;
  ts: number;
}

export type AnalyzeMode = 'analyze' | 'explain' | 'fix' | 'finding';

export interface AnalyzeResult {
  summary: string;
  severity: Severity;
  findings: { title: string; severity: Severity; detail: string }[];
  fix: string | null;
  poweredByAnthropic: boolean;
}

export interface CopilotTurn {
  role: 'user' | 'assistant';
  content: string;
}

export interface CopilotResult {
  reply: string;
  poweredByAnthropic: boolean;
}

export type NotifyInput = Pick<HeimdallNotification, 'type' | 'severity' | 'title' | 'body'> & {
  url?: string;
};

export interface BackgroundState {
  account: Account | null;
  signedIn: boolean;
  settings: Settings;
  scans: SyncedScan[];
  notifications: HeimdallNotification[];
  unread: number;
}

export type Msg =
  | { type: 'GET_STATE' }
  | { type: 'API_ME' }
  | { type: 'API_SCANS' }
  | { type: 'API_AGENT_SCAN'; repoUrl: string }
  | { type: 'API_ANALYZE'; content: string; language?: string; mode: AnalyzeMode }
  | { type: 'API_COPILOT'; history: CopilotTurn[] }
  | { type: 'SIGN_IN' }
  | { type: 'SIGN_IN_CODE'; token: string }
  | { type: 'SIGN_OUT' }
  | { type: 'GET_SETTINGS' }
  | { type: 'SET_SETTINGS'; settings: Partial<Settings> }
  | { type: 'NOTIFY'; notification: NotifyInput }
  | { type: 'GET_NOTIFICATIONS' }
  | { type: 'MARK_READ'; id?: string }
  | { type: 'CLEAR_NOTIFICATIONS' }
  | { type: 'OPEN_DASHBOARD'; path?: string }
  | { type: 'OPEN_SIDE_PANEL' }
  | { type: 'ANALYZE_ACTIVE_PAGE' }
  | { type: 'GET_PAGE_SCAN' }
  | { type: 'PAGE_SCAN_RESULT'; scan: PageScan };

// Discriminated result map so send<T>() infers the right response per message.
export interface ResultMap {
  GET_STATE: BackgroundState;
  API_ME: Account | null;
  API_SCANS: SyncedScan[];
  API_AGENT_SCAN: AgentScanResponse;
  API_ANALYZE: AnalyzeResult;
  API_COPILOT: CopilotResult;
  SIGN_IN: { account: Account | null };
  SIGN_IN_CODE: { account: Account | null };
  SIGN_OUT: { ok: true };
  GET_SETTINGS: Settings;
  SET_SETTINGS: Settings;
  NOTIFY: { id: string };
  GET_NOTIFICATIONS: HeimdallNotification[];
  MARK_READ: { ok: true };
  CLEAR_NOTIFICATIONS: { ok: true };
  OPEN_DASHBOARD: { ok: true };
  OPEN_SIDE_PANEL: { ok: true };
  ANALYZE_ACTIVE_PAGE: PageScan;
  GET_PAGE_SCAN: PageScan | null;
  PAGE_SCAN_RESULT: { ok: true };
}

export type Envelope<T> = { ok: true; data: T } | { ok: false; error: string };

/** Send a typed message to the background worker and unwrap the response. */
export async function send<K extends Msg['type']>(
  msg: Extract<Msg, { type: K }>,
): Promise<ResultMap[K]> {
  const res = (await chrome.runtime.sendMessage(msg)) as Envelope<ResultMap[K]> | undefined;
  if (!res) throw new Error('No response from Heimdall background worker');
  if (!res.ok) throw new Error(res.error);
  return res.data;
}

export const NOTIFICATION_LABELS: Record<NotificationType, string> = {
  'critical-finding': 'Critical Finding',
  'secret-leak': 'Secret Leak Detected',
  'prompt-injection': 'Prompt Injection Detected',
  'agent-risk': 'Agent Risk Increased',
  'mcp-exposure': 'MCP Exposure Found',
  'scan-complete': 'Scan Completed',
  'autofix-pr': 'Auto Fix Opened PR',
  'trust-change': 'Trust Score Changed',
};
