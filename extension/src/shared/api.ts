// Authenticated client for the Sentinel dashboard API. Mirrors the VS Code
// extension's CloudClient: every call carries the `sk_sentinel_…` connection
// token as a Bearer header, hitting the same dual-auth routes the web app uses
// (lib/auth.ts → resolveAuth). Lives only in the background service worker.

import { getToken } from './storage';
import { dashboardUrl } from './auth';
import type { Account, SyncedScan, AgentScanResponse } from './types';
import type { AnalyzeMode, AnalyzeResult, CopilotTurn, CopilotResult } from './messages';

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const token = await getToken();
  if (!token) throw new Error('Not signed in. Open the Sentinel popup and connect your account.');
  const base = await dashboardUrl();
  const res = await fetch(`${base}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...(init?.headers ?? {}),
    },
  });
  const text = await res.text();
  let data: unknown = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    const msg = (data as { error?: string })?.error || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data as T;
}

export async function getAccount(): Promise<Account> {
  return req<Account>('/api/extension/me');
}

export async function listScans(): Promise<SyncedScan[]> {
  const { scans } = await req<{ scans: SyncedScan[] }>('/api/extension/scans');
  return scans;
}

export async function agentScan(repoUrl: string): Promise<AgentScanResponse> {
  return req<AgentScanResponse>('/api/agent-scan', {
    method: 'POST',
    body: JSON.stringify({ repoUrl }),
  });
}

export async function analyze(content: string, mode: AnalyzeMode, language?: string): Promise<AnalyzeResult> {
  return req<AnalyzeResult>('/api/extension/analyze', {
    method: 'POST',
    body: JSON.stringify({ content, mode, language }),
  });
}

export async function copilot(history: CopilotTurn[]): Promise<CopilotResult> {
  return req<CopilotResult>('/api/extension/copilot', {
    method: 'POST',
    body: JSON.stringify({ history }),
  });
}
