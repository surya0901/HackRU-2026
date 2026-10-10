// AI Agent Detector + MCP Discovery content script (FEATURE 5 + 6).
//
// Runs on supported dev/AI sites automatically, and can be injected on demand
// into the active tab from the popup ("Analyze Page"). It fingerprints AI agent
// frameworks/SDKs present in the page source and probes the current origin for
// MCP / tool-server endpoints, then reports the result to the background worker
// (which caches it per tab and surfaces high-risk exposure as a notification).
//
// All probing is same-origin only — no cross-site access, no extra permissions.

import { collectPageSource, detectAgents } from '../shared/detectors/agents';
import { discoverMcp } from '../shared/detectors/mcp';
import { scanWebsite } from '../shared/detectors/website';
import type { PageScan } from '../shared/messages';

const HISTORY_KEY = 'heimdall.websiteBaselines';

async function run(): Promise<void> {
  const agents = detectAgents(collectPageSource(document));
  let mcp: PageScan['mcp'] = [];
  const limitations = [
    'Passive scan only: no forms submitted, payloads sent, or authenticated areas tested.',
    'Browser-visible DOM only; server code, database controls, and business logic are not tested.',
    'Security response headers are not readable from the DOM and are not verified by this scan.',
  ];
  try {
    mcp = await discoverMcp(location.origin);
  } catch {
    mcp = [];
  }
  if (mcp.length === 0) limitations.push('No MCP endpoint was confirmed; CORS, redirects, authentication, or extension host permissions can prevent endpoint verification.');
  const findings = scanWebsite(document, location);
  const stored = await chrome.storage.local.get(HISTORY_KEY);
  const baselines = (stored[HISTORY_KEY] ?? {}) as Record<string, { ts: number; evidence: Record<string, string> }>;
  const previous = baselines[location.origin];
  const ids = findings.map((item) => item.id).sort();
  const evidence = Object.fromEntries(findings.map((item) => [item.id, item.evidence]));
  const before = new Set(Object.keys(previous?.evidence ?? {}));
  const now = new Set(ids);
  const verification = {
    baselineTs: previous?.ts ?? null,
    added: ids.filter((id) => !before.has(id)),
    fixed: [...before].filter((id) => !now.has(id)),
    changed: ids.filter((id) => before.has(id) && previous?.evidence[id] !== evidence[id]),
    unchanged: ids.filter((id) => before.has(id) && previous?.evidence[id] === evidence[id]),
  };
  const ts = Date.now();
  baselines[location.origin] = { ts, evidence };
  await chrome.storage.local.set({ [HISTORY_KEY]: baselines });
  const scan: PageScan = { origin: location.origin, agents, mcp, findings, limitations, verification, ts };
  chrome.runtime.sendMessage({ type: 'PAGE_SCAN_RESULT', scan }).catch(() => undefined);
}

void run();
