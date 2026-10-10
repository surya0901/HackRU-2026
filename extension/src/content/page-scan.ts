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
import type { PageScan } from '../shared/messages';

async function run(): Promise<void> {
  const agents = detectAgents(collectPageSource(document));
  let mcp: PageScan['mcp'] = [];
  try {
    mcp = await discoverMcp(location.origin);
  } catch {
    mcp = [];
  }
  const scan: PageScan = { origin: location.origin, agents, mcp, ts: Date.now() };
  chrome.runtime.sendMessage({ type: 'PAGE_SCAN_RESULT', scan }).catch(() => undefined);
}

void run();
