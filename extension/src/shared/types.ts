// Shared strict types for the Heimdall Chrome extension. These mirror the
// dashboard API shapes (lib/db/schema.ts, app/api/extension/*, app/api/agent-scan)
// so the extension and the backend speak exactly the same language.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ThreatKind =
  | 'prompt-injection'
  | 'jailbreak'
  | 'system-prompt-extraction'
  | 'agent-manipulation'
  | 'tool-abuse'
  | 'secret-exfiltration'
  | 'secret-leak';

/** A single detection produced by a local detector (Prompt Shield / secrets). */
export interface Detection {
  kind: ThreatKind;
  severity: Severity;
  title: string;
  explanation: string;
  impact: string;
  recommendation: string;
  // For secret leaks: the matched (redacted) value and char range in the input.
  match?: string;
  redacted?: string;
  start?: number;
  end?: number;
  ruleId?: string;
}

/** Identity returned by GET /api/extension/me. */
export interface Account {
  userId: string;
  email: string | null;
  name: string | null;
}

/** A synced scan row from GET /api/extension/scans. */
export interface SyncedScan {
  id: string;
  repo: string;
  commitSha: string | null;
  trustScore: number;
  riskScore: number;
  grade: string | null;
  findingsCount: number;
  agentsCount: number;
  mcpCount: number;
  source: string;
  createdAt: string;
}

/** Compact agent-scan result the extension renders (subset of AgentScanResult). */
export interface ScanAgent {
  id: string;
  name: string;
  framework: string;
  model: string | null;
  file: string;
  line: number;
  hasTools: boolean;
  capabilities: string[];
}
export interface ScanMcp {
  id: string;
  name: string;
  file: string;
  transport: 'stdio' | 'http' | 'unknown';
  toolCount: number;
}
export interface ScanFinding {
  id: string;
  kind: string;
  severity: Severity;
  title: string;
  description: string;
  plainEnglish: string;
  recommendation: string;
  file: string;
  line: number;
}
export interface AgentScanResult {
  agents: ScanAgent[];
  mcpServers: ScanMcp[];
  findings: ScanFinding[];
  riskScore: number;
  grade: string;
  filesAnalyzed: number;
  diagnostics: { frameworks: string[] };
}
export interface AgentScanResponse {
  result: AgentScanResult;
  repo: { owner: string; repo: string; commitSha: string; branch: string };
  cached: boolean;
}

/** An AI agent / SDK detected live on a web page (FEATURE 5). */
export interface DetectedPageAgent {
  framework: string;
  evidence: string;
  capabilities: string[];
  riskScore: number;
}

/** An MCP indicator discovered by probing the current origin (FEATURE 6). */
export interface DetectedMcp {
  url: string;
  kind: 'mcp' | 'openapi' | 'swagger' | 'tools' | 'agent' | 'well-known';
  toolCount: number | null;
  authenticated: boolean | null;
  riskScore: number;
}

/** Evidence collected without submitting forms, executing attacks, or changing the page. */
export interface WebsiteFinding {
  id: string;
  severity: Severity;
  title: string;
  evidence: string;
  recommendation: string;
}

export interface WebsiteVerification {
  baselineTs: number | null;
  added: string[];
  fixed: string[];
  changed: string[];
  unchanged: string[];
}

export type NotificationType =
  | 'critical-finding'
  | 'secret-leak'
  | 'prompt-injection'
  | 'agent-risk'
  | 'mcp-exposure'
  | 'scan-complete'
  | 'autofix-pr'
  | 'trust-change';

export interface HeimdallNotification {
  id: string;
  type: NotificationType;
  severity: Severity;
  title: string;
  body: string;
  url?: string;
  read: boolean;
  createdAt: number;
}

/** Persisted extension settings (chrome.storage.sync). */
export interface Settings {
  dashboardUrl: string;
  promptShield: boolean;
  secretGuard: boolean;
  githubOverlay: boolean;
  notifications: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  dashboardUrl: 'https://sentinel-security-console.sg1670.chatgpt.site',
  promptShield: true,
  secretGuard: true,
  githubOverlay: true,
  notifications: true,
};
