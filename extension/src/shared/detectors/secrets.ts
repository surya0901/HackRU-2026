// Real-time secret detector for AI chat inputs (FEATURE 2).
//
// The provider patterns and the entropy-gated generic pass are ported verbatim
// from the dashboard's deterministic scanner (lib/scanners/secrets.ts) so the
// extension flags exactly what a Heimdall repo scan would — no separate, weaker
// heuristic. Everything runs locally in the content script; the secret never
// leaves the page.

import type { Detection } from '../types';

interface Rule {
  id: string;
  title: string;
  severity: Detection['severity'];
  regex: RegExp;
}

const RULES: Rule[] = [
  { id: 'aws-access-key-id', title: 'AWS access key ID', severity: 'critical', regex: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b/g },
  { id: 'aws-secret-access-key', title: 'AWS secret access key', severity: 'critical', regex: /aws_?secret_?access_?key["'\s:=]+([A-Za-z0-9/+]{40})\b/gi },
  { id: 'github-pat', title: 'GitHub personal access token', severity: 'critical', regex: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g },
  { id: 'stripe-secret-key', title: 'Stripe secret key', severity: 'critical', regex: /\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,})\b/g },
  { id: 'anthropic-key', title: 'Anthropic API key', severity: 'critical', regex: /\b(sk-ant-[A-Za-z0-9_-]{20,})\b/g },
  { id: 'openai-key', title: 'OpenAI API key', severity: 'critical', regex: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b/g },
  { id: 'openai-key-legacy', title: 'OpenAI API key', severity: 'critical', regex: /\b(sk-[A-Za-z0-9]{32,})\b/g },
  { id: 'google-api-key', title: 'Google API key', severity: 'high', regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g },
  { id: 'azure-key', title: 'Azure / generic 32-hex secret', severity: 'high', regex: /\b([0-9a-f]{32})\b/g },
  { id: 'slack-token', title: 'Slack token', severity: 'high', regex: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  { id: 'private-key', title: 'Private key', severity: 'critical', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { id: 'jwt', title: 'JWT / bearer token', severity: 'medium', regex: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { id: 'bearer-token', title: 'Bearer token', severity: 'high', regex: /\bBearer\s+([A-Za-z0-9_\-.=]{20,})/g },
  { id: 'db-connection-string', title: 'Database URL with credentials', severity: 'high', regex: /\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s:@/]+@[^\s"'`]+)/gi },
  { id: 'dotenv-block', title: '.env file contents', severity: 'high', regex: /(?:^|\n)\s*[A-Z][A-Z0-9_]{2,}\s*=\s*['"]?[^\s'"#]{8,}/g },
];

const GENERIC_ASSIGN =
  /\b([A-Za-z_][A-Za-z0-9_]*(?:secret|token|api[_-]?key|apikey|passwd|password|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?token)[A-Za-z0-9_]*)\b\s*[:=]\s*["'`]([^"'`\n]{12,})["'`]/gi;

const PLACEHOLDER = /^(your_|xxx|example|changeme|placeholder|<.*>|\$\{|process\.env|null|undefined|true|false|test|dummy|sample)/i;

/** Shannon entropy in bits/char — high for random secrets, low for words. */
export function shannonEntropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  let h = 0;
  for (const ch in freq) {
    const p = freq[ch] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function redact(secret: string): string {
  if (secret.length <= 8) return '•'.repeat(secret.length);
  return `${secret.slice(0, 4)}${'•'.repeat(Math.min(secret.length - 8, 20))}${secret.slice(-4)}`;
}

/** Scan a chat input string for secrets. Returns detections with char ranges. */
export function detectSecrets(text: string): Detection[] {
  if (!text) return [];
  const out: Detection[] = [];
  const seen = new Set<string>();

  for (const rule of RULES) {
    rule.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.regex.exec(text)) !== null) {
      const secret = m[1] ?? m[0];
      // Avoid trivial / placeholder hits for the broad generic-ish rules.
      if (PLACEHOLDER.test(secret)) continue;
      const start = m.index + (m[1] ? m[0].indexOf(m[1]) : 0);
      const end = start + secret.length;
      const key = `${rule.id}:${start}:${secret}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        kind: 'secret-leak',
        severity: rule.severity,
        title: `Potential ${rule.title} detected`,
        explanation: `Your message contains what looks like a ${rule.title.toLowerCase()}. Sending it to an AI provider transmits the secret to a third party and may persist it in chat history or training data.`,
        impact: 'Anyone with access to this conversation, the provider logs, or a compromised account could use this credential to access your systems.',
        recommendation: 'Redact the secret before sending. Reference it by name (e.g. "my OpenAI key") instead of pasting the real value, and rotate it if it was already shared.',
        match: secret,
        redacted: redact(secret),
        start,
        end,
        ruleId: rule.id,
      });
      if (rule.regex.lastIndex === m.index) rule.regex.lastIndex++;
    }
  }

  GENERIC_ASSIGN.lastIndex = 0;
  let g: RegExpExecArray | null;
  while ((g = GENERIC_ASSIGN.exec(text)) !== null) {
    const name = g[1];
    const value = g[2];
    if (PLACEHOLDER.test(value)) continue;
    if (shannonEntropy(value) < 3.2) continue;
    const start = g.index + g[0].indexOf(value);
    const end = start + value.length;
    const key = `generic:${start}:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      kind: 'secret-leak',
      severity: 'high',
      title: `Possible secret in \`${name}\``,
      explanation: `The value assigned to \`${name}\` looks like a real credential (high entropy). Sending it to an AI provider leaks it to a third party.`,
      impact: 'A leaked credential can be replayed against your infrastructure.',
      recommendation: 'Remove the value before sending and rotate the credential if it was exposed.',
      match: value,
      redacted: redact(value),
      start,
      end,
      ruleId: 'generic-assign',
    });
  }

  // Sort by position so redaction (applied right-to-left) is stable.
  return out.sort((a, b) => (a.start ?? 0) - (b.start ?? 0));
}

/** Redact every detected secret in a string (right-to-left to keep indices). */
export function redactAll(text: string, detections: Detection[]): string {
  const ranged = detections
    .filter((d): d is Detection & { start: number; end: number } => typeof d.start === 'number' && typeof d.end === 'number')
    .sort((a, b) => b.start - a.start);
  let out = text;
  for (const d of ranged) {
    out = out.slice(0, d.start) + '[REDACTED]' + out.slice(d.end);
  }
  return out;
}
