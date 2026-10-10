// AI Agent Detector (FEATURE 5).
//
// Scans a page's visible source — inline scripts, imported module URLs, and text
// — for fingerprints of AI agent frameworks and SDKs. Detection is signature
// based (real string/regex fingerprints), and capabilities are inferred from the
// framework's typical tool surface, matching the dashboard's agent-scan model
// (lib/agent-scan.ts capabilities: shell/filesystem/network/database/secrets/...).

import type { DetectedPageAgent } from '../types';

interface AgentSignature {
  framework: string;
  patterns: RegExp[];
  capabilities: string[];
  baseRisk: number;
}

const SIGNATURES: AgentSignature[] = [
  { framework: 'OpenAI SDK', patterns: [/\bopenai\b/i, /api\.openai\.com/i, /chat\.completions/i, /from ['"]openai['"]/i], capabilities: ['network', 'model-invocation'], baseRisk: 35 },
  { framework: 'Anthropic SDK', patterns: [/@anthropic-ai\/sdk/i, /api\.anthropic\.com/i, /\bclaude-(?:opus|sonnet|haiku)\b/i], capabilities: ['network', 'model-invocation'], baseRisk: 35 },
  { framework: 'LangChain', patterns: [/\blangchain\b/i, /from ['"]langchain/i, /AgentExecutor/i, /create_react_agent/i], capabilities: ['network', 'tools', 'filesystem'], baseRisk: 60 },
  { framework: 'CrewAI', patterns: [/\bcrewai\b/i, /from ['"]crewai['"]/i, /\bCrew\(/], capabilities: ['network', 'tools', 'shell'], baseRisk: 65 },
  { framework: 'AutoGen', patterns: [/\bautogen\b/i, /pyautogen/i, /AssistantAgent/i, /UserProxyAgent/i], capabilities: ['network', 'tools', 'shell'], baseRisk: 70 },
  { framework: 'OpenRouter', patterns: [/openrouter\.ai/i, /OPENROUTER_API_KEY/i], capabilities: ['network', 'model-invocation'], baseRisk: 35 },
  { framework: 'LlamaIndex', patterns: [/\bllama[_-]?index\b/i, /from ['"]llama_index/i], capabilities: ['network', 'tools', 'database'], baseRisk: 55 },
  { framework: 'Vercel AI SDK', patterns: [/\bai\/react\b/i, /from ['"]ai['"]/i, /useChat\(/, /streamText\(/], capabilities: ['network', 'model-invocation'], baseRisk: 30 },
  { framework: 'MCP', patterns: [/modelcontextprotocol/i, /@modelcontextprotocol\/sdk/i, /\bMCP server\b/i, /\bmcp\.json\b/i], capabilities: ['tools', 'network'], baseRisk: 60 },
];

/** Collect the page's inspectable source text (scripts + module URLs). */
export function collectPageSource(doc: Document): string {
  const parts: string[] = [];
  doc.querySelectorAll('script').forEach((s) => {
    if (s.textContent) parts.push(s.textContent.slice(0, 20000));
    const src = s.getAttribute('src');
    if (src) parts.push(src);
  });
  doc.querySelectorAll('link[rel="modulepreload"], link[rel="preload"]').forEach((l) => {
    const href = l.getAttribute('href');
    if (href) parts.push(href);
  });
  // A bounded slice of body text catches docs/READMEs that name the framework.
  parts.push((doc.body?.innerText ?? '').slice(0, 40000));
  return parts.join('\n');
}

export function detectAgents(source: string): DetectedPageAgent[] {
  const out: DetectedPageAgent[] = [];
  for (const sig of SIGNATURES) {
    const hit = sig.patterns.find((p) => {
      p.lastIndex = 0;
      return p.test(source);
    });
    if (!hit) continue;
    // More capabilities → larger blast radius → higher risk (matches the
    // dashboard's blast-radius intuition).
    const risk = Math.min(100, sig.baseRisk + (sig.capabilities.length - 2) * 8);
    out.push({
      framework: sig.framework,
      evidence: hit.source,
      capabilities: sig.capabilities,
      riskScore: Math.max(0, risk),
    });
  }
  return out;
}
