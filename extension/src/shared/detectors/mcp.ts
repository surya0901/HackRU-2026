// MCP Discovery (FEATURE 6).
//
// Probes the current origin for the well-known endpoints that expose Model
// Context Protocol servers, tool manifests, and OpenAPI/Swagger surfaces. These
// are real same-origin HTTP probes (no cross-origin access, no host permission
// beyond the page itself). For each hit we estimate tool count + auth status +
// a risk score the same way the dashboard's MCP analysis does (an exposed,
// unauthenticated tool server is high risk).

import type { DetectedMcp } from '../types';

interface Probe {
  path: string;
  kind: DetectedMcp['kind'];
}

const PROBES: Probe[] = [
  { path: '/mcp', kind: 'mcp' },
  { path: '/.well-known/mcp.json', kind: 'well-known' },
  { path: '/.well-known/ai-plugin.json', kind: 'well-known' },
  { path: '/openapi.json', kind: 'openapi' },
  { path: '/openapi.yaml', kind: 'openapi' },
  { path: '/swagger.json', kind: 'swagger' },
  { path: '/swagger/v1/swagger.json', kind: 'swagger' },
  { path: '/tools', kind: 'tools' },
  { path: '/agent', kind: 'agent' },
];

async function probeOne(origin: string, probe: Probe): Promise<DetectedMcp | null> {
  const url = origin + probe.path;
  try {
    const res = await fetch(url, { method: 'GET', credentials: 'omit', redirect: 'manual' });
    // 401/403 strongly indicate the endpoint exists but is protected.
    const authenticated = res.status === 401 || res.status === 403;
    if (!res.ok && !authenticated) return null;

    let toolCount: number | null = null;
    if (res.ok) {
      const ct = res.headers.get('content-type') ?? '';
      if (ct.includes('json')) {
        const data: unknown = await res.json().catch(() => null);
        toolCount = countTools(data);
      } else {
        const text = await res.text().catch(() => '');
        // Heuristic for YAML/text manifests.
        if (/tools?:|operationId:|paths:/i.test(text)) toolCount = (text.match(/operationId:|- name:/gi) ?? []).length || null;
        else if (!/mcp|openapi|swagger|tool|agent/i.test(text)) return null;
      }
    }

    // Risk: a reachable, unauthenticated tool/MCP surface is the dangerous case.
    let risk = authenticated ? 25 : 55;
    if (!authenticated && (toolCount ?? 0) > 0) risk += Math.min(30, (toolCount ?? 0) * 3);
    if (probe.kind === 'mcp' || probe.kind === 'tools') risk += 10;

    return {
      url,
      kind: probe.kind,
      toolCount,
      authenticated: authenticated ? true : res.ok ? false : null,
      riskScore: Math.min(100, risk),
    };
  } catch {
    return null; // network/CORS error — treat as not present
  }
}

function countTools(data: unknown): number | null {
  if (!data || typeof data !== 'object') return null;
  const obj = data as Record<string, unknown>;
  if (Array.isArray(obj.tools)) return obj.tools.length;
  if (obj.paths && typeof obj.paths === 'object') return Object.keys(obj.paths as object).length;
  if (Array.isArray(obj.functions)) return obj.functions.length;
  return null;
}

/** Probe the given origin for MCP / tool-server indicators. */
export async function discoverMcp(origin: string): Promise<DetectedMcp[]> {
  const results = await Promise.all(PROBES.map((p) => probeOne(origin, p)));
  return results.filter((r): r is DetectedMcp => r !== null);
}
