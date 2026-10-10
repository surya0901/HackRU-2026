// Minimal DOM helpers for content-script overlays. Content scripts inject UI
// into a closed-ish Shadow DOM so our styles never leak into — and are never
// clobbered by — the host page. The stylesheet is loaded as a web-accessible
// resource <link>, keeping us CSP-clean (no inline <style> blob, no remote CSS).

import type { Severity } from './types';

export interface OverlayHandle {
  host: HTMLElement;
  root: ShadowRoot;
  mount: HTMLElement;
  destroy: () => void;
}

/** Create a shadow-isolated overlay host appended to <body>. */
export function createOverlay(id: string): OverlayHandle {
  document.getElementById(id)?.remove();
  const host = document.createElement('div');
  host.id = id;
  host.className = 'sentinel-overlay-host';
  host.style.cssText = 'all: initial; position: fixed; z-index: 2147483647;';
  const root = host.attachShadow({ mode: 'open' });

  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = chrome.runtime.getURL('app.css');
  root.appendChild(link);

  const mount = document.createElement('div');
  root.appendChild(mount);
  document.documentElement.appendChild(host);

  return { host, root, mount, destroy: () => host.remove() };
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string,
  );
}

export function sevClass(sev: Severity): string {
  return `sev-${sev}`;
}

export function sevColor(sev: Severity): string {
  return {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#84cc16',
    info: '#22d3ee',
  }[sev];
}
