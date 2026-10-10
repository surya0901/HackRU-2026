import type { Severity, WebsiteFinding } from '../types';

function finding(id: string, severity: Severity, title: string, evidence: string, recommendation: string): WebsiteFinding {
  return { id, severity, title, evidence, recommendation };
}

function sample(values: string[]): string {
  return values.slice(0, 3).join(', ');
}

/** Passive checks only: reads the current DOM and URL; never submits, mutates, or attacks. */
export function scanWebsite(doc: Document, location: Location): WebsiteFinding[] {
  const findings: WebsiteFinding[] = [];
  if (location.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(location.hostname)) {
    findings.push(finding('WEB-HTTPS', 'high', 'Page is not using HTTPS', location.href, 'Serve the site over HTTPS and redirect HTTP requests.'));
  }

  const insecure = Array.from(doc.querySelectorAll<HTMLElement>('[src],[href]'))
    .map((el) => el.getAttribute('src') || el.getAttribute('href') || '')
    .filter((url) => /^http:\/\//i.test(url));
  if (location.protocol === 'https:' && insecure.length) {
    findings.push(finding('WEB-MIXED-CONTENT', 'high', 'HTTP resources referenced from HTTPS', `${insecure.length} resource(s): ${sample(insecure)}`, 'Load every resource over HTTPS or remove it.'));
  }

  const unsafeTabs = Array.from(doc.querySelectorAll<HTMLAnchorElement>('a[target="_blank"]'))
    .filter((a) => !/\bnoopener\b/i.test(a.rel));
  if (unsafeTabs.length) {
    findings.push(finding('WEB-OPENER', 'low', 'New tabs retain opener access', `${unsafeTabs.length} link(s), e.g. ${sample(unsafeTabs.map((a) => a.href || '(no href)'))}`, 'Add rel="noopener noreferrer" to target="_blank" links.'));
  }

  const passwordForms = Array.from(doc.querySelectorAll<HTMLInputElement>('input[type="password"]'))
    .map((input) => input.form).filter((form): form is HTMLFormElement => Boolean(form));
  const insecureForms = [...new Set(passwordForms)].filter((form) => {
    try { return new URL(form.action || location.href, location.href).protocol !== 'https:'; } catch { return true; }
  });
  if (insecureForms.length) {
    findings.push(finding('WEB-PASSWORD-TRANSPORT', 'critical', 'Password form may submit without HTTPS', `${insecureForms.length} password form(s) with non-HTTPS action`, 'Submit credentials only to an HTTPS endpoint.'));
  }

  const inlineHandlers = doc.querySelectorAll('[onclick],[onerror],[onload],[onmouseover]').length;
  if (inlineHandlers) {
    findings.push(finding('WEB-INLINE-HANDLER', 'info', 'Inline event handlers increase XSS exposure', `${inlineHandlers} element(s) use inline event attributes`, 'Move handlers to bundled scripts and enforce a nonce- or hash-based Content Security Policy.'));
  }

  const thirdPartyScripts = Array.from(doc.scripts).map((s) => s.src).filter(Boolean).filter((src) => {
    try { return new URL(src).origin !== location.origin; } catch { return false; }
  });
  const withoutSri = Array.from(doc.scripts).filter((s) => s.src && thirdPartyScripts.includes(s.src) && !s.integrity);
  if (withoutSri.length) {
    findings.push(finding('WEB-THIRD-PARTY-SCRIPT', 'medium', 'Third-party scripts lack integrity metadata', `${withoutSri.length}/${thirdPartyScripts.length} cross-origin script(s), e.g. ${sample(withoutSri.map((s) => s.src))}`, 'Self-host trusted assets or pin them with Subresource Integrity and crossorigin metadata.'));
  }

  return findings;
}
