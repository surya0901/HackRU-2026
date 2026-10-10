// Shared React building blocks for the popup and side panel. Styled with the
// Tailwind utilities + Heimdall design tokens defined in src/styles/app.css so
// both surfaces look like a slice of the dashboard.

import type { CSSProperties, ReactNode } from 'react';
import type { Severity } from '../shared/types';

export function Logo({ size = 22 }: { size?: number }) {
  return (
    <div
      className="flex items-center justify-center rounded-lg"
      style={{
        width: size,
        height: size,
        background: '#0071e3',
      }}
    >
      <svg width={size * 0.62} height={size * 0.62} viewBox="0 0 24 24" fill="none">
        <path d="M12 2l8 3v6c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V5l8-3z" fill="none" stroke="white" strokeWidth="1.5" strokeLinejoin="round" />
        <circle cx="12" cy="12" r="2.4" fill="white" />
      </svg>
    </div>
  );
}

export function SevBadge({ sev, children }: { sev: Severity; children?: ReactNode }) {
  return (
    <span className={`sev-${sev}`} style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 6, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
      {children ?? sev}
    </span>
  );
}

const sevColor: Record<Severity, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#84cc16', info: '#22d3ee',
};

export function trustSeverity(trust: number): Severity {
  if (trust >= 90) return 'low';
  if (trust >= 70) return 'medium';
  if (trust >= 50) return 'high';
  return 'critical';
}

export function ScoreRing({ score, label = 'TRUST', size = 84 }: { score: number; label?: string; size?: number }) {
  const sev = trustSeverity(score);
  const c = sevColor[sev];
  const inner = size - 14;
  return (
    <div
      className="relative flex items-center justify-center rounded-full"
      style={{ width: size, height: size, background: `conic-gradient(${c} ${score * 3.6}deg, #e5e5e7 0)` }}
    >
      <div className="flex flex-col items-center justify-center rounded-full" style={{ width: inner, height: inner, background: '#fff' }}>
        <span style={{ fontSize: size * 0.28, fontWeight: 800, color: c, lineHeight: 1 }}>{score}</span>
        <span style={{ fontSize: 9, fontWeight: 600, color: '#64748b', marginTop: 2 }}>{label}</span>
      </div>
    </div>
  );
}

export function Card({ children, className = '', style }: { children: ReactNode; className?: string; style?: CSSProperties }) {
  return <div className={`glass p-3 ${className}`} style={style}>{children}</div>;
}

export function Stat({ value, label, color = '#e8eef6' }: { value: ReactNode; label: string; color?: string }) {
  return (
    <div className="flex-1 text-center">
      <div style={{ fontSize: 18, fontWeight: 800, color }}>{value}</div>
      <div className="text-faint" style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{label}</div>
    </div>
  );
}

export function Skeleton({ h = 16, w = '100%' }: { h?: number; w?: number | string }) {
  return <div className="skeleton" style={{ height: h, width: w }} />;
}

export function Btn({
  children, onClick, variant = 'ghost', disabled, className = '', style,
}: {
  children: ReactNode; onClick?: () => void; variant?: 'brand' | 'ghost'; disabled?: boolean; className?: string; style?: CSSProperties;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`${variant === 'brand' ? 'btn-brand' : 'btn-ghost'} ${className}`}
      style={{ padding: '9px 12px', fontSize: 12.5, fontWeight: 600, cursor: disabled ? 'default' : 'pointer', opacity: disabled ? 0.5 : 1, ...style }}
    >
      {children}
    </button>
  );
}

export function relTime(ts: number | string): string {
  const t = typeof ts === 'string' ? new Date(ts).getTime() : ts;
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export { sevColor };
