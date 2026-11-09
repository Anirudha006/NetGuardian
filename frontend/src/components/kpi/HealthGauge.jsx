import React from 'react';
import { CheckCircle, AlertTriangle, XCircle, AlertCircle } from 'lucide-react';

function getHealthStyle(score) {
  if (score >= 80) return { label: 'HEALTHY', color: '#059669', bg: '#d1fae5', barColor: '#059669', Icon: CheckCircle };
  if (score >= 60) return { label: 'NEEDS ATTENTION', color: '#d97706', bg: '#fef3c7', barColor: '#d97706', Icon: AlertTriangle };
  if (score >= 40) return { label: 'AT RISK', color: '#f97316', bg: '#fff7ed', barColor: '#f97316', Icon: AlertCircle };
  return { label: 'CRITICAL', color: '#dc2626', bg: '#fee2e2', barColor: '#dc2626', Icon: XCircle };
}

export default function HealthGauge({ healthData }) {
  const score = healthData?.score ?? 0;
  const { label, color, bg, barColor, Icon } = getHealthStyle(score);
  const factors = healthData?.factors || [];

  return (
    <div className="ng-card" style={{ padding: 20 }}>
      <div className="ng-card-title" style={{ marginBottom: 16 }}>
        <Icon size={15} color={color} />
        Network Health Score
        <span style={{ marginLeft: 'auto', fontSize: '0.7rem', fontWeight: 600, background: bg, color: color, padding: '2px 8px', borderRadius: 20, border: `1px solid ${barColor}40` }}>
          {label}
        </span>
      </div>

      {/* Score number */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 10 }}>
        <span style={{ fontSize: '3rem', fontWeight: 900, color: color, lineHeight: 1, letterSpacing: '-0.05em' }}>{score}</span>
        <span style={{ fontSize: '1.125rem', fontWeight: 600, color: '#94a3b8' }}>/100</span>
      </div>

      {/* Bar */}
      <div className="health-bar-track" style={{ marginBottom: 14 }}>
        <div className="health-bar-fill" style={{ width: `${score}%`, background: barColor }} />
      </div>

      {/* Formula note */}
      <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginBottom: factors.length ? 12 : 0, fontStyle: 'italic' }}>
        Score = 100 minus penalties for active threats, suspicious devices, and traffic anomalies.
        <span style={{ marginLeft: 4, fontStyle: 'normal', fontWeight: 600, color: '#64748b' }}>(NetGuardian proprietary, not an industry standard)</span>
      </div>

      {/* Penalty factors */}
      {factors.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>Penalty Factors</div>
          {factors.map((f, i) => (
            <div key={i} className="risk-factor-row">
              <span style={{ flex: 2, fontSize: '0.75rem', color: '#334155' }}>{f.label}</span>
              <div className="risk-factor-bar">
                <div className="risk-factor-fill" style={{ width: `${Math.min(100, Math.abs(f.value) * 3)}%`, background: f.value < 0 ? '#dc2626' : '#059669' }} />
              </div>
              <span style={{ minWidth: 36, textAlign: 'right', fontSize: '0.75rem', fontWeight: 700, color: f.value < 0 ? '#dc2626' : '#059669' }}>
                {f.value > 0 ? '+' : ''}{f.value}
              </span>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 10, fontSize: '0.7rem', color: '#94a3b8' }}>
        <span className="tag-simulated">SIMULATED</span> data · Updated every 4 seconds
      </div>
    </div>
  );
}
