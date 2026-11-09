import React from 'react';

const ICON_MAP = {
  normal:   '🟢',
  warning:  '🟡',
  critical: '🔴',
  offline:  '⚫',
  info:     '🔵',
};

export default function KPICards({ kpis }) {
  if (!kpis) {
    return (
      <div className="kpi-grid">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="kpi-card">
            <div style={{ width: 80, height: 12, background: '#e2e8f0', borderRadius: 4 }} />
            <div style={{ width: 50, height: 28, background: '#f1f5f9', borderRadius: 6, marginTop: 4 }} />
          </div>
        ))}
      </div>
    );
  }

  const cards = [
    {
      label: 'Devices Online',
      value: kpis.devices_online ?? 0,
      total: kpis.total_devices,
      icon: '🖥️',
      color: '#2563eb',
      bg: '#dbeafe',
      sub: kpis.total_devices ? `of ${kpis.total_devices} total` : 'online',
    },
    {
      label: 'Threats Detected',
      value: kpis.threats_detected ?? 0,
      icon: '🔴',
      color: '#dc2626',
      bg: '#fee2e2',
      sub: kpis.threats_detected > 0 ? 'Requires attention' : 'No active threats',
      urgent: kpis.threats_detected > 0,
    },
    {
      label: 'Suspicious Devices',
      value: kpis.suspicious_devices ?? 0,
      icon: '⚠️',
      color: '#d97706',
      bg: '#fef3c7',
      sub: kpis.suspicious_devices > 0 ? 'Review recommended' : 'All devices clean',
      urgent: kpis.suspicious_devices > 0,
    },
    {
      label: 'Packets Monitored',
      value: kpis.packets_monitored ? kpis.packets_monitored.toLocaleString() : '0',
      icon: '📊',
      color: '#059669',
      bg: '#d1fae5',
      sub: 'SIMULATED',
      tag: 'simulated',
    },
    {
      label: 'Active Connections',
      value: kpis.active_connections ?? 0,
      icon: '🔗',
      color: '#7c3aed',
      bg: '#ede9fe',
      sub: 'Current flows',
    },
    {
      label: 'High-Risk Devices',
      value: kpis.high_risk_devices ?? 0,
      icon: '🚨',
      color: '#be185d',
      bg: '#fce7f3',
      sub: kpis.high_risk_devices > 0 ? 'Investigate now' : 'Network healthy',
      urgent: kpis.high_risk_devices > 0,
    },
  ];

  return (
    <div className="kpi-grid">
      {cards.map(card => (
        <div
          key={card.label}
          className="kpi-card"
          style={{ borderTop: `3px solid ${card.color}` }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="kpi-label">{card.label}</span>
            <span style={{ width: 32, height: 32, borderRadius: 8, background: card.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '1rem', flexShrink: 0 }}>
              {card.icon}
            </span>
          </div>
          <div className="kpi-value" style={{ color: card.urgent ? card.color : '#0f172a' }}>
            {card.value}
          </div>
          <div className="kpi-sub">
            {card.tag === 'simulated'
              ? <span className="tag-simulated">{card.sub}</span>
              : card.sub
            }
          </div>
        </div>
      ))}
    </div>
  );
}
