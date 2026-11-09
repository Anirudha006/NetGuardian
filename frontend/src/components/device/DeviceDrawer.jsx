import React, { useState, useEffect } from 'react';
import { X, AlertTriangle, CheckCircle, Crosshair, Shield, Info, Activity } from 'lucide-react';
import { api } from '../../services/api';

function RiskBar({ score }) {
  const color = score >= 75 ? '#dc2626' : score >= 40 ? '#d97706' : '#059669';
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: '0.75rem' }}>
        <span style={{ color: '#64748b', fontWeight: 600 }}>Risk Score</span>
        <span style={{ fontWeight: 800, color }}>{score}/100</span>
      </div>
      <div className="health-bar-track">
        <div className="health-bar-fill" style={{ width: `${score}%`, background: color }} />
      </div>
    </div>
  );
}

export default function DeviceDrawer({ device, onClose, onRunWhatIf, onDeviceUpdated }) {
  const [riskData, setRiskData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isolating, setIsolating] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    if (!device) return;
    setLoading(true);
    api.getDeviceRiskBreakdown(device.id || device.device_id)
      .then(d => { setRiskData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [device?.id || device?.device_id]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && onClose) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!device) return null;

  const ip = device.ip_address || device.ip;
  const name = device.device_name || device.name;
  const risk = device.risk_score ?? 0;
  const trust = device.trust_score ?? 0;
  const status = device.status || 'NORMAL';
  const isIsolated = device.status === 'ISOLATED';

  const statusColor = status === 'ISOLATED' ? '#dc2626' : status === 'SUSPICIOUS' ? '#d97706' : '#059669';

  const handleIsolate = async () => {
    if (!window.confirm(`SIMULATED ACTION: Isolate ${name} in the Digital Twin? No real network changes will be made.`)) return;
    setIsolating(true);
    try {
      await api.isolateDevice(device.id || device.device_id, 'Manual isolation from Device Inspector');
      setMsg('✅ Device isolated in Digital Twin. No real network changes were made.');
      onDeviceUpdated && onDeviceUpdated();
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setIsolating(false);
      setTimeout(() => setMsg(''), 6000);
    }
  };

  const handleRestore = async () => {
    setIsolating(true);
    try {
      await api.restoreDevice(device.id || device.device_id);
      setMsg('✅ Device restored in Digital Twin.');
      onDeviceUpdated && onDeviceUpdated();
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setIsolating(false);
      setTimeout(() => setMsg(''), 4000);
    }
  };

  return (
    <>
      {/* Overlay */}
      <div
        onClick={onClose}
        style={{ position: 'fixed', inset: 0, background: 'rgba(15,23,42,0.3)', zIndex: 100, backdropFilter: 'blur(2px)' }}
      />

      {/* Drawer */}
      <div data-testid="device-drawer" style={{
        position: 'fixed', right: 0, top: 0, bottom: 0, width: 380,
        background: 'white', boxShadow: '-8px 0 32px rgba(0,0,0,0.12)',
        zIndex: 101, display: 'flex', flexDirection: 'column', overflow: 'hidden'
      }}>

        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #e2e8f0', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', background: '#f8fafc' }}>
          <div>
            <div style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a' }}>{name}</div>
            <div style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 2, fontFamily: 'monospace' }}>{ip}</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '3px 8px', borderRadius: 20, background: statusColor + '1a', color: statusColor, border: `1px solid ${statusColor}40` }}>
              {status}
            </span>
            <button onClick={onClose} aria-label="Close device drawer" data-testid="close-drawer" className="btn btn-ghost btn-sm" style={{ padding: 4 }}>
              <X size={16} color="#64748b" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>

          {/* Tag */}
          <div style={{ marginBottom: 16 }}>
            <span className="tag-simulated">SIMULATED DATA</span>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8', marginLeft: 8 }}>Digital Twin representation</span>
          </div>

          {/* Risk Score */}
          <div className="ng-card-sm" style={{ marginBottom: 16 }}>
            <RiskBar score={risk} />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10, fontSize: '0.75rem', color: '#64748b' }}>
              <span>Trust Level: <strong style={{ color: (device.trust_level === 'HIGH' ? '#059669' : device.trust_level === 'MEDIUM' ? '#2563eb' : device.trust_level === 'LOW' ? '#d97706' : '#dc2626') }}>{device.trust_level || 'MEDIUM'} ({trust}/100)</strong></span>
              <span>Criticality: <strong>{device.criticality || 'Medium'}</strong></span>
            </div>
          </div>

          {/* Details grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 16 }}>
            {[
              ['Type', device.device_type || device.type || '—'],
              ['OS', device.os_type || device.os || '—'],
              ['MAC', device.mac_address || device.mac || '—'],
              ['Security Status', status],
              ['Trust Level', device.trust_level || 'MEDIUM'],
              ['Connections', device.connection_count ?? 'Active'],
              ['Traffic Volume', device.bytes_transferred ? `${Math.round(device.bytes_transferred / 1024)} KB` : 'Monitored'],
              ['First Seen', device.first_seen ? new Date(device.first_seen).toLocaleDateString() : 'Just now'],
              ['Last Seen', device.last_seen ? new Date(device.last_seen).toLocaleTimeString() : 'Active now'],
            ].map(([k, v]) => (
              <div key={k} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '8px 10px' }}>
                <div style={{ fontSize: '0.675rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 2 }}>{k}</div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#334155', fontFamily: k === 'MAC' ? 'monospace' : 'inherit' }}>{v}</div>
              </div>
            ))}
          </div>

          {/* Risk breakdown (Why This Risk?) */}
          {loading && <div style={{ color: '#94a3b8', fontSize: '0.8125rem', textAlign: 'center', padding: 12 }}>Loading risk analysis…</div>}

          {(riskData?.factors?.length > 0 || riskData?.breakdown?.length > 0) && (
            <div className="ng-card-sm" style={{ marginBottom: 16 }}>
              <div style={{ fontSize: '0.8125rem', fontWeight: 800, color: '#0f172a', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <AlertTriangle size={14} color="#d97706" />
                Why this risk? (Reasons List)
              </div>
              <p style={{ fontSize: '0.725rem', color: '#64748b', marginBottom: 10 }}>
                Transparent mathematical score breakdown based on asset criticality, behavior, and threat signals.
              </p>
              {(riskData.factors || riskData.breakdown).map((f, i) => {
                const impactVal = f.impact !== undefined ? f.impact : f.points;
                const nameLabel = f.name || f.label;
                const desc = f.description || '';
                return (
                  <div key={i} data-testid="risk-factor-row" style={{ borderBottom: '1px solid #f1f5f9', paddingBottom: 6, marginBottom: 6 }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                      <span style={{ color: '#1e293b', fontWeight: 600 }}>{nameLabel}</span>
                      <span style={{ fontWeight: 800, color: impactVal > 0 ? '#dc2626' : impactVal < 0 ? '#059669' : '#64748b', minWidth: 35, textAlign: 'right' }}>
                        {impactVal > 0 ? '+' : ''}{impactVal}
                      </span>
                    </div>
                    {desc && <div style={{ fontSize: '0.6875rem', color: '#64748b', marginTop: 1 }}>{desc}</div>}
                  </div>
                );
              })}
              <div style={{ borderTop: '1px solid #e2e8f0', marginTop: 8, paddingTop: 8, display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', fontWeight: 800 }}>
                <span>Total Calculated Risk</span>
                <span data-testid="drawer-total-risk" style={{ color: (riskData?.risk_score ?? risk) >= 75 ? '#dc2626' : (riskData?.risk_score ?? risk) >= 40 ? '#d97706' : '#059669' }}>
                  {riskData?.risk_score !== undefined ? riskData.risk_score : risk}/100
                </span>
              </div>
            </div>
          )}

          {/* Notification box */}
          {msg && (
            <div style={{ background: '#ecfdf5', border: '1px solid #6ee7b7', borderRadius: 8, padding: '10px 14px', marginBottom: 12, fontSize: '0.8125rem', color: '#065f46' }}>
              {msg}
            </div>
          )}
        </div>

        {/* Footer actions */}
        <div style={{ padding: '14px 20px', borderTop: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <button
            onClick={() => onRunWhatIf && onRunWhatIf(device)}
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center' }}
          >
            <Crosshair size={14} />
            Run What-If Simulation
          </button>

          {isIsolated ? (
            <button onClick={handleRestore} disabled={isolating} className="btn btn-success" style={{ width: '100%', justifyContent: 'center' }}>
              <CheckCircle size={14} />
              {isolating ? 'Restoring…' : 'Restore Device (Simulated)'}
            </button>
          ) : (
            <button onClick={handleIsolate} disabled={isolating} className="btn btn-danger" style={{ width: '100%', justifyContent: 'center' }}>
              <Shield size={14} />
              {isolating ? 'Isolating…' : 'Simulate Isolation'}
            </button>
          )}

          <div style={{ textAlign: 'center', fontSize: '0.675rem', color: '#94a3b8' }}>
            ⚠️ Isolation is a SIMULATED action only — no real changes are made
          </div>
        </div>
      </div>
    </>
  );
}
