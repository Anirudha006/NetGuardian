import React, { useState, useEffect } from 'react';
import { RefreshCw, Layers, Link2, Shield, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';
import TopologyGraph from '../components/topology/TopologyGraph';
import DeviceDrawer from '../components/device/DeviceDrawer';

export default function DigitalTwinPage({ onNavigate }) {
  const [topology, setTopology] = useState({ nodes: [], edges: [], state: 'SYNCHRONIZED' });
  const [twinStatus, setTwinStatus] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [msg, setMsg] = useState('');

  const load = async () => {
    setLoading(true);
    try {
      const [t, s] = await Promise.all([api.getDigitalTwinTopology(), api.getSystemStatus().catch(() => null)]);
      setTopology(t);
      setTwinStatus(t.twin_status || s);
      // If a node was previously selected, refresh its object reference
      if (selected) {
        const updated = (t.nodes || []).find(n => (n.id === selected.id || n.name === selected.name));
        if (updated) setSelected(updated);
      }
    } catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); const iv = setInterval(load, 5000); return () => clearInterval(iv); }, []);

  const sync = async () => {
    setSyncing(true);
    try { 
      await api.syncDigitalTwin(); 
      await load(); 
      setMsg('✅ Digital Twin synchronized.'); 
    }
    catch (e) { setMsg(`Error: ${e.message}`); }
    finally { setSyncing(false); setTimeout(() => setMsg(''), 4000); }
  };

  const nodes = topology.nodes || [];
  const edges = topology.edges || [];
  const isOutOfSync = topology.state === 'OUT OF SYNC';

  const criticalNodes = nodes.filter(n => (n.criticality || '').toUpperCase() === 'CRITICAL');
  const suspiciousNodes = nodes.filter(n => (n.risk_score || 0) >= 40 || n.status === 'SUSPICIOUS' || n.status === 'COMPROMISED');
  const onlineCount = nodes.filter(n => n.status !== 'OFFLINE').length;

  const getRiskLevel = (score) => {
    const s = score || 0;
    if (s >= 75) return { label: 'CRITICAL', color: '#dc2626' };
    if (s >= 50) return { label: 'HIGH', color: '#ea580c' };
    if (s >= 25) return { label: 'MEDIUM', color: '#d97706' };
    return { label: 'LOW', color: '#059669' };
  };

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20, gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a' }}>Digital Twin</h1>
            <span style={{ fontSize: '0.6875rem', fontWeight: 800, padding: '3px 8px', borderRadius: 6, background: '#eff6ff', color: '#1d4ed8', border: '1px solid #bfdbfe' }}>
              MODE: SIMULATION
            </span>
            <span className="tag-simulated">SIMULATED</span>
          </div>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 2 }}>
            Living NetworkX graph synchronized with network database · <span className="tag-simulated">SIMULATED DATA</span>
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {msg && <span style={{ fontSize: '0.75rem', color: '#059669', background: '#f0fdf4', border: '1px solid #bbf7d0', padding: '5px 10px', borderRadius: 8, fontWeight: 600 }}>{msg}</span>}
          {isOutOfSync ? (
            <span data-testid="twin-sync-badge" style={{ fontSize: '0.75rem', fontWeight: 700, padding: '5px 10px', borderRadius: 8, background: '#fef2f2', color: '#dc2626', border: '1px solid #fecaca', display: 'flex', alignItems: 'center', gap: 5 }}>
              ⚠️ OUT OF SYNC
            </span>
          ) : (
            <span data-testid="twin-sync-badge" style={{ fontSize: '0.75rem', fontWeight: 700, padding: '5px 10px', borderRadius: 8, background: '#f0fdf4', color: '#059669', border: '1px solid #bbf7d0', display: 'flex', alignItems: 'center', gap: 5 }}>
              ● SYNCHRONIZED
            </span>
          )}
          <button onClick={sync} disabled={syncing} className="btn btn-secondary btn-sm" title="Re-synchronize Digital Twin graph">
            <RefreshCw size={13} style={{ animation: syncing ? 'spin 1s linear infinite' : 'none' }} />
            {syncing ? 'Syncing…' : 'Sync Twin'}
          </button>
        </div>
      </div>

      {/* Status cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 20 }}>
        {[
          { label: 'Devices', value: nodes.length, icon: '🖥️', color: '#2563eb' },
          { label: 'Connections', value: edges.length, icon: '🔗', color: '#7c3aed' },
          { label: 'Online', value: onlineCount, icon: '🟢', color: '#059669' },
          { label: 'Critical Assets', value: criticalNodes.length, icon: '🏛️', color: '#d97706' },
          { label: 'Suspicious Nodes', value: suspiciousNodes.length, icon: '⚠️', color: '#dc2626' },
        ].map(c => (
          <div key={c.label} className="kpi-card" style={{ borderTop: `3px solid ${c.color}` }}>
            <span className="kpi-label">{c.label}</span>
            <span className="kpi-value" style={{ color: c.color }}>{c.value}</span>
          </div>
        ))}
      </div>

      <div className="twin-grid">
        {/* LEFT: Full topology map */}
        <div className="ng-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid #e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, fontSize: '0.8125rem', color: '#0f172a', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Layers size={14} color="#2563eb" /> Network State ({topology.state || 'SYNCHRONIZED'})
            </span>
            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Click a node on map to inspect details & risk factors</span>
          </div>
          <TopologyGraph nodes={nodes} edges={edges} selectedNode={selected} onSelectNode={setSelected} height={560} />
        </div>

        {/* RIGHT: Selected node + critical assets */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Selected node panel */}
          {selected ? (
            <div className="ng-card" data-testid="selected-node-panel">
              <div className="ng-card-title" style={{ marginBottom: 14 }}>
                <Layers size={14} color="#2563eb" /> Selected Node
              </div>
              <div style={{ fontWeight: 800, fontSize: '1rem', color: '#0f172a', marginBottom: 2 }}>
                {selected.device_name || selected.name}
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: '0.8125rem', color: '#64748b', marginBottom: 12 }}>
                {selected.ip_address || selected.ip}
              </div>

              {(() => {
                const rLevel = getRiskLevel(selected.risk_score);
                return [
                  ['Risk Level', <span style={{ fontWeight: 800, color: rLevel.color }}>{rLevel.label}</span>],
                  ['Risk Score', `${selected.risk_score ?? 0}/100`],
                  ['Trust Score', `${selected.trust_score ?? 100}/100`],
                  ['Status', selected.status],
                  ['Criticality', selected.criticality || 'Medium'],
                  ['Trust Level', selected.trust_level || 'MEDIUM'],
                  ['Type', selected.device_type || selected.type || 'Workstation'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid #f1f5f9', fontSize: '0.8125rem' }}>
                    <span style={{ color: '#64748b' }}>{k}</span>
                    <span style={{ fontWeight: 700, color: '#0f172a' }}>{v}</span>
                  </div>
                ));
              })()}

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 14 }}>
                <button
                  onClick={() => onNavigate('what-if', selected)}
                  className="btn btn-primary"
                  style={{ width: '100%', justifyContent: 'center' }}
                  data-testid="run-what-if-btn"
                >
                  🎯 Run What-If Simulation
                </button>
                <button
                  onClick={() => setSelected(null)}
                  className="btn btn-ghost"
                  style={{ width: '100%', justifyContent: 'center', fontSize: '0.75rem' }}
                >
                  Clear Selection
                </button>
              </div>
            </div>
          ) : (
            <div className="ng-card">
              <div className="empty-state" style={{ padding: '24px 12px' }}>
                <div className="empty-state-icon"><Layers size={20} color="#94a3b8" /></div>
                <div className="empty-state-title">No node selected</div>
                <div className="empty-state-sub">Click a device on the map to inspect its Twin state and risk breakdown.</div>
              </div>
            </div>
          )}

          {/* Critical assets */}
          <div className="ng-card">
            <div className="ng-card-title" style={{ marginBottom: 12 }}>
              <Shield size={14} color="#d97706" /> Critical Assets ({criticalNodes.length})
            </div>
            {criticalNodes.length === 0 ? (
              <div style={{ fontSize: '0.8125rem', color: '#94a3b8', textAlign: 'center', padding: '16px 0' }}>No critical assets defined yet.</div>
            ) : criticalNodes.map(n => (
              <div key={n.id || n.name} onClick={() => setSelected(n)}
                style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #fed7aa', background: '#fff7ed', cursor: 'pointer', marginBottom: 6 }}
                onMouseEnter={e => e.currentTarget.style.background = '#fef3c7'}
                onMouseLeave={e => e.currentTarget.style.background = '#fff7ed'}
              >
                <div style={{ fontWeight: 700, fontSize: '0.8125rem', color: '#92400e' }}>{n.device_name || n.name}</div>
                <div style={{ fontSize: '0.75rem', color: '#b45309', fontFamily: 'monospace' }}>{n.ip_address || n.ip}</div>
              </div>
            ))}
          </div>

          {/* Suspicious nodes */}
          {suspiciousNodes.length > 0 && (
            <div className="ng-card">
              <div className="ng-card-title" style={{ marginBottom: 12, color: '#991b1b' }}>
                ⚠️ Suspicious Nodes ({suspiciousNodes.length})
              </div>
              {suspiciousNodes.map(n => (
                <div key={n.id || n.name} onClick={() => setSelected(n)}
                  style={{ padding: '8px 10px', borderRadius: 8, border: '1px solid #fca5a5', background: '#fff5f5', cursor: 'pointer', marginBottom: 6 }}
                  onMouseEnter={e => e.currentTarget.style.background = '#fee2e2'}
                  onMouseLeave={e => e.currentTarget.style.background = '#fff5f5'}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.8125rem', color: '#991b1b' }}>{n.device_name || n.name}</span>
                    <span style={{ fontSize: '0.7rem', fontWeight: 800, padding: '2px 6px', borderRadius: 4, background: '#fee2e2', color: '#dc2626' }}>
                      {n.status === 'COMPROMISED' ? 'COMPROMISED' : 'SUSPICIOUS'}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#dc2626', fontFamily: 'monospace', marginTop: 2 }}>
                    {n.ip_address || n.ip} · Risk: {n.risk_score}/100
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Device Drawer for detailed factor breakdown */}
      {selected && (
        <DeviceDrawer
          device={selected}
          onClose={() => setSelected(null)}
          onRunWhatIf={d => { setSelected(null); onNavigate('what-if', d); }}
          onDeviceUpdated={load}
        />
      )}
    </div>
  );
}
