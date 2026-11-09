import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Activity, AlertTriangle, Layers, Crosshair, Play, Pause,
  SkipForward, RefreshCw, ArrowUpRight, CheckCircle2, ShieldAlert,
  Brain, HelpCircle, Terminal, Cpu
} from 'lucide-react';
import { api } from '../services/api';
import KPICards from '../components/kpi/KPICards';
import HealthGauge from '../components/kpi/HealthGauge';
import TopologyGraph from '../components/topology/TopologyGraph';
import DeviceDrawer from '../components/device/DeviceDrawer';

// Severity badge
function SevBadge({ s }) {
  const sev = (s || 'LOW').toUpperCase();
  const cls = sev === 'CRITICAL' ? 'badge-critical' : sev === 'HIGH' ? 'badge-high' : sev === 'MEDIUM' ? 'badge-medium' : 'badge-low';
  return <span className={`badge ${cls}`}>{sev}</span>;
}

export default function DashboardPage({ onNavigate, onOpenDemo }) {
  const [dash, setDash] = useState(null);
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [msg, setMsg] = useState('');
  const [simulating, setSimulating] = useState(false);
  const [trafficControl, setTrafficControl] = useState({ is_paused: false, status: 'RUNNING' });
  const [controllingTraffic, setControllingTraffic] = useState(false);

  // Reliable Polling with Backoff and Tab Visibility Pause (Task 2)
  const pollIntervalRef = useRef(5000);
  const pollTimerRef = useRef(null);
  const isTabVisibleRef = useRef(!document.hidden);

  const loadData = useCallback(async (isInitial = false) => {
    if (isInitial) setLoading(true);
    try {
      const [d, t] = await Promise.all([
        api.getDashboardSummary(),
        api.getDigitalTwinTopology()
      ]);
      setDash(d);
      setTopology(t);
      if (d.traffic_control) {
        setTrafficControl(d.traffic_control);
      }
      setError(null);
      // Reset backoff on success
      pollIntervalRef.current = 5000;
    } catch (e) {
      console.warn("Dashboard polling warning:", e);
      if (!dash) {
        setError("Unable to load dashboard data. Please verify the backend is running.");
      }
      // Exponential backoff up to 30s
      pollIntervalRef.current = Math.min(30000, pollIntervalRef.current * 1.5);
    } finally {
      setLoading(false);
    }
  }, [dash]);

  // Schedule next poll
  const scheduleNextPoll = useCallback(() => {
    if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
    if (!isTabVisibleRef.current) return; // Paused while tab hidden

    pollTimerRef.current = setTimeout(async () => {
      await loadData(false);
      scheduleNextPoll();
    }, pollIntervalRef.current);
  }, [loadData]);

  useEffect(() => {
    loadData(true);
    scheduleNextPoll();

    const handleVisibility = () => {
      const isVisible = !document.hidden;
      isTabVisibleRef.current = isVisible;
      if (isVisible) {
        // Resume immediately and reset interval
        pollIntervalRef.current = 5000;
        loadData(false);
        scheduleNextPoll();
      } else {
        // Pause timer
        if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      }
    };

    const handleManualRefresh = () => {
      loadData(false);
    };

    document.addEventListener('visibilitychange', handleVisibility);
    window.addEventListener('netguardian_refresh', handleManualRefresh);

    return () => {
      if (pollTimerRef.current) clearTimeout(pollTimerRef.current);
      document.removeEventListener('visibilitychange', handleVisibility);
      window.removeEventListener('netguardian_refresh', handleManualRefresh);
    };
  }, [loadData, scheduleNextPoll]);

  // Simulation Event Ingestion
  const simulate = async (type) => {
    setSimulating(true);
    setMsg(`Simulating ${type.replace(/_/g, ' ')}…`);
    try {
      const src = type === 'PORT_SCAN' ? '192.168.1.199' : '192.168.1.10';
      await api.triggerSecurityEvent(type, src, '192.168.1.20');
      await loadData(false);
      setMsg(`✅ ${type.replace(/_/g, ' ')} event triggered.`);
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setSimulating(false);
      setTimeout(() => setMsg(''), 5000);
    }
  };

  // Traffic Controls (Task 3)
  const handlePauseTraffic = async () => {
    setControllingTraffic(true);
    try {
      const res = await api.pauseTraffic();
      setTrafficControl(res);
      setMsg('⏸️ Simulation traffic paused.');
      await loadData(false);
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setControllingTraffic(false);
      setTimeout(() => setMsg(''), 4000);
    }
  };

  const handleResumeTraffic = async () => {
    setControllingTraffic(true);
    try {
      const res = await api.resumeTraffic();
      setTrafficControl(res);
      setMsg('▶️ Simulation traffic resumed.');
      await loadData(false);
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setControllingTraffic(false);
      setTimeout(() => setMsg(''), 4000);
    }
  };

  const handleStepTraffic = async () => {
    setControllingTraffic(true);
    setMsg('Advancing 1 simulation step…');
    try {
      await api.stepTraffic(6);
      setMsg('⏭️ Single simulation tick executed.');
      await loadData(false);
    } catch (e) {
      setMsg(`Error: ${e.message}`);
    } finally {
      setControllingTraffic(false);
      setTimeout(() => setMsg(''), 4000);
    }
  };

  const threatCount = dash?.kpis?.threats_detected ?? 0;
  const guidance = dash?.guidance;
  const aiResults = dash?.latest_ai_results;
  const needsAttention = dash?.needs_attention || [];

  // Friendly Offline State (Task 6 & Acceptance Check 5)
  if (error && !dash) {
    return (
      <div style={{ padding: '60px 0', maxWidth: 640, margin: '0 auto', textAlign: 'center' }}>
        <div className="ng-card" style={{ padding: '40px 30px' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>⚠️</div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#0f172a', marginBottom: 8 }}>
            Unable to Load Dashboard
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: 20 }}>
            Unable to load dashboard data. Please verify the backend is running.
          </p>
          <button
            onClick={() => loadData(true)}
            className="btn btn-primary"
            style={{ margin: '0 auto' }}
          >
            <RefreshCw size={14} /> Retry Connection
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: '24px 0', display: 'flex', flexDirection: 'column', gap: 24, maxWidth: 1240, margin: '0 auto' }}>

      {/* PAGE HEADER */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: 10 }}>
            Security Dashboard
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: trafficControl.is_paused ? '#f59e0b' : '#059669', display: 'inline-block' }} />
          </h1>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 3 }}>
            Real-time cybersecurity telemetry, AI anomaly detection and Digital Twin status
            · <span className="tag-simulated">SIMULATION MODE</span>
          </p>
        </div>

        {/* Traffic Controls (Task 3) */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {msg && (
            <span style={{ fontSize: '0.75rem', color: '#2563eb', background: '#dbeafe', border: '1px solid #bfdbfe', padding: '5px 10px', borderRadius: 8, fontWeight: 600 }}>
              {msg}
            </span>
          )}

          {/* Simulation Traffic State Pill */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: trafficControl.is_paused ? '#fef3c7' : '#ecfdf5',
            border: `1px solid ${trafficControl.is_paused ? '#fde68a' : '#a7f3d0'}`,
            padding: '4px 10px', borderRadius: 8, fontSize: '0.75rem', fontWeight: 700,
            color: trafficControl.is_paused ? '#b45309' : '#047857'
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: trafficControl.is_paused ? '#d97706' : '#059669' }} />
            SIMULATION: {trafficControl.is_paused ? 'PAUSED' : 'RUNNING'}
          </div>

          {trafficControl.is_paused ? (
            <button
              onClick={handleResumeTraffic}
              disabled={controllingTraffic}
              className="btn btn-secondary btn-sm"
              style={{ fontWeight: 700, color: '#047857' }}
              title="Resume background simulated traffic generation"
            >
              <Play size={13} fill="#047857" /> Resume
            </button>
          ) : (
            <button
              onClick={handlePauseTraffic}
              disabled={controllingTraffic}
              className="btn btn-secondary btn-sm"
              style={{ fontWeight: 700, color: '#b45309' }}
              title="Pause simulated traffic generation"
            >
              <Pause size={13} /> Pause
            </button>
          )}

          <button
            onClick={handleStepTraffic}
            disabled={controllingTraffic}
            className="btn btn-secondary btn-sm"
            style={{ fontWeight: 700 }}
            title="Step simulation forward by exactly 1 tick"
          >
            <SkipForward size={13} /> Step
          </button>

          <button onClick={onOpenDemo} className="btn btn-warning" style={{ fontWeight: 700 }}>
            <Play size={14} fill="#d97706" /> Start Guided Demo
          </button>
        </div>
      </div>

      {/* "What should I do next?" Comprehensive Card (Task 1) */}
      <div style={{
        background: threatCount > 0 ? '#fff7ed' : '#f0fdf4',
        border: `1px solid ${threatCount > 0 ? '#fed7aa' : '#bbf7d0'}`,
        borderRadius: 12,
        padding: '16px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: 10
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {threatCount > 0 ? (
              <AlertTriangle size={20} color="#d97706" style={{ flexShrink: 0 }} />
            ) : (
              <CheckCircle2 size={20} color="#059669" style={{ flexShrink: 0 }} />
            )}
            <span style={{ fontWeight: 800, color: threatCount > 0 ? '#92400e' : '#065f46', fontSize: '0.9375rem' }}>
              What should I do next?
            </span>
          </div>
          <span style={{
            fontSize: '0.725rem',
            fontWeight: 700,
            color: threatCount > 0 ? '#b45309' : '#047857',
            background: threatCount > 0 ? '#fef3c7' : '#dcfce7',
            padding: '2px 8px',
            borderRadius: 6
          }}>
            Status: {guidance?.network_state || 'HEALTHY'} ({guidance?.health_score ?? 100}/100)
          </span>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 12,
          fontSize: '0.8125rem',
          color: threatCount > 0 ? '#78350f' : '#14532d',
          lineHeight: 1.5
        }}>
          <div>
            <strong>1. Network State:</strong> {guidance?.threats_text}
          </div>
          <div>
            <strong>2. Suspicious Device:</strong> {guidance?.suspicious_device_text}
          </div>
          <div>
            <strong>3. Potential Impact:</strong> {guidance?.possible_impact}
          </div>
          <div>
            <strong>4. Recommended Action:</strong> {guidance?.what_to_investigate}
          </div>
        </div>

        <div style={{
          borderTop: `1px dashed ${threatCount > 0 ? '#fed7aa' : '#bbf7d0'}`,
          paddingTop: 8,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 8,
          fontSize: '0.75rem',
          color: threatCount > 0 ? '#9a3412' : '#166534'
        }}>
          <span>
            🛡️ <strong>Safe Simulation:</strong> {guidance?.safe_simulation}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            {threatCount > 0 && (
              <button
                onClick={() => onNavigate('threats')}
                className="btn btn-sm"
                style={{ background: '#d97706', color: 'white', fontWeight: 700, border: 'none' }}
              >
                Review Threats →
              </button>
            )}
            <button
              onClick={() => onNavigate('what-if')}
              className="btn btn-secondary btn-sm"
              style={{ fontWeight: 700 }}
            >
              Run What-If Simulation →
            </button>
          </div>
        </div>
      </div>

      {/* KPI CARDS (Task 1) */}
      {loading && !dash ? (
        <div style={{ color: '#94a3b8', fontSize: '0.8125rem', padding: '32px 0', textAlign: 'center' }}>Loading dashboard telemetry…</div>
      ) : (
        <KPICards kpis={dash?.kpis} />
      )}

      {/* MAIN CONTENT GRID */}
      <div className="dashboard-grid">

        {/* LEFT COLUMN */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Health Gauge with Label & Breakdown */}
          <HealthGauge healthData={dash?.network_health} />

          {/* Latest AI Results Card (Task 1) */}
          <div className="ng-card">
            <div className="ng-card-title" style={{ marginBottom: 12 }}>
              <Brain size={14} color="#7c3aed" />
              Latest AI Anomaly Detection
              <span style={{
                marginLeft: 'auto',
                fontSize: '0.7rem',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 12,
                background: aiResults?.status === 'ANOMALOUS' ? '#fee2e2' : '#dcfce7',
                color: aiResults?.status === 'ANOMALOUS' ? '#dc2626' : '#15803d',
                border: `1px solid ${aiResults?.status === 'ANOMALOUS' ? '#fca5a5' : '#86efac'}`
              }}>
                {aiResults?.status || 'NORMAL'} · Score: {aiResults?.anomaly_score ?? 0.14}
              </span>
            </div>

            <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: 10 }}>
              Evaluated Host: <code style={{ color: '#0f172a', fontWeight: 600 }}>{aiResults?.evaluated_ip || '192.168.1.10'}</code> · Confidence: <strong style={{ color: '#2563eb' }}>{aiResults?.confidence || 'HIGH'}</strong> ({aiResults?.training_samples || 2250} baseline samples)
            </div>

            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 12px' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase', marginBottom: 6 }}>
                Why was this flagged / Model explanation:
              </div>
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: '0.75rem', color: '#334155', lineHeight: 1.6 }}>
                {(aiResults?.reasons || [
                  'Observed traffic matches normal baseline clusters',
                  'Feature vector within expected bounds'
                ]).map((reason, idx) => (
                  <li key={idx}>{reason}</li>
                ))}
              </ul>
            </div>
            <div style={{ fontSize: '0.675rem', color: '#94a3b8', marginTop: 8, fontStyle: 'italic' }}>
              Anomalies indicate statistical deviations from baseline, not confirmed malicious activity.
            </div>
          </div>

          {/* "Needs Attention" List of Open Threats with Investigate Buttons (Task 1) */}
          <div className="ng-card">
            <div className="ng-card-title" style={{ marginBottom: 14 }}>
              <ShieldAlert size={14} color="#dc2626" />
              Needs Attention: Open Threats
              <button onClick={() => onNavigate('threats')} className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto', color: '#2563eb', fontSize: '0.75rem' }}>
                All Threats <ArrowUpRight size={12} />
              </button>
            </div>

            {needsAttention.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {needsAttention.slice(0, 5).map((a) => (
                  <div
                    key={a.id}
                    style={{
                      border: '1px solid #e2e8f0',
                      borderRadius: 8,
                      padding: '10px 14px',
                      background: '#ffffff',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 12
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                        <span style={{ fontWeight: 700, fontSize: '0.8125rem', color: '#0f172a' }}>{a.title}</span>
                        <SevBadge s={a.severity} />
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                        Source: <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{a.source_ip}</span> · Status: <strong>{a.status}</strong>
                      </div>
                    </div>
                    <button
                      onClick={() => onNavigate('threats')}
                      className="btn btn-secondary btn-sm"
                      style={{ fontWeight: 700, color: '#dc2626', borderColor: '#fca5a5' }}
                    >
                      Investigate
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state" style={{ padding: '24px 0' }}>
                <div className="empty-state-icon">✅</div>
                <div className="empty-state-title">No Open Threats</div>
                <div className="empty-state-sub">Network health is pristine. Simulate a scenario below to test detection.</div>
              </div>
            )}
          </div>

          {/* Simulate Security Event */}
          <div className="ng-card">
            <div className="ng-card-title" style={{ marginBottom: 14 }}>
              <Crosshair size={14} color="#7c3aed" />
              Simulate Security Event
              <span className="tag-simulated" style={{ marginLeft: 'auto' }}>SAFE — SYNTHETIC ONLY</span>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: 12, lineHeight: 1.6 }}>
              Inject synthetic security events to test detection and see how the system responds. No real traffic is generated.
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {[
                { type: 'UNKNOWN_DEVICE', label: '🔍 Unknown Device', desc: 'Joins network' },
                { type: 'PORT_SCAN', label: '🔁 Port Scan', desc: 'Multi-port probe' },
                { type: 'TRAFFIC_ANOMALY', label: '📈 Traffic Spike', desc: 'Above baseline' },
                { type: 'FAILED_AUTH', label: '🔒 Failed Auth', desc: '12 failed logins' },
                { type: 'SUSPICIOUS_OUTBOUND', label: '📡 Suspicious Out', desc: 'Unusual port' },
                { type: 'COMPROMISED_HOST', label: '💀 Compromised', desc: 'Lateral reach' },
              ].map(ev => (
                <button
                  key={ev.type}
                  onClick={() => simulate(ev.type)}
                  disabled={simulating}
                  style={{
                    background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8,
                    padding: '10px 12px', cursor: 'pointer', textAlign: 'left', transition: 'all 0.12s'
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = '#2563eb'; e.currentTarget.style.background = '#eff6ff'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = '#e2e8f0'; e.currentTarget.style.background = '#f8fafc'; }}
                >
                  <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#334155' }}>{ev.label}</div>
                  <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: 2 }}>{ev.desc}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* RIGHT COLUMN — Mini Topology Map (Task 1) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <h2 style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#0f172a', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Layers size={16} color="#2563eb" />
                Mini Topology Map (Digital Twin)
              </h2>
              <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>
                Live synchronized topology. Click any device to inspect details or run What-If.
              </p>
            </div>
            <button onClick={() => onNavigate('digital-twin')} className="btn btn-ghost btn-sm" style={{ color: '#2563eb' }}>
              Full Topology View <ArrowUpRight size={12} />
            </button>
          </div>

          <TopologyGraph
            nodes={topology.nodes || []}
            edges={topology.edges || []}
            selectedNode={selectedDevice}
            onSelectNode={setSelectedDevice}
            height={560}
          />
        </div>
      </div>

      {/* Device Drawer */}
      {selectedDevice && (
        <DeviceDrawer
          device={selectedDevice}
          onClose={() => setSelectedDevice(null)}
          onRunWhatIf={dev => { setSelectedDevice(null); onNavigate('what-if', dev); }}
          onDeviceUpdated={() => loadData(false)}
        />
      )}
    </div>
  );
}
