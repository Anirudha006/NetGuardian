import React, { useState, useEffect } from 'react';
import { RefreshCw, Crosshair, Shield, CheckCircle, AlertTriangle, Info, Clock, ArrowRight } from 'lucide-react';
import { api } from '../services/api';
import TopologyGraph from '../components/topology/TopologyGraph';

function RiskLevelBadge({ score, level }) {
  const lvl = level || (score >= 80 ? 'CRITICAL' : score >= 55 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW');
  if (lvl === 'CRITICAL') return <span className="badge badge-critical">🔴 CRITICAL (≥80)</span>;
  if (lvl === 'HIGH') return <span className="badge badge-high">🟠 HIGH (55–79)</span>;
  if (lvl === 'MEDIUM') return <span className="badge badge-medium">🟡 MEDIUM (30–54)</span>;
  return <span className="badge badge-normal">🟢 LOW (&lt;30)</span>;
}

export default function WhatIfPage({ initialDevice }) {
  const [devices, setDevices] = useState([]);
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
  const [selectedDevice, setSelectedDevice] = useState(initialDevice || null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isolating, setIsolating] = useState(false);
  const [isolated, setIsolated] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const [isolationComparison, setIsolationComparison] = useState(null);
  const [historyRuns, setHistoryRuns] = useState([]);

  const loadData = () => {
    Promise.all([api.getDevices({ limit: 100 }), api.getDigitalTwinTopology(), api.getSimulationRuns()])
      .then(([d, t, runs]) => {
        const items = Array.isArray(d) ? d : (d.items || d.devices || []);
        // Allow all internal network devices in picker
        setDevices(items.filter(x => (x.device_type || '').toLowerCase() !== 'internet'));
        setTopology(t);
        if (Array.isArray(runs)) setHistoryRuns(runs);
      }).catch(console.error);
  };

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (initialDevice) {
      setSelectedDevice(initialDevice);
      setResult(null);
      setIsolated(initialDevice.is_isolated || initialDevice.status === 'ISOLATED');
    }
  }, [initialDevice]);

  const runSim = async () => {
    if (!selectedDevice) return;
    setLoading(true); setResult(null); setIsolationComparison(null);
    try {
      const r = await api.runWhatIfSimulation(selectedDevice.id || selectedDevice.device_id, 'COMPROMISED_HOST');
      setResult(r);
      setIsolated(selectedDevice.is_isolated || selectedDevice.status === 'ISOLATED');
      // Refresh history
      api.getSimulationRuns().then(runs => Array.isArray(runs) && setHistoryRuns(runs)).catch(() => {});
    } catch (e) {
      alert(e.message || 'Simulation execution failed');
    } finally {
      setLoading(false);
    }
  };

  const simulateIsolation = async () => {
    if (!selectedDevice) return;
    const name = selectedDevice.device_name || selectedDevice.name;
    const confirmed = window.confirm(
      `SIMULATED ACTION: Isolate ${name} in the Digital Twin?\n\nThis will interrupt the potential attack path in the simulation. NO real network changes will be performed.`
    );
    if (!confirmed) return;

    setIsolating(true);
    try {
      const isoRes = await api.isolateDevice(selectedDevice.id || selectedDevice.device_id, 'What-If simulation isolation');
      setIsolated(true);
      setIsolationComparison(isoRes.before_after_comparison || null);

      // Re-run simulation to confirm cleared reachability
      const postSim = await api.runWhatIfSimulation(selectedDevice.id || selectedDevice.device_id, 'COMPROMISED_HOST');
      setResult({ ...postSim, after_isolation: true, isolation_message: isoRes.message });

      // Refresh topology & devices list
      loadData();
    } catch (e) {
      alert(e.message || 'Simulated isolation failed');
    } finally {
      setIsolating(false);
    }
  };

  const restore = async () => {
    if (!selectedDevice) return;
    const name = selectedDevice.device_name || selectedDevice.name;
    const confirmed = window.confirm(
      `SIMULATED ACTION: Restore ${name} in the Digital Twin?\n\nThis will reconnect its structural links in the simulation.`
    );
    if (!confirmed) return;

    setRestoring(true);
    try {
      await api.restoreDevice(selectedDevice.id || selectedDevice.device_id);
      setIsolated(false);
      setIsolationComparison(null);
      loadData();
      await runSim();
    } catch (e) {
      alert(e.message || 'Restore failed');
    } finally {
      setRestoring(false);
    }
  };

  const pathScore = result?.path_risk_score ?? result?.max_path_risk ?? 0;
  const simLevel = result?.simulated_risk_level || (pathScore >= 80 ? 'CRITICAL' : pathScore >= 55 ? 'HIGH' : pathScore >= 30 ? 'MEDIUM' : 'LOW');
  const primaryPath = result?.potential_reach_path || result?.attack_paths?.[0]?.path || [];
  const primaryPathDisplay = result?.path_display || (primaryPath.length ? primaryPath.join(' → ') : 'No reachable systems');
  const attackSteps = result?.attack_path || [];

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>
      {/* Page Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
            What-If Attack Simulation Engine
          </h1>
          <span className="tag-hypothetical">HYPOTHETICAL</span>
          <span className="tag-simulated">SIMULATED DATA</span>
        </div>
        <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 4 }}>
          Safely explore hypothetical lateral movement and attack propagation using the living Digital Twin graph. No real network changes are ever performed.
        </p>
      </div>

      {/* Safety & Methodology Notice */}
      <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 10, padding: '12px 16px', marginBottom: 20, display: 'flex', gap: 12, alignItems: 'flex-start' }}>
        <Info size={16} color="#2563eb" style={{ flexShrink: 0, marginTop: 2 }} />
        <div style={{ fontSize: '0.8125rem', color: '#334155', lineHeight: 1.5 }}>
          <strong>NetGuardian Digital Twin Traversal:</strong> Traverses structural links only (excluding offline, isolated, and Internet nodes). Evaluates potential reachability, hop counts, and simulated path risk according to the formula:
          <span style={{ fontFamily: 'monospace', fontWeight: 600, background: '#e2e8f0', padding: '1px 6px', borderRadius: 4, marginLeft: 6 }}>
            0.30×Source Risk + 0.35×Target Criticality + 0.15×Hop Factor + 0.20×Avg Trust
          </span>.
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 20, alignItems: 'start' }}>
        {/* LEFT COLUMN: Controls & Device Picker */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Target Device Selector Card */}
          <div className="ng-card">
            <div className="ng-card-title" style={{ marginBottom: 12 }}>
              <Crosshair size={14} color="#7c3aed" /> Select Device
            </div>
            <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: 12 }}>
              Choose which device to hypothetically compromise:
            </p>
            <select
              className="ng-select"
              style={{ marginBottom: 12 }}
              value={selectedDevice?.id || selectedDevice?.device_id || ''}
              onChange={e => {
                const d = devices.find(x => String(x.id || x.device_id) === e.target.value);
                setSelectedDevice(d || null);
                setResult(null);
                setIsolated(d ? (d.is_isolated || d.status === 'ISOLATED') : false);
                setIsolationComparison(null);
              }}
            >
              <option value="">— Select a device —</option>
              {devices.map(d => (
                <option key={d.id} value={d.id}>
                  {d.device_name} ({d.ip_address}) — {d.criticality}
                </option>
              ))}
            </select>

            {selectedDevice && (
              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 12px', marginBottom: 14, fontSize: '0.8125rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontWeight: 800, color: '#0f172a' }}>{selectedDevice.device_name || selectedDevice.name}</span>
                  <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '2px 6px', borderRadius: 4, background: '#f1f5f9', color: '#475569' }}>
                    {selectedDevice.status || 'ONLINE'}
                  </span>
                </div>
                <div style={{ color: '#64748b', fontFamily: 'monospace', fontSize: '0.75rem', marginTop: 2 }}>{selectedDevice.ip_address || selectedDevice.ip}</div>
                <div style={{ color: '#64748b', fontSize: '0.75rem', marginTop: 4 }}>
                  Criticality: <strong>{selectedDevice.criticality || 'MEDIUM'}</strong> · Risk: <strong>{selectedDevice.risk_score ?? 0}/100</strong>
                </div>
              </div>
            )}

            <button
              onClick={runSim}
              disabled={!selectedDevice || loading}
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center' }}
            >
              <Crosshair size={14} />
              {loading ? 'Traversing Graph…' : 'Run What-If Simulation'}
            </button>
          </div>

          {/* Simulated Isolation Card */}
          {result && !isolated && (
            <div className="ng-card" style={{ borderColor: '#fca5a5' }}>
              <div style={{ fontWeight: 800, fontSize: '0.875rem', color: '#991b1b', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Shield size={16} /> Simulate Path Severance
              </div>
              <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: 12 }}>
                Simulate cutting {selectedDevice?.device_name}'s links in the Digital Twin. This neutralizes open alerts, updates health, and stops simulated traffic.
              </p>
              <button
                onClick={simulateIsolation}
                disabled={isolating}
                className="btn btn-danger"
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <Shield size={14} />
                {isolating ? 'Severing Links…' : 'Simulate Isolation'}
              </button>
            </div>
          )}

          {/* Isolated State Feedback Card */}
          {isolated && (
            <div className="ng-card" style={{ borderColor: '#6ee7b7' }}>
              <div style={{ fontWeight: 800, fontSize: '0.875rem', color: '#065f46', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <CheckCircle size={16} /> Twin Links Severed
              </div>
              <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: '10px 12px', fontSize: '0.775rem', color: '#065f46', marginBottom: 12, lineHeight: 1.4 }}>
                SIMULATED ACTION — {selectedDevice?.device_name} isolated. Potential attack path interrupted. <strong>No real network changes were performed.</strong>
              </div>
              <button
                onClick={restore}
                disabled={restoring}
                className="btn btn-secondary"
                style={{ width: '100%', justifyContent: 'center' }}
              >
                {restoring ? 'Restoring…' : '↩ Restore Device'}
              </button>
            </div>
          )}

          {/* Past Simulation History */}
          <div className="ng-card">
            <div className="ng-card-title" style={{ marginBottom: 10 }}>
              <Clock size={14} color="#64748b" /> Simulation History ({historyRuns.length})
            </div>
            {historyRuns.length === 0 ? (
              <div style={{ fontSize: '0.75rem', color: '#94a3b8', textAlign: 'center', padding: '12px 0' }}>No past runs recorded.</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 220, overflowY: 'auto' }}>
                {historyRuns.slice(0, 8).map(run => (
                  <div key={run.id} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 6, padding: '6px 8px', fontSize: '0.75rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 700, color: '#0f172a' }}>{run.target_device}</span>
                      <span className="tag-hypothetical" style={{ fontSize: '0.65rem', padding: '1px 4px' }}>HYPOTHETICAL</span>
                    </div>
                    <div style={{ color: '#64748b', fontSize: '0.7rem', marginTop: 2, display: 'flex', justifyContent: 'space-between' }}>
                      <span>Risk: {run.path_risk_score} ({run.risk_level})</span>
                      <span>Crit: {run.critical_assets_reached ? 'YES' : 'NO'}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: Results & Attack Path Visualization */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!result && !loading && (
            <div className="ng-card" style={{ minHeight: 360 }}>
              <div className="empty-state">
                <div className="empty-state-icon"><Crosshair size={28} color="#94a3b8" /></div>
                <div className="empty-state-title">No What-If Simulation Running</div>
                <div className="empty-state-sub" style={{ maxWidth: 440 }}>
                  Select a device on the left and click <strong>"Run What-If Simulation"</strong> to compute hypothetical lateral attack paths, reachable systems, and path risk through the Digital Twin.
                </div>
              </div>
            </div>
          )}

          {result && (
            <>
              {/* Scenario Text Banner */}
              <div style={{ background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 8, padding: '12px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Simulated Scenario</div>
                  <div style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                    {result.scenario_text || `${result.target_device} is hypothetically compromised`}
                  </div>
                </div>
                <span className="tag-hypothetical">HYPOTHETICAL RESULT</span>
              </div>

              {/* Exact Isolation Confirmation Banner if isolated */}
              {isolated && (
                <div style={{ background: '#f0fdf4', border: '1px solid #86efac', borderRadius: 8, padding: '12px 16px', color: '#166534', fontSize: '0.875rem', fontWeight: 600 }}>
                  SIMULATED ACTION — {selectedDevice?.device_name} isolated. Potential attack path interrupted. No real network changes were performed.
                </div>
              )}

              {/* Summary KPIs Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                <div className="ng-card-sm" style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Reachable Systems</div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 900, color: (result.reachable_nodes_count ?? result.reachable_count ?? 0) > 0 ? '#dc2626' : '#059669' }}>
                    {result.reachable_nodes_count ?? result.reachable_count ?? 0}
                  </div>
                </div>

                <div className="ng-card-sm" style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Hop Count</div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 900, color: '#d97706' }}>
                    {result.hop_count ?? 0}
                  </div>
                </div>

                <div className="ng-card-sm" style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Critical Asset Reached</div>
                  <div style={{ fontSize: '1.75rem', fontWeight: 900, color: result.critical_asset_reached === 'YES' ? '#dc2626' : '#059669' }}>
                    {result.critical_asset_reached ?? (result.is_critical_asset_reached ? 'YES' : 'NO')}
                  </div>
                </div>

                <div className="ng-card-sm" style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Simulated Risk Level</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 900, marginTop: 4 }}>
                    <RiskLevelBadge score={pathScore} level={simLevel} />
                  </div>
                </div>
              </div>

              {/* Before and After Comparison Card (Task 6) */}
              {isolationComparison && (
                <div className="ng-card" style={{ background: '#f8fafc', borderColor: '#bbf7d0' }}>
                  <div className="ng-card-title" style={{ marginBottom: 10, color: '#065f46' }}>
                    ⚖️ Before vs After Isolation Comparison
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                    <div style={{ background: '#fff5f5', border: '1px solid #fed7aa', borderRadius: 8, padding: '12px' }}>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#991b1b', textTransform: 'uppercase' }}>Before Isolation</div>
                      <div style={{ fontSize: '0.8125rem', marginTop: 4 }}>Reachable Systems: <strong>{isolationComparison.before.reachable_count}</strong></div>
                      <div style={{ fontSize: '0.8125rem', marginTop: 2 }}>Simulated Path Risk: <strong>{isolationComparison.before.simulated_risk}</strong></div>
                      <div style={{ fontSize: '0.8125rem', marginTop: 2 }}>Critical Asset Reached: <strong>{isolationComparison.before.critical_asset_reached}</strong></div>
                    </div>

                    <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: '12px' }}>
                      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#065f46', textTransform: 'uppercase' }}>After Simulated Isolation</div>
                      <div style={{ fontSize: '0.8125rem', marginTop: 4 }}>Reachable Systems: <strong>0</strong> (100% Severance)</div>
                      <div style={{ fontSize: '0.8125rem', marginTop: 2 }}>Simulated Path Risk: <strong>0.0</strong> (LOW)</div>
                      <div style={{ fontSize: '0.8125rem', marginTop: 2 }}>Critical Asset Reached: <strong>NO</strong></div>
                    </div>
                  </div>
                </div>
              )}

              {/* Potential Reach Path (Task 2 & 4) */}
              <div className="ng-card">
                <div className="ng-card-title" style={{ marginBottom: 12 }}>
                  🛤️ Potential Reach Path
                  <span style={{ marginLeft: 'auto', fontSize: '0.7rem', color: '#64748b' }}>
                    Length: {result.hop_count ?? 0} hops
                  </span>
                </div>
                <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 14px', fontFamily: 'monospace', fontSize: '0.875rem', fontWeight: 700, color: '#0f172a', marginBottom: 14 }}>
                  {primaryPathDisplay}
                </div>

                {/* Ordered Step List with Numbered Nodes and Text Labels (Task 4) */}
                {attackSteps.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                      Attack Path Traversal Steps:
                    </div>
                    {attackSteps.map(step => (
                      <div
                        key={step.step}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          background: step.step === 1 ? '#fee2e2' : step.is_critical ? '#fff7ed' : '#ffffff',
                          border: `1px solid ${step.step === 1 ? '#fca5a5' : step.is_critical ? '#fed7aa' : '#e2e8f0'}`,
                          borderRadius: 8,
                          padding: '10px 14px'
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{
                            width: 24, height: 24, borderRadius: '50%',
                            background: step.step === 1 ? '#dc2626' : step.is_critical ? '#d97706' : '#2563eb',
                            color: '#ffffff', display: 'flex', alignItems: 'center', justifyContent: 'center',
                            fontSize: '0.75rem', fontWeight: 800
                          }}>
                            {step.step}
                          </span>
                          <div>
                            <div style={{ fontSize: '0.875rem', fontWeight: 800, color: '#0f172a' }}>
                              {step.name || step.node}
                            </div>
                            <div style={{ fontSize: '0.725rem', color: '#64748b', fontFamily: 'monospace' }}>
                              {step.ip_address} · {step.device_type}
                            </div>
                          </div>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{
                            fontSize: '0.7rem',
                            fontWeight: 800,
                            padding: '3px 8px',
                            borderRadius: 6,
                            background: step.step === 1 ? '#fee2e2' : step.is_critical ? '#fff7ed' : '#f1f5f9',
                            color: step.step === 1 ? '#991b1b' : step.is_critical ? '#9a3412' : '#334155',
                            border: `1px solid ${step.step === 1 ? '#fca5a5' : step.is_critical ? '#fdba74' : '#cbd5e1'}`
                          }}>
                            {step.role_label}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* All Reachable Systems & Lateral Path Risks Table (Item 1) */}
                {result.attack_paths && result.attack_paths.length > 0 && (
                  <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid #e2e8f0' }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#475569', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span>Reachable Systems & Lateral Path Risks ({result.reachable_nodes_count ?? result.attack_paths.length}):</span>
                      <span style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 600 }}>Structural graph traversal</span>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 8 }}>
                      {result.attack_paths.map(ap => (
                        <div
                          key={ap.destination_node}
                          style={{
                            background: ap.destination_node === 'Database' ? '#fef2f2' : '#ffffff',
                            border: `1px solid ${ap.destination_node === 'Database' ? '#fca5a5' : '#e2e8f0'}`,
                            borderRadius: 6,
                            padding: '8px 10px',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            fontSize: '0.75rem'
                          }}
                        >
                          <div>
                            <div style={{ fontWeight: 800, color: '#0f172a', display: 'flex', alignItems: 'center', gap: 6 }}>
                              {ap.destination_node}
                              {ap.target_criticality === 'CRITICAL' && (
                                <span style={{ fontSize: '0.625rem', padding: '1px 4px', borderRadius: 4, background: '#fee2e2', color: '#991b1b', fontWeight: 800 }}>CRITICAL</span>
                              )}
                            </div>
                            <div style={{ color: '#64748b', fontSize: '0.675rem', fontFamily: 'monospace', marginTop: 1 }}>
                              {ap.hop_count} {ap.hop_count === 1 ? 'hop' : 'hops'} · {ap.path ? ap.path.join(' → ') : ''}
                            </div>
                          </div>
                          <div style={{ textAlign: 'right' }}>
                            <div style={{ fontWeight: 800, color: ap.risk >= 80 ? '#dc2626' : ap.risk >= 55 ? '#ea580c' : ap.risk >= 30 ? '#d97706' : '#059669' }}>
                              {ap.risk}
                            </div>
                            <div style={{ fontSize: '0.65rem', color: '#94a3b8' }}>{ap.simulated_risk_level}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* NetGuardian Simulated Path Risk & Mathematical Breakdown (Task 3) */}
              <div className="ng-card">
                <div className="ng-card-title" style={{ marginBottom: 12 }}>
                  NetGuardian Simulated Path Risk
                  <span style={{ marginLeft: 'auto' }}><RiskLevelBadge score={pathScore} level={simLevel} /></span>
                </div>

                <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 10 }}>
                  <span style={{ fontSize: '2.5rem', fontWeight: 900, color: pathScore >= 80 ? '#dc2626' : pathScore >= 55 ? '#f97316' : pathScore >= 30 ? '#d97706' : '#059669' }}>
                    {pathScore}
                  </span>
                  <span style={{ color: '#94a3b8', fontSize: '1rem', fontWeight: 600 }}>/100</span>
                  <span style={{ marginLeft: 8, fontSize: '0.75rem', color: '#64748b', fontStyle: 'italic' }}>
                    (Defensive simulation estimate — not a certified industry score)
                  </span>
                </div>

                <div className="health-bar-track" style={{ marginBottom: 14 }}>
                  <div className="health-bar-fill" style={{ width: `${pathScore}%`, background: pathScore >= 80 ? '#dc2626' : pathScore >= 55 ? '#f97316' : pathScore >= 30 ? '#d97706' : '#059669' }} />
                </div>

                {/* Mathematical Breakdown Table */}
                <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '12px 14px' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#475569', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Formula Component Breakdown:
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, textAlign: 'center' }}>
                    <div style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: 6, padding: '8px 6px' }}>
                      <div style={{ fontSize: '0.675rem', color: '#64748b', fontWeight: 600 }}>0.30 × Source Risk</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                        {result.breakdown?.source_risk?.points ?? (result.score_breakdown?.['Source Risk'] ?? 0)}
                      </div>
                      <div style={{ fontSize: '0.65rem', color: '#94a3b8' }}>Val: {result.breakdown?.source_risk?.value ?? 0}</div>
                    </div>

                    <div style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: 6, padding: '8px 6px' }}>
                      <div style={{ fontSize: '0.675rem', color: '#64748b', fontWeight: 600 }}>0.35 × Target Crit</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                        {result.breakdown?.target_criticality?.points ?? (result.score_breakdown?.['Target Criticality'] ?? 0)}
                      </div>
                      <div style={{ fontSize: '0.65rem', color: '#94a3b8' }}>Val: {result.breakdown?.target_criticality?.value ?? 0}</div>
                    </div>

                    <div style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: 6, padding: '8px 6px' }}>
                      <div style={{ fontSize: '0.675rem', color: '#64748b', fontWeight: 600 }}>0.15 × Hop Factor</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                        {result.breakdown?.hop_factor?.points ?? (result.score_breakdown?.['Hops'] ?? 0)}
                      </div>
                      <div style={{ fontSize: '0.65rem', color: '#94a3b8' }}>Factor: {result.breakdown?.hop_factor?.value ?? 0}</div>
                    </div>

                    <div style={{ background: '#ffffff', border: '1px solid #e2e8f0', borderRadius: 6, padding: '8px 6px' }}>
                      <div style={{ fontSize: '0.675rem', color: '#64748b', fontWeight: 600 }}>0.20 × Path Trust</div>
                      <div style={{ fontSize: '1.1rem', fontWeight: 800, color: '#0f172a', marginTop: 2 }}>
                        {result.breakdown?.path_trust?.points ?? (result.score_breakdown?.['Trust'] ?? 0)}
                      </div>
                      <div style={{ fontSize: '0.65rem', color: '#94a3b8' }}>Avg: {result.breakdown?.path_trust?.average_trust ?? 0}</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Recommended Controls (Task 2) */}
              <div className="ng-card">
                <div className="ng-card-title" style={{ marginBottom: 12 }}>
                  🛡️ Recommended Defensive Controls
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  {[
                    { title: 'Restrict Unnecessary Communication', desc: 'Sever non-essential lateral port routes between endpoint subnets and internal management interfaces.' },
                    { title: 'Review Trust Relationships', desc: 'Audit inherited subnet trust and enforce explicit microsegmentation boundaries.' },
                    { title: 'Isolate the Suspicious Endpoint', desc: 'Execute simulated containment in Digital Twin to evaluate blast-radius reduction before hardware changes.' },
                    { title: 'Monitor Server Connections', desc: 'Deploy fine-grained behavioral monitoring on high-criticality database and application servers.' },
                  ].map((c, idx) => (
                    <div key={idx} style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a' }}>
                        <span style={{ color: '#059669' }}>✓</span> {c.title}
                      </div>
                      <div style={{ fontSize: '0.725rem', color: '#64748b', marginTop: 4, lineHeight: 1.4 }}>
                        {c.desc}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Topology with Path Highlighted */}
              <div className="ng-card">
                <div className="ng-card-title" style={{ marginBottom: 12 }}>
                  Digital Twin Topology — Path Traversal Highlight
                  {isolated && <span className="badge badge-normal" style={{ marginLeft: 'auto' }}>Path Interrupted</span>}
                </div>
                <TopologyGraph
                  nodes={topology.nodes || []}
                  edges={topology.edges || []}
                  selectedNode={selectedDevice}
                  onSelectNode={() => {}}
                  height={380}
                />
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
