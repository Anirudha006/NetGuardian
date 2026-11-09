import React, { useState, useEffect } from 'react';
import { Search, Filter, Plus, RefreshCw, ChevronLeft, ChevronRight, Activity, Network, Layers, Radio } from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../hooks/useAuth';
import DeviceDrawer from '../components/device/DeviceDrawer';
import TopologyGraph from '../components/topology/TopologyGraph';

function SevBadge({ v }) {
  if (v >= 75) return <span className="badge badge-high">🔴 HIGH</span>;
  if (v >= 40) return <span className="badge badge-medium">🟡 MEDIUM</span>;
  return <span className="badge badge-normal">🟢 LOW</span>;
}

export default function DevicesPage({ onNavigate }) {
  const { isAdmin } = useAuth();
  const [subTab, setSubTab] = useState('table'); // 'table' | 'map' | 'traffic'
  
  // Devices state
  const [devices, setDevices] = useState([]);
  const [topology, setTopology] = useState({ nodes: [], edges: [] });
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selected, setSelected] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const limit = 20;

  // Traffic stream state
  const [trafficRecords, setTrafficRecords] = useState([]);
  const [trafficStats, setTrafficStats] = useState(null);
  const [trafficLoading, setTrafficLoading] = useState(false);
  const [anomalyOnly, setAnomalyOnly] = useState(false);
  const [scenario, setScenario] = useState('NORMAL');
  const [trafficSeed, setTrafficSeed] = useState('');
  const [pulsing, setPulsing] = useState(false);

  const loadDevices = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {};
      if (filterType) params.device_type = filterType;
      if (filterStatus) params.status = filterStatus;
      const [res, topo] = await Promise.all([
        api.getDevices(params),
        api.getDigitalTwinTopology()
      ]);
      const items = Array.isArray(res) ? res : (res.items || res.devices || []);
      setDevices(items);
      setTopology(topo);
    } catch (e) {
      console.error("Error loading network devices:", e);
      setError("Unable to load devices. Please verify the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  const loadTraffic = async () => {
    setTrafficLoading(true);
    try {
      const [t, s] = await Promise.all([
        api.getTraffic(100, anomalyOnly),
        api.getTrafficStats()
      ]);
      const items = Array.isArray(t) ? t : (t.records || t.items || []);
      setTrafficRecords(items);
      setTrafficStats(s);
    } catch (e) {
      console.error("Error loading traffic stream:", e);
    } finally {
      setTrafficLoading(false);
    }
  };

  useEffect(() => {
    loadDevices();
  }, [filterType, filterStatus]);

  useEffect(() => {
    if (subTab === 'traffic') {
      loadTraffic();
      const iv = setInterval(loadTraffic, 6000);
      return () => clearInterval(iv);
    }
  }, [subTab, anomalyOnly]);

  const handlePulseTraffic = async () => {
    setPulsing(true);
    try {
      const query = new URLSearchParams({ scenario });
      if (trafficSeed) query.append('seed', trafficSeed);
      await fetch(`/api/traffic/pulse?${query.toString()}`, { method: 'POST', credentials: 'include' });
      await loadTraffic();
      await loadDevices();
    } catch (e) {
      console.error(e);
    } finally {
      setPulsing(false);
    }
  };

  // Filtered devices
  const filtered = devices.filter(d => {
    const s = search.toLowerCase();
    const matchSearch = !search || d.device_name?.toLowerCase().includes(s) || d.ip_address?.includes(s) || d.mac_address?.toLowerCase().includes(s);
    return matchSearch;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / limit));
  const paginated = filtered.slice((page - 1) * limit, page * limit);

  const formatBytes = (b) => b >= 1_000_000 ? `${(b/1_000_000).toFixed(1)} MB` : b >= 1000 ? `${(b/1000).toFixed(1)} KB` : `${b} B`;

  if (error && devices.length === 0) {
    return (
      <div style={{ padding: '60px 0', maxWidth: 640, margin: '0 auto', textAlign: 'center' }}>
        <div className="ng-card" style={{ padding: '40px 30px' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>⚠️</div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#0f172a', marginBottom: 8 }}>
            Unable to Load Devices
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: 20 }}>
            Unable to load devices. Please verify the backend is running.
          </p>
          <button
            onClick={loadDevices}
            className="btn btn-primary"
            style={{ margin: '0 auto' }}
          >
            <RefreshCw size={14} /> Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20, gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a' }}>Network Operations</h1>
            <span className="ng-mode-badge">MODE: SIMULATION</span>
          </div>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 3 }}>
            Monitored virtual infrastructure · Deterministic synthetic flows · <span className="tag-simulated">SIMULATED DATA</span>
          </p>
        </div>

        {/* View Switcher Tabs & Actions */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', background: '#e2e8f0', borderRadius: 8, padding: 3, gap: 2 }}>
            <button
              onClick={() => setSubTab('table')}
              className={`btn btn-sm ${subTab === 'table' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontWeight: 600, padding: '4px 12px' }}
            >
              📋 Devices ({devices.length})
            </button>
            <button
              onClick={() => setSubTab('map')}
              className={`btn btn-sm ${subTab === 'map' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontWeight: 600, padding: '4px 12px' }}
            >
              🗺️ Network Map
            </button>
            <button
              onClick={() => setSubTab('traffic')}
              className={`btn btn-sm ${subTab === 'traffic' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontWeight: 600, padding: '4px 12px' }}
            >
              📡 Traffic Stream
            </button>
          </div>

          {isAdmin && (
            <button onClick={() => setShowAdd(true)} className="btn btn-primary btn-sm">
              <Plus size={14} /> Add Simulated Device
            </button>
          )}

          <button onClick={() => { loadDevices(); if (subTab === 'traffic') loadTraffic(); }} className="btn btn-secondary btn-sm" title="Refresh">
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* SUB-TAB 1: DEVICES TABLE */}
      {subTab === 'table' && (
        <>
          {/* Search & Filters */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
            <div style={{ position: 'relative', flex: 1, minWidth: 220 }}>
              <Search size={14} color="#94a3b8" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
              <input
                className="ng-input"
                style={{ paddingLeft: 32 }}
                placeholder="Search by device name, IP, or MAC…"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(1); }}
              />
            </div>
            
            <select
              className="ng-select"
              style={{ width: 170 }}
              value={filterType}
              onChange={e => { setFilterType(e.target.value); setPage(1); }}
            >
              <option value="">All Device Types</option>
              {['Router', 'Switch', 'Workstation', 'Laptop', 'Server', 'Database', 'Printer', 'Mobile', 'Camera', 'Internet'].map(t => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>

            <select
              className="ng-select"
              style={{ width: 170 }}
              value={filterStatus}
              onChange={e => { setFilterStatus(e.target.value); setPage(1); }}
            >
              <option value="">All Statuses</option>
              {['ONLINE', 'SUSPICIOUS', 'CRITICAL', 'OFFLINE', 'ISOLATED'].map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          {/* Table */}
          <div className="ng-table-wrap">
            <table className="ng-table">
              <thead>
                <tr>
                  <th>Device Name</th>
                  <th>IP Address</th>
                  <th>MAC Address</th>
                  <th>Type</th>
                  <th>OS / Firmware</th>
                  <th>Criticality</th>
                  <th>Trust Level</th>
                  <th>Status</th>
                  <th>Risk Score</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan={10} style={{ textAlign: 'center', padding: 36, color: '#94a3b8' }}>Loading network devices…</td></tr>
                ) : paginated.length === 0 ? (
                  <tr><td colSpan={10} style={{ textAlign: 'center', padding: 36, color: '#94a3b8' }}>No devices matching search/filter criteria.</td></tr>
                ) : paginated.map(d => (
                  <tr key={d.id}>
                    <td style={{ fontWeight: 700, color: '#0f172a' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span>{d.device_name}</span>
                        {d.device_source === 'OBSERVED' || d.is_registered === false ? (
                          <span className="tag-observed" title="Passively observed on network (Unregistered)">OBSERVED</span>
                        ) : (
                          <span className="tag-simulated" title="Simulated inventory baseline">SIMULATED</span>
                        )}
                      </div>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8125rem' }}>{d.ip_address}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#64748b' }}>{d.mac_address}</td>
                    <td><span className="badge badge-info">{d.device_type}</span></td>
                    <td style={{ fontSize: '0.8125rem', color: '#64748b' }}>{d.os_type || '—'}</td>
                    <td>
                      <span className={`badge ${d.criticality === 'CRITICAL' ? 'badge-high' : d.criticality === 'HIGH' ? 'badge-medium' : 'badge-normal'}`}>
                        {d.criticality}
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${
                        d.trust_level === 'HIGH' ? 'badge-normal' :
                        d.trust_level === 'MEDIUM' ? 'badge-info' :
                        d.trust_level === 'LOW' ? 'badge-medium' : 'badge-high'
                      }`}>
                        {d.trust_level || 'MEDIUM'} ({d.trust_score ?? 100})
                      </span>
                    </td>
                    <td>
                      <span className={`badge ${d.status === 'ONLINE' ? 'badge-normal' : d.status === 'CRITICAL' ? 'badge-high' : d.status === 'SUSPICIOUS' ? 'badge-medium' : d.status === 'ISOLATED' ? 'badge-info' : 'badge-offline'}`}>
                        {d.status}
                      </span>
                    </td>
                    <td><SevBadge v={d.risk_score ?? 0} /></td>
                    <td>
                      <button onClick={() => setSelected(d)} className="btn btn-ghost btn-sm" style={{ color: '#2563eb', fontWeight: 700 }}>
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 12, marginTop: 16 }}>
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="btn btn-secondary btn-sm"
              >
                <ChevronLeft size={14} /> Previous
              </button>
              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#64748b' }}>
                Page {page} of {totalPages} ({filtered.length} total devices)
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="btn btn-secondary btn-sm"
              >
                Next <ChevronRight size={14} />
              </button>
            </div>
          )}
        </>
      )}

      {/* SUB-TAB 2: TOPOLOGY MAP VIEW */}
      {subTab === 'map' && (
        <div className="ng-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 18px', borderBottom: '1px solid #e2e8f0', background: '#f8fafc', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ fontSize: '0.875rem', fontWeight: 700, color: '#0f172a' }}>
              Hierarchical Architecture: Internet → Router → Switch → Endpoints/Server → Database
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
              Click any node to inspect risk & connections
            </div>
          </div>
          <TopologyGraph
            nodes={topology.nodes}
            edges={topology.edges}
            selectedNode={selected}
            onSelectNode={setSelected}
            height={560}
          />
        </div>
      )}

      {/* SUB-TAB 3: LIVE TRAFFIC STREAM VIEW (Task 10) */}
      {subTab === 'traffic' && (
        <div>
          {/* Traffic Pulse Controls & Deterministic Seed */}
          <div className="ng-card-sm" style={{ marginBottom: 18, background: '#ffffff' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
              <div>
                <div style={{ fontWeight: 800, fontSize: '0.9375rem', color: '#0f172a' }}>
                  Synthetic Traffic Generation Engine
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>
                  Deterministic flows with repeatable seeds and scenario simulation
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                <select
                  className="ng-select"
                  style={{ width: 170 }}
                  value={scenario}
                  onChange={e => setScenario(e.target.value)}
                >
                  <option value="NORMAL">Normal Traffic</option>
                  <option value="LIGHT">Light Volume</option>
                  <option value="BUSY">Busy Burst</option>
                  <option value="SUSPICIOUS_ACTIVITY">Suspicious Ports</option>
                  <option value="SECURITY_INCIDENT">Security Incident</option>
                </select>

                <input
                  className="ng-input"
                  style={{ width: 120 }}
                  type="number"
                  placeholder="Seed (e.g. 42)"
                  value={trafficSeed}
                  onChange={e => setTrafficSeed(e.target.value)}
                  title="Deterministic integer seed"
                />

                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8125rem', color: '#334155', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={anomalyOnly}
                    onChange={e => setAnomalyOnly(e.target.checked)}
                    style={{ accentColor: '#dc2626' }}
                  />
                  Anomalies Only
                </label>

                <button
                  onClick={handlePulseTraffic}
                  disabled={pulsing}
                  className="btn btn-primary btn-sm"
                  style={{ fontWeight: 700 }}
                >
                  <Activity size={13} /> {pulsing ? 'Generating Pulse…' : 'Generate Pulse'}
                </button>
              </div>
            </div>
          </div>

          {/* Traffic Stats KPI Summary */}
          {trafficStats && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 18 }}>
              {[
                ['Total Processed Packets', trafficStats.total_packets || 0, '#2563eb'],
                ['Total Bytes Transferred', formatBytes(trafficStats.total_bytes || 0), '#7c3aed'],
                ['Active Connection Flows', trafficStats.active_connections || 0, '#059669'],
                ['Anomalous Records Flagged', trafficStats.anomalous_records || 0, '#dc2626'],
              ].map(([l, v, c]) => (
                <div key={l} className="kpi-card" style={{ borderTop: `3px solid ${c}` }}>
                  <span className="kpi-label">{l}</span>
                  <span className="kpi-value" style={{ color: c }}>{v}</span>
                </div>
              ))}
            </div>
          )}

          {/* Traffic Stream Table */}
          <div className="ng-table-wrap">
            <table className="ng-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Src Port</th>
                  <th>Dst Port</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Duration</th>
                  <th>Detection Status</th>
                </tr>
              </thead>
              <tbody>
                {trafficLoading && trafficRecords.length === 0 ? (
                  <tr><td colSpan={10} style={{ textAlign: 'center', padding: 36, color: '#94a3b8' }}>Loading traffic stream…</td></tr>
                ) : trafficRecords.length === 0 ? (
                  <tr><td colSpan={10} style={{ textAlign: 'center', padding: 36, color: '#94a3b8' }}>No traffic flows recorded. Click "Generate Pulse" to emit traffic.</td></tr>
                ) : trafficRecords.map((r, i) => (
                  <tr key={i} style={r.is_anomalous ? { background: '#fff5f5' } : {}}>
                    <td style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'monospace' }}>
                      {r.timestamp ? new Date(r.timestamp).toLocaleTimeString() : '—'}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8125rem' }}>{r.source_ip}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.8125rem' }}>{r.destination_ip}</td>
                    <td><span className="badge badge-info">{r.protocol}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{r.source_port}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{r.destination_port}</td>
                    <td style={{ fontWeight: 600 }}>{r.packet_count}</td>
                    <td>{formatBytes(r.bytes)}</td>
                    <td style={{ fontSize: '0.75rem', color: '#64748b' }}>{r.duration ? `${r.duration.toFixed(3)}s` : '—'}</td>
                    <td>
                      {r.is_anomalous ? (
                        <span className="badge badge-high">⚠️ ANOMALOUS</span>
                      ) : (
                        <span className="badge badge-normal">🟢 BENIGN</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Device Side Panel Drawer */}
      {selected && (
        <DeviceDrawer
          device={selected}
          onClose={() => setSelected(null)}
          onRunWhatIf={d => { setSelected(null); onNavigate('what-if', d); }}
          onDeviceUpdated={loadDevices}
        />
      )}

      {/* Add Simulated Device Modal (Admin Only - Task 3) */}
      {showAdd && (
        <AddDeviceModal
          onClose={() => setShowAdd(false)}
          onAdded={() => { loadDevices(); setSubTab('table'); }}
        />
      )}
    </div>
  );
}

function AddDeviceModal({ onClose, onAdded }) {
  const [form, setForm] = useState({
    device_name: '',
    ip_address: '',
    mac_address: '',
    device_type: 'Workstation',
    os_type: 'Linux',
    criticality: 'MEDIUM',
    trust_level: 'MEDIUM',
    status: 'ONLINE',
    trust_score: 85.0
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError('');

    // IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(form.ip_address.trim())) {
      setError('Invalid IP address format. Example: 192.168.1.55');
      return;
    }

    // MAC validation
    const macRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
    if (!macRegex.test(form.mac_address.trim())) {
      setError('Invalid MAC address format. Example: 00:1A:2B:3C:4D:5E');
      return;
    }

    setLoading(true);
    try {
      await api.createDevice({
        ...form,
        device_name: form.device_name.trim(),
        ip_address: form.ip_address.trim(),
        mac_address: form.mac_address.trim(),
        trust_score: form.trust_level === 'HIGH' ? 95 : form.trust_level === 'MEDIUM' ? 80 : form.trust_level === 'LOW' ? 50 : 20
      });
      onAdded();
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to add simulated device.');
    } finally {
      setLoading(false);
    }
  };

  if (error && devices.length === 0) {
    return (
      <div style={{ padding: '60px 0', maxWidth: 640, margin: '0 auto', textAlign: 'center' }}>
        <div className="ng-card" style={{ padding: '40px 30px' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>⚠️</div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#0f172a', marginBottom: 8 }}>
            Unable to Load Devices
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: 20 }}>
            Unable to load devices. Please verify the backend is running.
          </p>
          <button
            onClick={loadDevices}
            className="btn btn-primary"
            style={{ margin: '0 auto' }}
          >
            <RefreshCw size={14} /> Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="ng-modal-overlay" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="ng-modal" style={{ maxWidth: 480 }}>
        <div className="ng-modal-header">
          <div>
            <div style={{ fontWeight: 800, fontSize: '1.0625rem', color: '#0f172a' }}>
              Add Simulated Device
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>
              Attached to Core-Switch-01 · <span className="tag-simulated">SIMULATED ONLY</span>
            </div>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-sm">✕</button>
        </div>

        <form onSubmit={submit}>
          <div className="ng-modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {error && (
              <div style={{ background: '#fee2e2', border: '1px solid #fca5a5', color: '#991b1b', padding: '8px 12px', borderRadius: 8, fontSize: '0.8125rem' }}>
                {error}
              </div>
            )}

            <div>
              <label className="ng-label">Device Name *</label>
              <input
                className="ng-input"
                type="text"
                required
                placeholder="e.g., Security-Auditor-PC"
                value={form.device_name}
                onChange={e => setForm(p => ({ ...p, device_name: e.target.value }))}
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label className="ng-label">IP Address *</label>
                <input
                  className="ng-input"
                  type="text"
                  required
                  placeholder="192.168.1.55"
                  value={form.ip_address}
                  onChange={e => setForm(p => ({ ...p, ip_address: e.target.value }))}
                />
              </div>

              <div>
                <label className="ng-label">MAC Address *</label>
                <input
                  className="ng-input"
                  type="text"
                  required
                  placeholder="00:1A:2B:3C:4D:55"
                  value={form.mac_address}
                  onChange={e => setForm(p => ({ ...p, mac_address: e.target.value }))}
                />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label className="ng-label">Device Type *</label>
                <select
                  className="ng-select"
                  value={form.device_type}
                  onChange={e => setForm(p => ({ ...p, device_type: e.target.value }))}
                >
                  {['Workstation', 'Laptop', 'Server', 'Database', 'Printer', 'Mobile', 'Camera', 'IoT', 'Router', 'Switch'].map(t => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="ng-label">OS / Firmware</label>
                <input
                  className="ng-input"
                  type="text"
                  placeholder="e.g., Windows 11, Linux"
                  value={form.os_type}
                  onChange={e => setForm(p => ({ ...p, os_type: e.target.value }))}
                />
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label className="ng-label">Trust Level *</label>
                <select
                  className="ng-select"
                  value={form.trust_level}
                  onChange={e => setForm(p => ({ ...p, trust_level: e.target.value }))}
                >
                  <option value="HIGH">High (Hardened Infrastructure)</option>
                  <option value="MEDIUM">Medium (Managed Endpoints)</option>
                  <option value="LOW">Low (Personal / Vulnerable IoT)</option>
                  <option value="UNTRUSTED">Untrusted (Unregistered / Guest)</option>
                </select>
              </div>

              <div>
                <label className="ng-label">Criticality *</label>
                <select
                  className="ng-select"
                  value={form.criticality}
                  onChange={e => setForm(p => ({ ...p, criticality: e.target.value }))}
                >
                  <option value="LOW">Low</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="HIGH">High</option>
                  <option value="CRITICAL">Critical</option>
                </select>
              </div>
            </div>
          </div>

          <div className="ng-modal-footer">
            <button type="button" onClick={onClose} className="btn btn-secondary">
              Cancel
            </button>
            <button type="submit" disabled={loading} className="btn btn-primary">
              {loading ? 'Adding Device…' : 'Add Simulated Device'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
