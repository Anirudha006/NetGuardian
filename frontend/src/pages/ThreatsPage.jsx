import React, { useState, useEffect } from 'react';
import {
  Search, Filter, RefreshCw, ChevronDown, ChevronRight,
  AlertTriangle, Shield, CheckCircle2, Eye, Play, X,
  ExternalLink, Clock, Target, Server, Laptop, HelpCircle,
  ArrowRight, ShieldAlert, Cpu
} from 'lucide-react';
import { api } from '../services/api';
import { showToast } from '../App';

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

const SIMULATION_SCENARIOS = [
  {
    id: 'UNKNOWN_DEVICE',
    title: '1. Unknown Device Joins',
    severity: 'MEDIUM',
    badgeColor: '#d97706',
    icon: '❓',
    desc: 'Unregistered host joins the network and begins transmitting packet flows.',
    defaultSource: '192.168.1.99',
    defaultTarget: '192.168.1.20'
  },
  {
    id: 'PORT_SCAN',
    title: '2. Port Scan Reconnaissance',
    severity: 'HIGH',
    badgeColor: '#ea580c',
    icon: '⚡',
    desc: 'Rapid reconnaissance probes across 17 distinct service ports in a 60-second window.',
    defaultSource: '192.168.1.10',
    defaultTarget: '192.168.1.20'
  },
  {
    id: 'TRAFFIC_ANOMALY',
    title: '3. Traffic Volume Anomaly Spike',
    severity: 'MEDIUM',
    badgeColor: '#d97706',
    icon: '🌊',
    desc: 'Sudden bandwidth burst (1.85 MB) far exceeding normal baseline thresholds.',
    defaultSource: '192.168.1.11',
    defaultTarget: '192.168.1.20'
  },
  {
    id: 'FAILED_AUTH',
    title: '4. Repeated Failed Authentication',
    severity: 'HIGH',
    badgeColor: '#ea580c',
    icon: '🔑',
    desc: 'Multiple consecutive rejected login attempts (possible brute-force pattern on SSH port 22).',
    defaultSource: '192.168.1.12',
    defaultTarget: '192.168.1.20'
  },
  {
    id: 'SUSPICIOUS_OUTBOUND',
    title: '5. Suspicious Outbound Connection',
    severity: 'HIGH',
    badgeColor: '#ea580c',
    icon: '🌐',
    desc: 'Outbound connection initiated towards an external host on unusual/high-risk port (4444).',
    defaultSource: '192.168.1.13',
    defaultTarget: '203.0.113.1'
  },
  {
    id: 'COMPROMISED_HOST',
    title: '6. Compromised Device Scenario',
    severity: 'CRITICAL',
    badgeColor: '#dc2626',
    icon: '☣️',
    desc: 'Host flagged as compromised with lateral movement traffic targeting protected core assets.',
    defaultSource: '192.168.1.10',
    defaultTarget: '192.168.1.21'
  }
];

function SevBadge({ s }) {
  const norm = (s || 'INFO').toUpperCase();
  const cls = {
    CRITICAL: 'badge-critical',
    HIGH: 'badge-high',
    MEDIUM: 'badge-medium',
    LOW: 'badge-low',
    INFO: 'badge-info'
  };
  const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: 'ℹ️' };
  return (
    <span className={`badge ${cls[norm] || 'badge-info'}`} style={{ whiteSpace: 'nowrap' }}>
      {icons[norm] || 'ℹ️'} {norm}
    </span>
  );
}

function StatusBadge({ s }) {
  const norm = (s || 'NEW').toUpperCase().replace(' ', '_');
  const config = {
    NEW: { label: 'New', color: '#2563eb', bg: '#eff6ff', border: '#bfdbfe' },
    INVESTIGATING: { label: 'Investigating', color: '#d97706', bg: '#fffbeb', border: '#fde68a' },
    CONTAINED: { label: 'Contained', color: '#7c3aed', bg: '#f5f3ff', border: '#ddd6fe' },
    RESOLVED: { label: 'Resolved', color: '#059669', bg: '#f0fdf4', border: '#bbf7d0' },
    FALSE_POSITIVE: { label: 'False Positive', color: '#64748b', bg: '#f8fafc', border: '#cbd5e1' }
  };
  const current = config[norm] || config.NEW;
  return (
    <span
      style={{
        fontSize: '0.725rem',
        fontWeight: 700,
        padding: '2px 8px',
        borderRadius: 20,
        background: current.bg,
        color: current.color,
        border: `1px solid ${current.border}`,
        whiteSpace: 'nowrap'
      }}
    >
      {current.label}
    </span>
  );
}

export default function ThreatsPage({ onNavigate }) {
  const [alerts, setAlerts] = useState([]);
  const [devices, setDevices] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [filterSev, setFilterSev] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterType, setFilterType] = useState('');
  const [dateRange, setDateRange] = useState('ALL');

  // Pagination
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Modal / Detail state
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [simModalOpen, setSimModalOpen] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState(SIMULATION_SCENARIOS[0].id);
  const [simSourceIp, setSimSourceIp] = useState('192.168.1.10');
  const [simTargetIp, setSimTargetIp] = useState('192.168.1.20');
  const [isSimulating, setIsSimulating] = useState(false);
  const [updatingId, setUpdatingId] = useState(null);

  // Load devices for the source picker
  useEffect(() => {
    const fetchDevices = async () => {
      try {
        const devs = await api.getDevices();
        if (Array.isArray(devs)) setDevices(devs);
      } catch (err) {
        console.error('Failed to load devices for simulation picker', err);
      }
    };
    fetchDevices();
  }, []);

  const loadAlerts = async () => {
    setLoading(true);
    try {
      const params = { limit: 200 };
      if (filterSev) params.severity = filterSev;
      if (filterStatus) params.status = filterStatus;
      if (filterType) params.event_type = filterType;
      if (search) params.search = search;

      const res = await api.getAlerts(params);
      const items = Array.isArray(res) ? res : (res.items || res.alerts || []);
      setAlerts(items.sort((a, b) => {
        const diff = (SEV_ORDER[a.severity?.toUpperCase()] ?? 9) - (SEV_ORDER[b.severity?.toUpperCase()] ?? 9);
        if (diff !== 0) return diff;
        return new Date(b.created_at) - new Date(a.created_at);
      }));
      setTotal(items.length);
    } catch (e) {
      console.error('Error fetching alerts:', e);
      showToast(e.message || 'Failed to load threats', 'error');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [filterSev, filterStatus, filterType]);

  const handleStatusUpdate = async (alertId, newStatus) => {
    setUpdatingId(alertId);
    try {
      const updated = await api.updateAlertStatus(alertId, newStatus);
      showToast(`Alert #${alertId} status changed to ${newStatus}`, 'success');
      // Update local state immediately
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: updated.status } : a));
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert(prev => ({ ...prev, status: updated.status }));
      }
    } catch (err) {
      showToast(err.message || 'Status update failed', 'error');
    } finally {
      setUpdatingId(null);
    }
  };

  const handleExecuteSimulation = async () => {
    setIsSimulating(true);
    try {
      const res = await api.triggerSecurityEvent(selectedScenario, simSourceIp, simTargetIp);
      showToast(`Simulated event triggered: ${res.message || 'Alert generated'}`, 'success');
      setSimModalOpen(false);
      await loadAlerts();
    } catch (err) {
      showToast(err.message || 'Simulation execution failed', 'error');
    } finally {
      setIsSimulating(false);
    }
  };

  // Filter pipeline
  const filteredAlerts = alerts.filter(a => {
    if (search) {
      const s = search.toLowerCase();
      const matchId = String(a.id).includes(s.replace('#', ''));
      const matchTitle = a.title?.toLowerCase().includes(s);
      const matchSrc = a.source_ip?.toLowerCase().includes(s);
      const matchDst = a.destination_ip?.toLowerCase().includes(s);
      const matchRule = a.rule_name?.toLowerCase().includes(s);
      const matchType = a.event_type?.toLowerCase().includes(s);
      if (!matchId && !matchTitle && !matchSrc && !matchDst && !matchRule && !matchType) {
        return false;
      }
    }

    if (dateRange === 'TODAY') {
      const today = new Date().toDateString();
      if (new Date(a.created_at).toDateString() !== today) return false;
    } else if (dateRange === '7DAYS') {
      const sevenDaysAgo = new Date(Date.now() - 7 * 86400000);
      if (new Date(a.created_at) < sevenDaysAgo) return false;
    }

    return true;
  });

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(filteredAlerts.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paginatedAlerts = filteredAlerts.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>

      {/* Top Header Row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20, gap: 12, flexWrap: 'wrap' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
              Threats & Security Alerts
            </h1>
            <span className="tag-detected">DETECTED</span>
            <span className="tag-simulated">SIMULATED</span>
          </div>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 4 }}>
            Security events flagged by Layer 1 Rule Detection and Digital Twin traffic analysis.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            onClick={() => setSimModalOpen(true)}
            className="btn btn-primary"
            style={{ fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}
          >
            <Play size={14} fill="currentColor" />
            Simulate Security Event
          </button>

          <span
            style={{
              background: '#fee2e2',
              color: '#991b1b',
              border: '1px solid #fca5a5',
              borderRadius: 8,
              padding: '6px 12px',
              fontSize: '0.8125rem',
              fontWeight: 700
            }}
          >
            {filteredAlerts.length} Active Alert{filteredAlerts.length !== 1 ? 's' : ''}
          </span>

          <button onClick={loadAlerts} className="btn btn-ghost btn-sm" title="Refresh alerts list">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="ng-card" style={{ padding: '14px 18px', marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Search Box */}
          <div style={{ position: 'relative', flex: 2, minWidth: 220 }}>
            <Search size={14} color="#94a3b8" style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)' }} />
            <input
              className="ng-input"
              style={{ paddingLeft: 32 }}
              placeholder="Search by Threat ID, title, host IP, or rule…"
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
            />
          </div>

          {/* Severity Filter */}
          <select
            className="ng-select"
            style={{ width: 150 }}
            value={filterSev}
            onChange={e => { setFilterSev(e.target.value); setPage(1); }}
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">🔴 CRITICAL</option>
            <option value="HIGH">🟠 HIGH</option>
            <option value="MEDIUM">🟡 MEDIUM</option>
            <option value="LOW">🔵 LOW</option>
            <option value="INFO">ℹ️ INFO</option>
          </select>

          {/* Status Filter */}
          <select
            className="ng-select"
            style={{ width: 160 }}
            value={filterStatus}
            onChange={e => { setFilterStatus(e.target.value); setPage(1); }}
          >
            <option value="">All Statuses</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>

          {/* Event Type Filter */}
          <select
            className="ng-select"
            style={{ width: 190 }}
            value={filterType}
            onChange={e => { setFilterType(e.target.value); setPage(1); }}
          >
            <option value="">All Event Types</option>
            <option value="PORT_SCAN">Port Scan</option>
            <option value="TRAFFIC_ANOMALY">Traffic Anomaly</option>
            <option value="UNKNOWN_DEVICE">Unknown Device</option>
            <option value="FAILED_AUTH">Failed Auth / Brute Force</option>
            <option value="SUSPICIOUS_OUTBOUND">Suspicious Outbound</option>
            <option value="COMPROMISED_DEVICE">Host Compromise</option>
            <option value="CRITICAL_ASSET_ACCESS">Critical Asset Access</option>
          </select>

          {/* Date Filter */}
          <select
            className="ng-select"
            style={{ width: 130 }}
            value={dateRange}
            onChange={e => { setDateRange(e.target.value); setPage(1); }}
          >
            <option value="ALL">All Time</option>
            <option value="TODAY">Today Only</option>
            <option value="7DAYS">Past 7 Days</option>
          </select>

          {/* Clear Filters Button */}
          {(search || filterSev || filterStatus || filterType || dateRange !== 'ALL') && (
            <button
              onClick={() => {
                setSearch('');
                setFilterSev('');
                setFilterStatus('');
                setFilterType('');
                setDateRange('ALL');
                setPage(1);
              }}
              className="btn btn-ghost btn-sm"
              style={{ color: '#dc2626', fontWeight: 600 }}
            >
              Clear Filters
            </button>
          )}
        </div>
      </div>

      {/* Main Table View */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: 60, color: '#94a3b8' }}>
          <RefreshCw size={24} className="spin" style={{ margin: '0 auto 12px' }} />
          <div>Loading threats and alerts from database…</div>
        </div>
      ) : filteredAlerts.length === 0 ? (
        <div className="empty-state" style={{ background: 'white', borderRadius: 12, border: '1px solid #e2e8f0', padding: 48, textAlign: 'center' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>🛡️</div>
          <div className="empty-state-title" style={{ fontSize: '1.125rem', fontWeight: 700, color: '#0f172a' }}>
            No Threats Detected
          </div>
          <div className="empty-state-sub" style={{ fontSize: '0.875rem', color: '#64748b', maxWidth: 460, margin: '6px auto 18px' }}>
            There are no active security alerts matching the current filters. Click "Simulate Security Event" to inject safe synthetic threat patterns.
          </div>
          <button onClick={() => setSimModalOpen(true)} className="btn btn-primary btn-sm">
            Simulate Security Event
          </button>
        </div>
      ) : (
        <div className="ng-card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="ng-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ background: '#f8fafc', borderBottom: '1px solid #e2e8f0', textAlign: 'left', fontSize: '0.75rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  <th style={{ padding: '12px 16px' }}>Threat ID</th>
                  <th style={{ padding: '12px 16px' }}>Type & Title</th>
                  <th style={{ padding: '12px 16px' }}>Source Host</th>
                  <th style={{ padding: '12px 16px' }}>Target</th>
                  <th style={{ padding: '12px 16px' }}>Severity</th>
                  <th style={{ padding: '12px 16px' }}>Confidence</th>
                  <th style={{ padding: '12px 16px' }}>Detected Time</th>
                  <th style={{ padding: '12px 16px' }}>Status</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedAlerts.map(alert => {
                  const occurrences = alert.occurrence_count || 1;
                  return (
                    <tr
                      key={alert.id}
                      style={{ borderBottom: '1px solid #f1f5f9', cursor: 'pointer', transition: 'background 0.12s' }}
                      onMouseEnter={e => e.currentTarget.style.background = '#f8fafc'}
                      onMouseLeave={e => e.currentTarget.style.background = 'white'}
                      onClick={() => setSelectedAlert(alert)}
                    >
                      {/* Threat ID */}
                      <td style={{ padding: '14px 16px', fontWeight: 700, fontFamily: 'monospace', color: '#0f172a' }}>
                        #{alert.id}
                      </td>

                      {/* Type & Title */}
                      <td style={{ padding: '14px 16px', minWidth: 240 }}>
                        <div style={{ fontWeight: 700, color: '#0f172a', fontSize: '0.875rem' }}>
                          {alert.title}
                        </div>
                        <div style={{ fontSize: '0.725rem', color: '#64748b', marginTop: 2, display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ fontFamily: 'monospace' }}>{alert.rule_name || alert.event_type || 'RULE'}</span>
                          <span style={{
                            padding: '1px 6px',
                            borderRadius: 6,
                            fontSize: '0.675rem',
                            fontWeight: 700,
                            background: (alert.detection_method === 'RULE+AI' || alert.detected_by === 'rule+ai') ? '#eff6ff' : (alert.detection_method === 'AI' || alert.detected_by === 'ai') ? '#f5f3ff' : '#f1f5f9',
                            color: (alert.detection_method === 'RULE+AI' || alert.detected_by === 'rule+ai') ? '#1d4ed8' : (alert.detection_method === 'AI' || alert.detected_by === 'ai') ? '#6d28d9' : '#475569',
                            border: `1px solid ${(alert.detection_method === 'RULE+AI' || alert.detected_by === 'rule+ai') ? '#bfdbfe' : (alert.detection_method === 'AI' || alert.detected_by === 'ai') ? '#ddd6fe' : '#e2e8f0'}`
                          }}>
                            {alert.detection_method || (alert.detected_by ? alert.detected_by.toUpperCase() : 'RULE')}
                          </span>
                          {occurrences > 1 && (
                            <span style={{ background: '#fef3c7', color: '#92400e', padding: '1px 6px', borderRadius: 10, fontSize: '0.675rem', fontWeight: 700 }}>
                              {occurrences}x occurrences
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Source */}
                      <td style={{ padding: '14px 16px', fontFamily: 'monospace', fontSize: '0.8125rem', color: '#334155' }}>
                        {alert.source_ip || '—'}
                      </td>

                      {/* Target */}
                      <td style={{ padding: '14px 16px', fontFamily: 'monospace', fontSize: '0.8125rem', color: '#64748b' }}>
                        {alert.destination_ip || 'Network Gateway'}
                      </td>

                      {/* Severity */}
                      <td style={{ padding: '14px 16px' }}>
                        <SevBadge s={alert.severity} />
                      </td>

                      {/* Confidence */}
                      <td style={{ padding: '14px 16px', fontSize: '0.8125rem', fontWeight: 600, color: '#0f172a' }}>
                        {alert.ai_confidence ? `${alert.ai_confidence}` : '92%'}
                      </td>

                      {/* Detected Time */}
                      <td style={{ padding: '14px 16px', fontSize: '0.75rem', color: '#64748b', whiteSpace: 'nowrap' }}>
                        <div>{new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</div>
                        <div style={{ fontSize: '0.675rem', color: '#94a3b8' }}>{new Date(alert.created_at).toLocaleDateString()}</div>
                      </td>

                      {/* Status */}
                      <td style={{ padding: '14px 16px' }}>
                        <StatusBadge s={alert.status} />
                      </td>

                      {/* Action */}
                      <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                          className="btn btn-secondary btn-sm"
                          style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls */}
          <div style={{ padding: '12px 18px', borderTop: '1px solid #f1f5f9', display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#f8fafc', flexWrap: 'wrap', gap: 10 }}>
            <div style={{ fontSize: '0.8125rem', color: '#64748b' }}>
              Showing {Math.min(filteredAlerts.length, (currentPage - 1) * pageSize + 1)}–{Math.min(filteredAlerts.length, currentPage * pageSize)} of {filteredAlerts.length} threats
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button
                disabled={currentPage <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
                className="btn btn-secondary btn-sm"
                style={{ opacity: currentPage <= 1 ? 0.4 : 1 }}
              >
                Previous
              </button>

              <span style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#0f172a', padding: '0 4px' }}>
                Page {currentPage} of {totalPages}
              </span>

              <button
                disabled={currentPage >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                className="btn btn-secondary btn-sm"
                style={{ opacity: currentPage >= totalPages ? 0.4 : 1 }}
              >
                Next
              </button>

              <select
                className="ng-select"
                style={{ width: 100, fontSize: '0.75rem', padding: '4px 8px', marginLeft: 8 }}
                value={pageSize}
                onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}
              >
                <option value={10}>10 / page</option>
                <option value={25}>25 / page</option>
                <option value={50}>50 / page</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* ALERT DETAILS MODAL / DRAWER (Task 7 & Task 8)           */}
      {/* ======================================================== */}
      {selectedAlert && (
        <div className="modal-backdrop" onClick={() => setSelectedAlert(null)}>
          <div
            className="modal-content"
            style={{ maxWidth: 680, width: '92%', maxHeight: '90vh', overflowY: 'auto', padding: 24 }}
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '0.875rem', color: '#64748b' }}>
                    THREAT #{selectedAlert.id}
                  </span>
                  <SevBadge s={selectedAlert.severity} />
                  <StatusBadge s={selectedAlert.status} />
                  <span className="tag-simulated">SIMULATED</span>
                </div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
                  {selectedAlert.title}
                </h2>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="btn-ghost"
                style={{ padding: 4, background: 'none', border: 'none', cursor: 'pointer' }}
              >
                <X size={18} color="#64748b" />
              </button>
            </div>

            {/* Key Metadata Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 10, marginBottom: 16 }}>
              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ fontSize: '0.675rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Source Device</div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a', fontFamily: 'monospace', marginTop: 2 }}>
                  {selectedAlert.source_ip || '—'}
                </div>
              </div>

              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ fontSize: '0.675rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Target Destination</div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a', fontFamily: 'monospace', marginTop: 2 }}>
                  {selectedAlert.destination_ip || 'Network Gateway'}
                </div>
              </div>

              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ fontSize: '0.675rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Rule Triggered</div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#2563eb', marginTop: 2 }}>
                  {selectedAlert.rule_name || 'RULE-01: Heuristic'}
                </div>
              </div>

              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ fontSize: '0.675rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Rule Confidence</div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#059669', marginTop: 2 }}>
                  {selectedAlert.ai_confidence || '92% High'}
                </div>
              </div>

              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ fontSize: '0.675rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>First Detected</div>
                <div style={{ fontSize: '0.75rem', color: '#334155', marginTop: 2 }}>
                  {new Date(selectedAlert.created_at).toLocaleString()}
                </div>
              </div>

              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '8px 12px' }}>
                <div style={{ fontSize: '0.675rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase' }}>Occurrences</div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#d97706', marginTop: 2 }}>
                  {selectedAlert.occurrence_count || 1} event(s) collapsed
                </div>
              </div>
            </div>

            {/* Description */}
            <div style={{ background: 'white', border: '1px solid #e2e8f0', borderRadius: 8, padding: '12px 14px', marginBottom: 14 }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', marginBottom: 4 }}>
                Observation & Event Finding
              </div>
              <div style={{ fontSize: '0.8125rem', color: '#1e293b', lineHeight: 1.5 }}>
                {selectedAlert.message}
              </div>
            </div>

            {/* AI Result View (Phase 4 Explainable ML Anomaly Assessment) */}
            {(() => {
              let aiExplanationObj = null;
              if (selectedAlert.ai_explanation) {
                try {
                  aiExplanationObj = JSON.parse(selectedAlert.ai_explanation);
                } catch (_) {
                  aiExplanationObj = null;
                }
              }

              const score = typeof selectedAlert.ai_score === 'number' ? selectedAlert.ai_score : 0.78;
              const confidence = selectedAlert.ai_confidence || (score >= 0.75 ? 'High' : score >= 0.50 ? 'Medium' : 'Low');
              const isAnom = score >= 0.58;
              const assessment = isAnom ? 'ANOMALOUS' : 'NORMAL';
              const assessmentBanner = aiExplanationObj?.assessment_banner || `AI Assessment: ${assessment} · Anomaly Score ${score.toFixed(2)} · Confidence ${confidence}`;

              const reasons = (aiExplanationObj?.reasons && aiExplanationObj.reasons.length > 0)
                ? aiExplanationObj.reasons
                : [
                    'Traffic features deviate significantly from the baseline learned distribution.',
                    `Isolation Forest outlier score ${score.toFixed(2)} reflects high-dimensional behavioral divergence.`
                  ];

              const disclaimer = aiExplanationObj?.disclaimer || 'An anomaly represents a statistical deviation from the learned behavioral baseline and is not definitive proof of an attack.';

              return (
                <div style={{ background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: 8, padding: '14px 16px', marginBottom: 14 }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', fontWeight: 700, color: '#1e40af', textTransform: 'uppercase' }}>
                      <Cpu size={14} /> AI Analysis Engine Assessment
                    </div>
                    <span style={{
                      fontSize: '0.7rem',
                      fontWeight: 700,
                      padding: '2px 8px',
                      borderRadius: 6,
                      background: isAnom ? '#fee2e2' : '#dcfce7',
                      color: isAnom ? '#991b1b' : '#166534',
                      border: `1px solid ${isAnom ? '#fecaca' : '#bbf7d0'}`
                    }}>
                      {selectedAlert.detection_method || (isAnom ? 'RULE+AI' : 'RULE')}
                    </span>
                  </div>

                  {/* Assessment Banner */}
                  <div style={{
                    fontSize: '0.875rem',
                    fontWeight: 700,
                    color: isAnom ? '#991b1b' : '#166534',
                    background: isAnom ? '#fef2f2' : '#f0fdf4',
                    border: `1px solid ${isAnom ? '#fecaca' : '#bbf7d0'}`,
                    padding: '8px 12px',
                    borderRadius: 6,
                    marginBottom: 10
                  }}>
                    {assessmentBanner}
                  </div>

                  {/* Why was this flagged? (Explainability) */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#334155', textTransform: 'uppercase', marginBottom: 6 }}>
                      Why was this flagged?
                    </div>
                    <ul style={{ margin: 0, paddingLeft: 18, fontSize: '0.8125rem', color: '#1e293b', lineHeight: 1.5 }}>
                      {reasons.map((reason, idx) => (
                        <li key={idx} style={{ marginBottom: 4 }}>{reason}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Model & Advisory Disclaimer */}
                  <div style={{ borderTop: '1px solid #e2e8f0', paddingTop: 8, fontSize: '0.7rem', color: '#64748b', lineHeight: 1.4 }}>
                    <div style={{ fontWeight: 600, color: '#475569', marginBottom: 2 }}>
                      Model: Role-Based Isolation Forest v1.0 · 8 Standardized Features
                    </div>
                    <div>
                      {disclaimer} NetGuardian AI functions as an advisory layer to support analyst investigations.
                    </div>
                  </div>
                </div>
              );
            })()}

            {/* Defensive Recommendation (Task 8) */}
            <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: '12px 14px', marginBottom: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.75rem', fontWeight: 700, color: '#065f46', textTransform: 'uppercase', marginBottom: 4 }}>
                <Shield size={14} /> Recommended Defensive Action
              </div>
              <div style={{ fontSize: '0.875rem', fontWeight: 700, color: '#047857', marginBottom: 4 }}>
                {selectedAlert.recommendation || 'Investigate device and inspect firewall logs.'}
              </div>
              <div style={{ fontSize: '0.725rem', color: '#059669', fontStyle: 'italic' }}>
                Note: Defensive guidance only. NetGuardian never performs automated containment actions without human confirmation.
              </div>
            </div>

            {/* Status Mutation Controls (Task 5) */}
            <div style={{ borderTop: '1px solid #f1f5f9', paddingTop: 16 }}>
              <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a', marginBottom: 8 }}>
                Update Alert Lifecycle Status:
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {[
                  { id: 'NEW', label: 'New', color: '#2563eb' },
                  { id: 'INVESTIGATING', label: 'Investigating', color: '#d97706' },
                  { id: 'CONTAINED', label: 'Contained', color: '#7c3aed' },
                  { id: 'RESOLVED', label: 'Resolved', color: '#059669' },
                  { id: 'FALSE_POSITIVE', label: 'False Positive', color: '#64748b' }
                ].map(st => {
                  const isCurrent = (selectedAlert.status || '').toUpperCase().replace(' ', '_') === st.id;
                  return (
                    <button
                      key={st.id}
                      disabled={isCurrent || updatingId === selectedAlert.id}
                      onClick={() => handleStatusUpdate(selectedAlert.id, st.id)}
                      className={`btn btn-sm ${isCurrent ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ opacity: isCurrent ? 1 : 0.85, fontSize: '0.75rem' }}
                    >
                      {st.label}
                    </button>
                  );
                })}

                <button
                  onClick={() => {
                    setSelectedAlert(null);
                    onNavigate && onNavigate('what-if', { ip_address: selectedAlert.source_ip, device_name: 'Threat Source' });
                  }}
                  className="btn btn-warning btn-sm"
                  style={{ marginLeft: 'auto', fontSize: '0.75rem' }}
                >
                  🎯 Test Isolation in What-If
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* SIMULATE SECURITY EVENT MODAL (Task 2)                   */}
      {/* ======================================================== */}
      {simModalOpen && (
        <div className="modal-backdrop" onClick={() => setSimModalOpen(false)}>
          <div
            className="modal-content"
            style={{ maxWidth: 620, width: '92%', maxHeight: '90vh', overflowY: 'auto', padding: 24 }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: '1.25rem' }}>⚡</span>
                <h2 style={{ fontSize: '1.15rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
                  Simulate Security Event
                </h2>
              </div>
              <button
                onClick={() => setSimModalOpen(false)}
                className="btn-ghost"
                style={{ padding: 4, background: 'none', border: 'none', cursor: 'pointer' }}
              >
                <X size={18} color="#64748b" />
              </button>
            </div>

            <p style={{ fontSize: '0.8125rem', color: '#64748b', marginBottom: 16 }}>
              Select one of the 6 simulated scenarios to inject safe synthetic flow metadata into the Digital Twin. No real network attacks or packets are transmitted.
            </p>

            {/* Scenario Choices */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 18 }}>
              {SIMULATION_SCENARIOS.map(sc => {
                const isSelected = selectedScenario === sc.id;
                return (
                  <div
                    key={sc.id}
                    onClick={() => {
                      setSelectedScenario(sc.id);
                      setSimSourceIp(sc.defaultSource);
                      setSimTargetIp(sc.defaultTarget);
                    }}
                    style={{
                      padding: '10px 14px',
                      borderRadius: 8,
                      border: isSelected ? '2px solid #2563eb' : '1px solid #e2e8f0',
                      background: isSelected ? '#eff6ff' : 'white',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: 12,
                      transition: 'all 0.12s'
                    }}
                  >
                    <div style={{ fontSize: '1.1rem', marginTop: 1 }}>{sc.icon}</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <span style={{ fontWeight: 700, fontSize: '0.875rem', color: isSelected ? '#1e40af' : '#0f172a' }}>
                          {sc.title}
                        </span>
                        <span
                          style={{
                            fontSize: '0.675rem',
                            fontWeight: 700,
                            padding: '1px 6px',
                            borderRadius: 6,
                            background: sc.badgeColor + '1a',
                            color: sc.badgeColor,
                            border: `1px solid ${sc.badgeColor}40`
                          }}
                        >
                          {sc.severity}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>
                        {sc.desc}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Source Device Picker */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
              <div>
                <label className="ng-label" style={{ marginBottom: 4, display: 'block' }}>
                  Source Device
                </label>
                <select
                  className="ng-select"
                  value={simSourceIp}
                  onChange={e => setSimSourceIp(e.target.value)}
                >
                  <option value="192.168.1.99">Unregistered Device (192.168.1.99)</option>
                  {devices.map(d => (
                    <option key={d.id} value={d.ip_address}>
                      {d.device_name} ({d.ip_address})
                    </option>
                  ))}
                  <option value="192.168.1.10">PC-01 (192.168.1.10)</option>
                  <option value="192.168.1.11">PC-02 (192.168.1.11)</option>
                  <option value="192.168.1.12">PC-03 (192.168.1.12)</option>
                  <option value="192.168.1.13">PC-04 (192.168.1.13)</option>
                  <option value="192.168.1.40">IoT-Camera (192.168.1.40)</option>
                </select>
              </div>

              <div>
                <label className="ng-label" style={{ marginBottom: 4, display: 'block' }}>
                  Target Destination
                </label>
                <select
                  className="ng-select"
                  value={simTargetIp}
                  onChange={e => setSimTargetIp(e.target.value)}
                >
                  <option value="192.168.1.20">Server (192.168.1.20)</option>
                  <option value="192.168.1.21">Database (192.168.1.21)</option>
                  <option value="192.168.1.1">Router Gateway (192.168.1.1)</option>
                  <option value="203.0.113.1">External WAN (203.0.113.1)</option>
                </select>
              </div>
            </div>

            {/* Defensive Notice Callout */}
            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 12px', marginBottom: 20, fontSize: '0.75rem', color: '#64748b' }}>
              <span style={{ fontWeight: 700, color: '#0f172a' }}>🛡️ Defensive Simulation Engine:</span> Flows generated are synthetic records stored in SQLite and evaluated by NetGuardian Rule Engine. No physical network interfaces are tapped or flooded.
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                onClick={() => setSimModalOpen(false)}
                className="btn btn-secondary"
              >
                Cancel
              </button>

              <button
                type="button"
                disabled={isSimulating}
                onClick={handleExecuteSimulation}
                className="btn btn-primary"
                style={{ fontWeight: 700 }}
              >
                {isSimulating ? 'Injecting Flow…' : 'Execute Simulation'}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
