import React, { useState, useEffect } from 'react';
import {
  FileText, Download, Printer, RefreshCw, AlertTriangle, ShieldCheck,
  Activity, Server, Database, CheckCircle2, Info
} from 'lucide-react';
import { api } from '../services/api';

export default function ReportsPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('all'); // '15m', '1h', 'all'
  const [dataSource, setDataSource] = useState('ALL'); // 'ALL', 'SIMULATED', 'OBSERVED'
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const fetchReport = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.getReportSummary({
        time_range: timeRange,
        data_source: dataSource
      });
      setReport(res);
    } catch (err) {
      console.error("Failed to load report summary:", err);
      setError("Unable to generate security report. Please verify the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, [timeRange, dataSource]);

  const handleDownloadPdf = async () => {
    try {
      setDownloadingPdf(true);
      const url = api.getReportPdfUrl({ time_range: timeRange, data_source: dataSource });
      const res = await fetch(url, { credentials: 'include' });
      if (!res.ok) throw new Error("PDF download failed");
      const blob = await res.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = `NetGuardian_Security_Report_${timeRange}_${dataSource.toLowerCase()}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error("PDF export error:", err);
      alert("Failed to export PDF report. Please check server logs.");
    } finally {
      setDownloadingPdf(false);
    }
  };

  const handlePrintView = () => {
    const url = api.getReportHtmlUrl({ time_range: timeRange, data_source: dataSource });
    window.open(url, '_blank');
  };

  if (loading && !report) {
    return (
      <div style={{ padding: '60px 0', textAlign: 'center', color: '#64748b' }}>
        <RefreshCw size={24} className="spin" style={{ marginBottom: 12, color: '#2563eb' }} />
        <div>Compiling NetGuardian Security Report...</div>
      </div>
    );
  }

  if (error && !report) {
    return (
      <div style={{ padding: '40px 20px', maxWidth: 600, margin: '40px auto', textAlign: 'center' }} className="ng-card">
        <AlertTriangle size={32} color="#dc2626" style={{ marginBottom: 12 }} />
        <h2 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#0f172a', marginBottom: 8 }}>Report Generation Failed</h2>
        <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: 20 }}>{error}</p>
        <button onClick={fetchReport} className="btn btn-primary btn-sm">
          <RefreshCw size={14} style={{ marginRight: 6 }} /> Retry
        </button>
      </div>
    );
  }

  const ov = report?.network_overview || {};
  const nh = report?.network_health || {};
  const hb = nh?.breakdown || {};
  const devices = report?.devices || [];
  const events = report?.security_events || [];
  const anomalies = report?.ai_anomalies || [];
  const highRisk = report?.high_risk_devices || [];
  const critical = report?.critical_assets || [];
  const attackPaths = report?.simulated_attack_paths || [];
  const traffic = report?.traffic_summary || {};

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>
      {/* Top Header & Action Controls */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: 20,
        gap: 16,
        flexWrap: 'wrap'
      }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
            NetGuardian Security Report
          </h1>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 4 }}>
            Reporting Period: <b>{report?.reporting_period}</b> · Mode: <b>{report?.system_mode}</b> · Source:{' '}
            <span className={dataSource === 'OBSERVED' ? 'badge badge-low' : dataSource === 'SIMULATED' ? 'tag-simulated' : 'badge badge-medium'}>
              {dataSource}
            </span>
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Time Range Selector */}
          <div style={{
            display: 'flex',
            background: '#f1f5f9',
            padding: 3,
            borderRadius: 8,
            border: '1px solid #e2e8f0'
          }}>
            <button
              onClick={() => setTimeRange('15m')}
              className={`btn btn-sm ${timeRange === '15m' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              15m
            </button>
            <button
              onClick={() => setTimeRange('1h')}
              className={`btn btn-sm ${timeRange === '1h' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              1h
            </button>
            <button
              onClick={() => setTimeRange('all')}
              className={`btn btn-sm ${timeRange === 'all' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              All Data
            </button>
          </div>

          {/* Source Filter */}
          <div style={{
            display: 'flex',
            background: '#f1f5f9',
            padding: 3,
            borderRadius: 8,
            border: '1px solid #e2e8f0'
          }}>
            <button
              onClick={() => setDataSource('ALL')}
              className={`btn btn-sm ${dataSource === 'ALL' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              All
            </button>
            <button
              onClick={() => setDataSource('SIMULATED')}
              className={`btn btn-sm ${dataSource === 'SIMULATED' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              Simulated
            </button>
            <button
              onClick={() => setDataSource('OBSERVED')}
              className={`btn btn-sm ${dataSource === 'OBSERVED' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              Observed
            </button>
          </div>

          <button onClick={handlePrintView} className="btn btn-outline btn-sm">
            <Printer size={13} style={{ marginRight: 6 }} /> Print-Friendly
          </button>

          <button
            onClick={handleDownloadPdf}
            disabled={downloadingPdf}
            className="btn btn-primary btn-sm"
          >
            <Download size={13} style={{ marginRight: 6 }} />
            {downloadingPdf ? 'Exporting PDF...' : 'Export PDF'}
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Section 1: Reporting Period */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <FileText size={18} color="#2563eb" />
            <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
              1. Reporting Period
            </h2>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 12 }}>
            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 14px' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Time Window</div>
              <div style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#0f172a', marginTop: 4 }}>{report?.reporting_period}</div>
            </div>
            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 14px' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Generated Timestamp</div>
              <div style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#0f172a', marginTop: 4 }}>{report?.generated_at}</div>
            </div>
            <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 14px' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase' }}>Operational Mode</div>
              <div style={{ fontSize: '0.9375rem', fontWeight: 700, color: '#2563eb', marginTop: 4 }}>MODE: {report?.system_mode}</div>
            </div>
          </div>
          {/* Prominent Simulated Data Notice */}
          <div style={{
            background: '#eff6ff',
            border: '1px solid #bfdbfe',
            borderRadius: 8,
            padding: '12px 16px',
            fontSize: '0.8125rem',
            color: '#1e40af',
            display: 'flex',
            alignItems: 'center',
            gap: 10
          }}>
            <Info size={18} color="#2563eb" style={{ flexShrink: 0 }} />
            <div>
              <b>SIMULATED DATA NOTICE:</b> {report?.simulated_data_notice}
            </div>
          </div>
        </div>

        {/* Section 2: Network Overview */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
            <Activity size={18} color="#2563eb" />
            <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
              2. Network Overview
            </h2>
          </div>

          {/* KPI Strip */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
            gap: 12,
            marginBottom: 20
          }}>
            {[
              ['Network Health', `${nh.score}% (${nh.status})`, nh.score >= 80 ? '#065f46' : nh.score >= 50 ? '#78350f' : '#991b1b'],
              ['Devices Monitored', ov.total_devices ?? '0', '#0f172a'],
              ['Online Devices', ov.online_devices ?? '0', '#1d4ed8'],
              ['Active Threats', ov.active_threats ?? '0', ov.active_threats > 0 ? '#991b1b' : '#065f46'],
              ['AI Anomalies', ov.ai_anomalies ?? '0', ov.ai_anomalies > 0 ? '#9a3412' : '#065f46'],
              ['Isolated Devices', ov.isolated_devices ?? '0', ov.isolated_devices > 0 ? '#6d28d9' : '#475569']
            ].map(([k, v, color]) => (
              <div key={k} style={{
                background: '#f8fafc',
                border: '1px solid #e2e8f0',
                borderRadius: 8,
                padding: '12px 14px',
                textAlign: 'center'
              }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#475569', textTransform: 'uppercase' }}>
                  {k}
                </div>
                <div style={{ fontSize: '1.25rem', fontWeight: 800, color: color, marginTop: 4 }}>
                  {v}
                </div>
              </div>
            ))}
          </div>

          {/* Health Breakdown Table */}
          <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: 14 }}>
            <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a', marginBottom: 10 }}>
              Network Health Breakdown Formula
            </div>
            <div className="ng-table-wrap">
              <table className="ng-table" style={{ fontSize: '0.8125rem' }}>
                <thead>
                  <tr>
                    <th>Component</th>
                    <th>Score / Impact</th>
                    <th>Breakdown Reason</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>Baseline Clean Standard</td>
                    <td style={{ fontWeight: 700, color: '#065f46' }}>100.0 pts</td>
                    <td>Clean operating baseline for all known endpoints.</td>
                  </tr>
                  <tr>
                    <td>Active Threat Penalty</td>
                    <td style={{ fontWeight: 700, color: '#991b1b' }}>-{hb.threat_penalty || 0} pts</td>
                    <td>Deduction for unresolved security alerts and rule hits.</td>
                  </tr>
                  <tr>
                    <td>AI Anomaly Penalty</td>
                    <td style={{ fontWeight: 700, color: '#9a3412' }}>-{hb.anomaly_penalty || 0} pts</td>
                    <td>Deduction for active Isolation Forest behavioral outliers.</td>
                  </tr>
                  <tr>
                    <td>Unregistered Device Penalty</td>
                    <td style={{ fontWeight: 700, color: '#78350f' }}>-{hb.unregistered_device_penalty || 0} pts</td>
                    <td>Deduction for unauthorized / rogue hosts connected to subnet.</td>
                  </tr>
                  <tr>
                    <td>Containment Credit</td>
                    <td style={{ fontWeight: 700, color: '#1d4ed8' }}>+{hb.containment_credit || 0} pts</td>
                    <td>Credit awarded for isolated endpoints that successfully mitigate lateral attack reach.</td>
                  </tr>
                  <tr style={{ background: '#f1f5f9', fontWeight: 800 }}>
                    <td>Effective Network Health</td>
                    <td style={{ color: nh.score >= 80 ? '#065f46' : nh.score >= 50 ? '#78350f' : '#991b1b' }}>
                      {nh.score}% ({nh.status})
                    </td>
                    <td>{hb.formula}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Section 3: Devices */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
            3. Devices
          </h2>
          {devices.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>IP Address</th>
                    <th>Type</th>
                    <th>Criticality</th>
                    <th>Risk Score</th>
                    <th>Status</th>
                    <th>Trust Level</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{d.name}</td>
                      <td style={{ fontFamily: 'monospace' }}>{d.ip}</td>
                      <td>{d.type}</td>
                      <td>
                        <span className={`badge ${d.criticality === 'CRITICAL' ? 'badge-high' : d.criticality === 'HIGH' ? 'badge-medium' : 'badge-low'}`}>
                          {d.criticality}
                        </span>
                      </td>
                      <td style={{ fontWeight: 700 }}>{d.risk_score.toFixed(1)}/100</td>
                      <td>
                        <span className={`badge ${d.is_isolated ? 'badge-high' : d.status === 'ONLINE' ? 'badge-low' : 'badge-medium'}`}>
                          {d.is_isolated ? 'ISOLATED' : d.status}
                        </span>
                      </td>
                      <td>{d.trust_level}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: '#64748b', fontSize: '0.875rem', textAlign: 'center', padding: '20px 0' }}>
              No devices currently enrolled in network inventory.
            </div>
          )}
        </div>

        {/* Section 4: Traffic Summary */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
            4. Traffic Summary
          </h2>
          <div style={{ display: 'flex', gap: 20, marginBottom: 14, flexWrap: 'wrap' }}>
            <div>Total Packets Monitored: <b>{traffic.total_packets?.toLocaleString() || '0'}</b></div>
            <div>Total Volume: <b>{((traffic.total_bytes || 0) / 1024).toFixed(1)} KB</b></div>
            <div>Anomalous Flows Flagged: <b>{traffic.anomalous_flows || 0}</b></div>
          </div>
          {traffic.protocols?.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table" style={{ maxWidth: 600 }}>
                <thead>
                  <tr><th>Protocol</th><th>Flow Count</th><th>Volume (Bytes)</th></tr>
                </thead>
                <tbody>
                  {traffic.protocols.map((p, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{p.protocol}</td>
                      <td>{p.count}</td>
                      <td>{p.bytes.toLocaleString()} bytes</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: '#64748b', fontSize: '0.875rem' }}>No protocol telemetry recorded in this period.</div>
          )}
        </div>

        {/* Section 5: Security Events */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
            5. Security Events
          </h2>
          {events.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table">
                <thead>
                  <tr>
                    <th>Alert Title</th>
                    <th>Severity</th>
                    <th>Source IP</th>
                    <th>Detection Method</th>
                    <th>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{e.title}</td>
                      <td>
                        <span className={`badge ${e.severity === 'CRITICAL' || e.severity === 'HIGH' ? 'badge-high' : e.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>
                          {e.severity}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'monospace' }}>{e.source_ip}</td>
                      <td>{e.detection_method}</td>
                      <td style={{ fontSize: '0.8125rem' }}>{e.recommendation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: '#64748b', fontSize: '0.875rem', textAlign: 'center', padding: '20px 0' }}>
              No events in reporting period.
            </div>
          )}
        </div>

        {/* Section 6: AI Anomalies */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
            6. AI Anomalies
          </h2>
          {anomalies.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table">
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Source IP</th>
                    <th>Anomaly Score</th>
                    <th>Confidence</th>
                    <th>Explainable AI Contributing Factors</th>
                  </tr>
                </thead>
                <tbody>
                  {anomalies.map((a, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{a.device_name}</td>
                      <td style={{ fontFamily: 'monospace' }}>{a.source_ip}</td>
                      <td style={{ fontWeight: 700, color: '#ea580c' }}>{a.score}</td>
                      <td><span className="badge badge-low">{a.confidence}</span></td>
                      <td style={{ fontSize: '0.8125rem' }}>{a.explanation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: '#64748b', fontSize: '0.875rem', textAlign: 'center', padding: '20px 0' }}>
              No AI anomalies detected in this reporting period.
            </div>
          )}
        </div>

        {/* Section 7: High-Risk Devices */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
            7. High-Risk Devices
          </h2>
          {highRisk.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table">
                <thead><tr><th>Device</th><th>IP Address</th><th>Risk Score</th><th>Criticality</th><th>Status</th></tr></thead>
                <tbody>
                  {highRisk.map((hr, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{hr.name}</td>
                      <td style={{ fontFamily: 'monospace' }}>{hr.ip}</td>
                      <td style={{ fontWeight: 700, color: '#dc2626' }}>{hr.risk_score.toFixed(1)}/100</td>
                      <td>{hr.criticality}</td>
                      <td>
                        <span className={`badge ${hr.is_isolated ? 'badge-high' : 'badge-medium'}`}>
                          {hr.is_isolated ? 'ISOLATED' : hr.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: '#065f46', fontSize: '0.875rem', fontWeight: 600 }}>
              ✅ No high-risk endpoints identified.
            </div>
          )}
        </div>

        {/* Section 8: Critical Assets */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
            8. Critical Assets
          </h2>
          {critical.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table">
                <thead><tr><th>Asset Name</th><th>IP Address</th><th>Role</th><th>Criticality</th><th>Risk Score</th></tr></thead>
                <tbody>
                  {critical.map((c, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{c.name}</td>
                      <td style={{ fontFamily: 'monospace' }}>{c.ip}</td>
                      <td>{c.type}</td>
                      <td><span className="badge badge-high">{c.criticality}</span></td>
                      <td>{c.risk_score.toFixed(1)}/100</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: '#64748b', fontSize: '0.875rem' }}>
              No critical infrastructure assets recorded.
            </div>
          )}
        </div>

        {/* Section 9: Simulated Attack Paths */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
              9. Simulated Attack Paths
            </h2>
            <span className="tag-simulated">HYPOTHETICAL SIMULATION</span>
          </div>
          {attackPaths.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table">
                <thead>
                  <tr>
                    <th>Simulation Type</th>
                    <th>Target Device</th>
                    <th>Path Risk Score</th>
                    <th>Critical Assets Reached</th>
                    <th>Traversal Result</th>
                  </tr>
                </thead>
                <tbody>
                  {attackPaths.map((sp, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{sp.simulation_type} [HYPOTHETICAL]</td>
                      <td>{sp.target_device}</td>
                      <td style={{ fontWeight: 700 }}>{sp.path_risk_score.toFixed(1)}</td>
                      <td>{sp.critical_assets_reached}</td>
                      <td style={{ fontSize: '0.8125rem' }}>{sp.result}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div style={{ color: '#64748b', fontSize: '0.875rem', textAlign: 'center', padding: '20px 0' }}>
              No hypothetical attack paths simulated in this reporting period.
            </div>
          )}
        </div>

        {/* Section 10: Recommendations */}
        <div className="ng-card" style={{ padding: '20px 24px' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 14px 0' }}>
            10. Recommendations
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {report?.recommendations?.map((r, i) => (
              <div key={i} style={{
                display: 'flex',
                gap: 10,
                alignItems: 'flex-start',
                background: '#f0fdf4',
                border: '1px solid #bbf7d0',
                borderRadius: 8,
                padding: '10px 14px',
                fontSize: '0.8125rem',
                color: '#065f46'
              }}>
                <CheckCircle2 size={16} color="#059669" style={{ flexShrink: 0, marginTop: 1 }} />
                <div>{r}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Section 11: Conclusion */}
        <div className="ng-card" style={{ padding: '20px 24px', background: '#f8fafc' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: '0 0 10px 0' }}>
            11. Conclusion
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#334155', lineHeight: 1.6, margin: '0 0 14px 0' }}>
            {report?.conclusion}
          </p>
          <div style={{
            background: '#fff7ed',
            border: '1px solid #fed7aa',
            borderRadius: 8,
            padding: '12px 16px',
            fontSize: '0.8125rem',
            color: '#9a3412',
            lineHeight: 1.5
          }}>
            <b>LIMITATIONS & DISCLAIMER:</b> {report?.limitations_paragraph}
          </div>
        </div>
      </div>
    </div>
  );
}
