import React, { useState, useEffect } from 'react';
import { FileText, Download, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

export default function ReportsPage() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  const load = async () => {
    setLoading(true);
    try { const r = await api.getReportSummary(); setReport(r); }
    catch (e) { console.error(e); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const printReport = () => window.print();

  if (loading) return <div style={{ textAlign: 'center', padding: 60, color: '#94a3b8' }}>Loading report data…</div>;

  const now = new Date();
  const period = `${new Date(now - 7 * 86400000).toLocaleDateString()} – ${now.toLocaleDateString()}`;

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 20, gap: 12, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a' }}>Security Report</h1>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 2 }}>
            NetGuardian Security Report · Reporting Period: {period}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={load} className="btn btn-ghost btn-sm"><RefreshCw size={13} /></button>
          <button onClick={printReport} className="btn btn-primary btn-sm">
            <Download size={13} /> Export / Print
          </button>
        </div>
      </div>

      {/* Disclaimer */}
      <div style={{ background: '#eff6ff', border: '1px solid #bfdbfe', borderRadius: 10, padding: '12px 16px', marginBottom: 20, fontSize: '0.8125rem', color: '#1e40af' }}>
        📋 This report contains <span className="tag-simulated">SIMULATED</span> data from the NetGuardian Simulation Mode. All devices, traffic, and events are synthetic. Production use requires Live Monitoring Mode.
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* Overview */}
        <div className="ng-card">
          <div className="ng-card-title" style={{ marginBottom: 14, fontSize: '1rem' }}>
            <FileText size={16} color="#2563eb" /> 1. Network Overview
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
            {[
              ['Total Devices', report?.devices_total || '—'],
              ['Online Devices', report?.devices_online || '—'],
              ['Total Events', report?.events_total || '—'],
              ['Active Threats', report?.threats_active || '—'],
              ['AI Anomalies', report?.anomalies_detected || '—'],
              ['Simulations Run', report?.simulations_run || '—'],
            ].map(([k, v]) => (
              <div key={k} className="ng-card-sm" style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{k}</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', marginTop: 4 }}>{v}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Security Events */}
        <div className="ng-card">
          <div className="ng-card-title" style={{ marginBottom: 14, fontSize: '1rem' }}>
            2. Security Events Summary
          </div>
          {report?.event_summary?.length > 0 ? (
            <div className="ng-table-wrap">
              <table className="ng-table">
                <thead><tr><th>Event Type</th><th>Count</th><th>Severity</th></tr></thead>
                <tbody>
                  {report.event_summary.map((e, i) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{e.type}</td>
                      <td>{e.count}</td>
                      <td><span className={`badge ${e.severity === 'HIGH' || e.severity === 'CRITICAL' ? 'badge-high' : e.severity === 'MEDIUM' ? 'badge-medium' : 'badge-low'}`}>{e.severity}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div style={{ color: '#94a3b8', fontSize: '0.875rem', textAlign: 'center', padding: '20px 0' }}>No events recorded in this period.</div>}
        </div>

        {/* Recommendations */}
        <div className="ng-card">
          <div className="ng-card-title" style={{ marginBottom: 14, fontSize: '1rem' }}>
            3. Security Recommendations
          </div>
          {report?.recommendations?.length > 0 ? (
            <ul style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {report.recommendations.map((r, i) => (
                <li key={i} style={{ display: 'flex', gap: 10, background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: '10px 14px', fontSize: '0.8125rem', color: '#065f46' }}>
                  <span style={{ fontWeight: 700 }}>✓</span> {r}
                </li>
              ))}
            </ul>
          ) : (
            <div style={{ background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 8, padding: '14px', fontSize: '0.875rem', color: '#065f46', textAlign: 'center' }}>
              ✅ No critical recommendations. Network appears healthy.
            </div>
          )}
        </div>

        {/* Conclusion */}
        <div className="ng-card" style={{ background: '#f8fafc' }}>
          <div className="ng-card-title" style={{ marginBottom: 12, fontSize: '1rem' }}>4. Conclusion</div>
          <p style={{ fontSize: '0.875rem', color: '#334155', lineHeight: 1.7 }}>
            {report?.conclusion || `NetGuardian monitored the simulated network during the reporting period. 
            AI-powered anomaly detection (Isolation Forest) and rule-based detection ran continuously. 
            The Digital Twin represented the network in real-time, and What-If simulations were available 
            for safe attack-path analysis. All data in this report is SIMULATED for educational purposes.`}
          </p>
          <div style={{ marginTop: 12, fontSize: '0.75rem', color: '#94a3b8' }}>
            Generated: {now.toLocaleString()} · NetGuardian v1.0.0 · Educational Prototype
          </div>
        </div>
      </div>
    </div>
  );
}
