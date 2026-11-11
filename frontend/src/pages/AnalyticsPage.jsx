import React, { useState, useEffect } from 'react';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts';
import { RefreshCw, Filter, Clock, AlertTriangle, ShieldCheck, Activity } from 'lucide-react';
import { api } from '../services/api';

const PIE_COLORS = ['#dc2626', '#f97316', '#eab308', '#2563eb', '#7c3aed', '#059669'];

const RISK_BAND_COLORS = {
  'Low (0-29)': '#059669',
  'Medium (30-69)': '#d97706',
  'High (70-89)': '#ea580c',
  'Critical (90-100)': '#dc2626'
};

function ChartCard({ title, sub, children, tableContent, empty, emptyMessage, chartId }) {
  const [showTable, setShowTable] = useState(false);

  return (
    <div
      className="ng-card"
      style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column' }}
      id={chartId}
      role="region"
      aria-label={title}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: '0.875rem', color: '#0f172a' }}>{title}</div>
          {sub && <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>{sub}</div>}
        </div>
        {!empty && (
          <button
            onClick={() => setShowTable(prev => !prev)}
            className="btn btn-ghost btn-sm"
            style={{ fontSize: '0.75rem', padding: '3px 8px', height: 26 }}
            aria-label={`Toggle table view for ${title}`}
            aria-pressed={showTable}
          >
            {showTable ? '📊 Chart View' : '📋 Show as table'}
          </button>
        )}
      </div>
      <div style={{ flex: 1, minHeight: 210 }} tabIndex={0} aria-label={`${title} display area`}>
        {empty ? (
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: 190,
            background: '#f8fafc',
            border: '1px dashed #cbd5e1',
            borderRadius: 8,
            padding: 16,
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '0.8125rem', color: '#64748b', maxWidth: 300, lineHeight: 1.5 }}>
              {emptyMessage || "No data yet. Click Simulate Security Event to try it."}
            </div>
          </div>
        ) : showTable ? (
          <div className="ng-table-wrap" style={{ maxHeight: 210, overflowY: 'auto' }}>
            {tableContent}
          </div>
        ) : children}
      </div>
    </div>
  );
}

export default function AnalyticsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('all'); // '15m', '1h', 'all'
  const [dataSource, setDataSource] = useState('ALL'); // 'ALL', 'SIMULATED', 'OBSERVED'
  const [showAnomaliesTable, setShowAnomaliesTable] = useState(false);

  const fetchAnalytics = async () => {
    try {
      setError(null);
      const res = await api.getAnalytics({
        time_range: timeRange,
        data_source: dataSource
      });
      setData(res);
    } catch (err) {
      console.error("Failed to load analytics:", err);
      setError("Unable to load analytics telemetry. Please verify the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
    const interval = setInterval(() => {
      // Pause polling if document is hidden to avoid flicker/resource consumption
      if (typeof document !== 'undefined' && !document.hidden) {
        api.getAnalytics({ time_range: timeRange, data_source: dataSource })
          .then(res => setData(res))
          .catch(() => {});
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [timeRange, dataSource]);

  if (loading && !data) {
    return (
      <div style={{ padding: '60px 0', textAlign: 'center', color: '#64748b' }}>
        <RefreshCw size={24} className="spin" style={{ marginBottom: 12, color: '#2563eb' }} />
        <div>Loading server-aggregated analytics...</div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div style={{ padding: '40px 20px', maxWidth: 600, margin: '40px auto', textAlign: 'center' }} className="ng-card">
        <AlertTriangle size={32} color="#dc2626" style={{ marginBottom: 12 }} />
        <h2 style={{ fontSize: '1.125rem', fontWeight: 700, color: '#0f172a', marginBottom: 8 }}>Analytics Unavailable</h2>
        <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: 20 }}>{error}</p>
        <button onClick={fetchAnalytics} className="btn btn-primary btn-sm">
          <RefreshCw size={14} style={{ marginRight: 6 }} /> Retry
        </button>
      </div>
    );
  }

  const traffic = data?.traffic_over_time || [];
  const threats = data?.threats_over_time || [];
  const categories = data?.threat_categories || [];
  const riskDist = data?.device_risk_distribution || [];
  const protocols = data?.protocol_usage || [];
  const topDevices = data?.top_communicating_devices || [];
  const anomalies = data?.anomalies_timeline || [];
  const summary = data?.summary || {};

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>
      {/* Header and Control Bar */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: 20,
        gap: 16,
        flexWrap: 'wrap'
      }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>Analytics & Telemetry</h1>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 4 }}>
            Server-aggregated SQL metrics · Real stored data only · Active Source:{' '}
            <span className={dataSource === 'OBSERVED' ? 'badge badge-low' : dataSource === 'SIMULATED' ? 'tag-simulated' : 'badge badge-medium'}>
              {dataSource === 'ALL' ? 'ALL TELEMETRY' : dataSource}
            </span>
          </p>
        </div>

        {/* Filter Controls */}
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
              Last 15m
            </button>
            <button
              onClick={() => setTimeRange('1h')}
              className={`btn btn-sm ${timeRange === '1h' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              Last 1h
            </button>
            <button
              onClick={() => setTimeRange('all')}
              className={`btn btn-sm ${timeRange === 'all' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '0.75rem', padding: '4px 10px', height: 28 }}
            >
              All Data
            </button>
          </div>

          {/* Source Filter Selector */}
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
              All Sources
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

          <button onClick={fetchAnalytics} className="btn btn-ghost btn-sm" title="Refresh metrics">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* Summary KPI Strip */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: 14,
        marginBottom: 20
      }}>
        {[
          { label: 'Monitored Packets', val: summary.total_packets?.toLocaleString() || '0', icon: Activity, color: '#2563eb' },
          { label: 'Total Volume', val: `${((summary.total_bytes || 0) / 1024).toFixed(1)} KB`, icon: Activity, color: '#0891b2' },
          { label: 'Security Threats', val: summary.total_threats || '0', icon: AlertTriangle, color: '#dc2626' },
          { label: 'AI Anomalies Flagged', val: summary.total_anomalies || '0', icon: AlertTriangle, color: '#ea580c' },
          { label: 'Active Devices', val: summary.total_devices || '0', icon: ShieldCheck, color: '#059669' }
        ].map((kpi, idx) => {
          const Icon = kpi.icon;
          return (
            <div key={idx} className="ng-card" style={{ padding: '14px 16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#64748b' }}>{kpi.label}</span>
                <Icon size={16} color={kpi.color} />
              </div>
              <div style={{ fontSize: '1.375rem', fontWeight: 800, color: '#0f172a', marginTop: 6 }}>
                {kpi.val}
              </div>
            </div>
          );
        })}
      </div>

      {/* Grid of Analytical Charts */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
        gap: 20,
        marginBottom: 20
      }}>
        {/* 1. Traffic Over Time */}
        <ChartCard
          title="Traffic Over Time"
          sub="Packet count per time interval (Server binned)"
          chartId="chart-traffic-over-time"
          empty={traffic.length === 0}
          emptyMessage="No traffic records in this period. Generate traffic to view telemetry."
          tableContent={
            <table className="ng-table" style={{ fontSize: '0.8125rem' }} aria-label="Traffic over time data table">
              <thead>
                <tr>
                  <th scope="col">Time Interval</th>
                  <th scope="col">Packets</th>
                  <th scope="col">Volume (Bytes)</th>
                  <th scope="col">Anomalous Flows</th>
                </tr>
              </thead>
              <tbody>
                {traffic.map((r, idx) => (
                  <tr key={idx}>
                    <td>{r.time}</td>
                    <td>{r.packets.toLocaleString()}</td>
                    <td>{r.bytes.toLocaleString()} bytes</td>
                    <td>{r.anomalies}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          }
        >
          <ResponsiveContainer width="100%" height={210}>
            <LineChart data={traffic} margin={{ top: 10, right: 15, left: -10, bottom: 0 }} aria-label="Traffic over time line chart">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#64748b' }} stroke="#cbd5e1" />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} stroke="#cbd5e1" />
              <Tooltip
                contentStyle={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: 6, fontSize: 12, boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}
                formatter={(val, name) => [val.toLocaleString(), name === 'packets' ? 'Packets' : name === 'bytes' ? 'Bytes' : 'Anomalies']}
              />
              <Line type="monotone" dataKey="packets" name="packets" stroke="#2563eb" strokeWidth={2.5} dot={{ r: 2, fill: '#2563eb' }} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 2. Threats Over Time */}
        <ChartCard
          title="Threats Over Time"
          sub="Security events detected by timestamp"
          chartId="chart-threats-over-time"
          empty={threats.length === 0}
          emptyMessage="No threats yet. Click Simulate Security Event to try it."
          tableContent={
            <table className="ng-table" style={{ fontSize: '0.8125rem' }} aria-label="Threats over time data table">
              <thead>
                <tr>
                  <th scope="col">Timestamp</th>
                  <th scope="col">Detected Threat Count</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t, idx) => (
                  <tr key={idx}>
                    <td>{t.time}</td>
                    <td>{t.count} event(s)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          }
        >
          <ResponsiveContainer width="100%" height={210}>
            <BarChart data={threats} margin={{ top: 10, right: 15, left: -10, bottom: 0 }} aria-label="Threats over time bar chart">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#64748b' }} stroke="#cbd5e1" />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} stroke="#cbd5e1" allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: 6, fontSize: 12 }}
                formatter={(val) => [`${val} event(s)`, 'Threat Count']}
              />
              <Bar dataKey="count" fill="#dc2626" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 3. Threat Categories Distribution */}
        <ChartCard
          title="Threat Categories"
          sub="Distribution across event types"
          chartId="chart-threat-categories"
          empty={categories.length === 0}
          emptyMessage="No threat categories recorded in this period."
          tableContent={
            <table className="ng-table" style={{ fontSize: '0.8125rem' }} aria-label="Threat categories data table">
              <thead>
                <tr>
                  <th scope="col">Threat Category</th>
                  <th scope="col">Event Count</th>
                </tr>
              </thead>
              <tbody>
                {categories.map((c, idx) => (
                  <tr key={idx}>
                    <td>{c.name}</td>
                    <td>{c.value} event(s)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          }
        >
          <ResponsiveContainer width="100%" height={210}>
            <PieChart aria-label="Threat categories pie chart">
              <Pie
                data={categories}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={75}
                innerRadius={38}
                paddingAngle={2}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                labelLine={false}
              >
                {categories.map((_, i) => (
                  <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: 6, fontSize: 12 }}
                formatter={(val, name) => [`${val} events`, name]}
              />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 4. Device Risk Distribution */}
        <ChartCard
          title="Device Risk Distribution"
          sub="Risk score distribution across monitored devices"
          chartId="chart-device-risk"
          empty={riskDist.every(r => r.count === 0)}
          emptyMessage="No devices currently registered."
          tableContent={
            <table className="ng-table" style={{ fontSize: '0.8125rem' }} aria-label="Device risk distribution data table">
              <thead>
                <tr>
                  <th scope="col">Risk Band</th>
                  <th scope="col">Device Count</th>
                </tr>
              </thead>
              <tbody>
                {riskDist.map((r, idx) => (
                  <tr key={idx}>
                    <td>{r.range}</td>
                    <td>{r.count} device(s)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          }
        >
          <ResponsiveContainer width="100%" height={210}>
            <BarChart data={riskDist} margin={{ top: 10, right: 15, left: -10, bottom: 0 }} aria-label="Device risk distribution bar chart">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="range" tick={{ fontSize: 10, fill: '#64748b' }} stroke="#cbd5e1" />
              <YAxis tick={{ fontSize: 11, fill: '#64748b' }} stroke="#cbd5e1" allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: 6, fontSize: 12 }}
                formatter={(val) => [`${val} device(s)`, 'Count']}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {riskDist.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={RISK_BAND_COLORS[entry.range] || '#2563eb'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 5. Protocol Usage */}
        <ChartCard
          title="Protocol Usage"
          sub="Share of network traffic by protocol"
          chartId="chart-protocol-usage"
          empty={protocols.length === 0}
          emptyMessage="No protocol activity in this period."
          tableContent={
            <table className="ng-table" style={{ fontSize: '0.8125rem' }} aria-label="Protocol usage data table">
              <thead>
                <tr>
                  <th scope="col">Protocol</th>
                  <th scope="col">Flow Count</th>
                  <th scope="col">Volume (Bytes)</th>
                </tr>
              </thead>
              <tbody>
                {protocols.map((p, idx) => (
                  <tr key={idx}>
                    <td>{p.protocol}</td>
                    <td>{p.count}</td>
                    <td>{p.bytes.toLocaleString()} bytes</td>
                  </tr>
                ))}
              </tbody>
            </table>
          }
        >
          <ResponsiveContainer width="100%" height={210}>
            <BarChart data={protocols} layout="vertical" margin={{ top: 10, right: 15, left: 10, bottom: 0 }} aria-label="Protocol usage horizontal bar chart">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} stroke="#cbd5e1" />
              <YAxis dataKey="protocol" type="category" tick={{ fontSize: 11, fill: '#0f172a', fontWeight: 600 }} stroke="#cbd5e1" width={60} />
              <Tooltip
                contentStyle={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: 6, fontSize: 12 }}
                formatter={(val, name) => [val.toLocaleString(), name === 'bytes' ? 'Bytes' : 'Flows']}
              />
              <Bar dataKey="bytes" fill="#059669" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* 6. Top Communicating Devices */}
        <ChartCard
          title="Top Communicating Devices"
          sub="Devices with largest traffic volume (bytes)"
          chartId="chart-top-devices"
          empty={topDevices.length === 0}
          emptyMessage="No communicating devices recorded."
          tableContent={
            <table className="ng-table" style={{ fontSize: '0.8125rem' }} aria-label="Top communicating devices data table">
              <thead>
                <tr>
                  <th scope="col">Device Name</th>
                  <th scope="col">IP Address</th>
                  <th scope="col">Volume (Bytes)</th>
                  <th scope="col">Packets</th>
                </tr>
              </thead>
              <tbody>
                {topDevices.map((d, idx) => (
                  <tr key={idx}>
                    <td>{d.name}</td>
                    <td>{d.ip}</td>
                    <td>{d.bytes.toLocaleString()} bytes</td>
                    <td>{d.packets.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          }
        >
          <ResponsiveContainer width="100%" height={210}>
            <BarChart data={topDevices.slice(0, 6)} layout="vertical" margin={{ top: 10, right: 15, left: 15, bottom: 0 }} aria-label="Top communicating devices bar chart">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#64748b' }} stroke="#cbd5e1" />
              <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: '#0f172a' }} stroke="#cbd5e1" width={80} />
              <Tooltip
                contentStyle={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: 6, fontSize: 12 }}
                formatter={(val, name, item) => [`${(val / 1024).toFixed(1)} KB (${item.payload.packets} pkts)`, item.payload.ip]}
              />
              <Bar dataKey="bytes" fill="#2563eb" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* 7. Anomalies Timeline */}
      <div className="ng-card" style={{ padding: '18px 20px' }} id="chart-anomalies-timeline" role="region" aria-label="AI Anomalies Timeline">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.875rem', color: '#0f172a' }}>AI Anomalies Timeline</div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>
              Recent Machine Learning (Isolation Forest) anomalies with Explainable AI attribution
            </div>
          </div>
          {anomalies.length > 0 && (
            <button
              onClick={() => setShowAnomaliesTable(prev => !prev)}
              className="btn btn-ghost btn-sm"
              style={{ fontSize: '0.75rem', padding: '3px 8px', height: 26 }}
              aria-label="Toggle table view for AI Anomalies Timeline"
              aria-pressed={showAnomaliesTable}
            >
              {showAnomaliesTable ? '📊 Timeline View' : '📋 Show as table'}
            </button>
          )}
        </div>

        {anomalies.length === 0 ? (
          <div style={{
            background: '#f8fafc',
            border: '1px dashed #cbd5e1',
            borderRadius: 8,
            padding: 24,
            textAlign: 'center',
            color: '#64748b',
            fontSize: '0.8125rem'
          }}>
            No AI anomalies detected in this reporting period.
          </div>
        ) : showAnomaliesTable ? (
          <div className="ng-table-wrap">
            <table className="ng-table" style={{ fontSize: '0.8125rem' }} aria-label="AI Anomalies data table">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Device Name</th>
                  <th scope="col">Source IP</th>
                  <th scope="col">Anomaly Score</th>
                  <th scope="col">Confidence</th>
                  <th scope="col">Explainable Contributing Factors</th>
                </tr>
              </thead>
              <tbody>
                {anomalies.map((a) => (
                  <tr key={a.id}>
                    <td>{a.time}</td>
                    <td style={{ fontWeight: 600 }}>{a.device}</td>
                    <td style={{ fontFamily: 'monospace' }}>{a.ip}</td>
                    <td style={{ fontWeight: 700, color: '#ea580c' }}>{a.score}</td>
                    <td><span className="badge badge-low">{a.confidence}</span></td>
                    <td>{a.reasons}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {anomalies.map((a) => (
              <div
                key={a.id}
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  justifyContent: 'space-between',
                  background: '#f8fafc',
                  border: '1px solid #e2e8f0',
                  borderRadius: 8,
                  padding: '12px 14px',
                  gap: 12,
                  flexWrap: 'wrap'
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontWeight: 700, fontSize: '0.875rem', color: '#0f172a' }}>
                      {a.device}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: '#64748b', fontFamily: 'monospace' }}>
                      ({a.ip})
                    </span>
                    <span className="badge badge-high" style={{ fontSize: '0.7rem' }}>
                      Anomaly Score: {a.score}
                    </span>
                    <span className="badge badge-low" style={{ fontSize: '0.7rem' }}>
                      {a.confidence} Confidence
                    </span>
                  </div>
                  <div style={{ fontSize: '0.8125rem', color: '#334155', lineHeight: 1.4 }}>
                    {a.reasons}
                  </div>
                </div>
                <div style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 600 }}>
                  {a.time}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
