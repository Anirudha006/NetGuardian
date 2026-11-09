import React, { useState, useEffect } from 'react';
import { BarChart, Bar, LineChart, Line, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { api } from '../services/api';

const COLORS = ['#2563eb', '#059669', '#d97706', '#dc2626', '#7c3aed', '#0891b2'];

function ChartCard({ title, sub, children, empty }) {
  return (
    <div className="ng-card" style={{ padding: '18px 20px' }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontWeight: 700, fontSize: '0.875rem', color: '#0f172a' }}>{title}</div>
        {sub && <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>{sub}</div>}
      </div>
      {empty
        ? <div className="empty-state" style={{ padding: '24px 0' }}><div className="empty-state-sub">No data yet. Generate traffic or security events first.</div></div>
        : children
      }
    </div>
  );
}

export default function AnalyticsPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAnalytics().then(d => { setData(d); setLoading(false); }).catch(() => setLoading(false));
    const iv = setInterval(() => api.getAnalytics().then(d => setData(d)).catch(() => {}), 10000);
    return () => clearInterval(iv);
  }, []);

  if (loading) return <div style={{ textAlign: 'center', padding: 60, color: '#94a3b8' }}>Loading analytics…</div>;

  const traffic = data?.traffic_over_time || [];
  const threats = data?.threats_over_time || [];
  const categories = data?.threat_categories || [];
  const riskDist = data?.device_risk_distribution || [];
  const protocols = data?.protocol_usage || [];
  const topDevices = data?.top_communicating_devices || [];

  return (
    <div style={{ padding: '24px 0', maxWidth: 1240, margin: '0 auto' }}>
      <div style={{ marginBottom: 20 }}>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a' }}>Analytics</h1>
        <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 2 }}>
          Real stored and simulated data only — no fake charts · <span className="tag-simulated">SIMULATED</span>
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 20 }}>
        {/* Traffic over time */}
        <ChartCard title="Traffic Over Time" sub="Packet count per time window" empty={traffic.length === 0}>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={traffic}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid #e2e8f0', borderRadius: 8, fontSize: 12 }} />
              <Line type="monotone" dataKey="packets" stroke="#2563eb" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Threats over time */}
        <ChartCard title="Threats Over Time" sub="Security events detected per period" empty={threats.length === 0}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={threats}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid #e2e8f0', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="count" fill="#dc2626" radius={[3,3,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Threat categories */}
        <ChartCard title="Threat Categories" sub="Distribution of event types" empty={categories.length === 0}>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={categories} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={false}>
                {categories.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ background: 'white', border: '1px solid #e2e8f0', borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Device Risk Distribution */}
        <ChartCard title="Device Risk Distribution" sub="Risk score buckets across all devices" empty={riskDist.length === 0}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={riskDist}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="range" tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid #e2e8f0', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="count" fill="#7c3aed" radius={[3,3,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Protocol usage */}
        <ChartCard title="Protocol Usage" sub="Share of network protocols" empty={protocols.length === 0}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={protocols} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <YAxis dataKey="protocol" type="category" tick={{ fontSize: 10, fill: '#94a3b8' }} width={50} />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid #e2e8f0', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="count" fill="#059669" radius={[0,3,3,0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        {/* Top devices */}
        <ChartCard title="Top Communicating Devices" sub="Devices with most traffic flows" empty={topDevices.length === 0}>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={topDevices.slice(0, 8)} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis type="number" tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: '#94a3b8' }} width={80} />
              <Tooltip contentStyle={{ background: 'white', border: '1px solid #e2e8f0', borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="flows" fill="#d97706" radius={[0,3,3,0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>
    </div>
  );
}
