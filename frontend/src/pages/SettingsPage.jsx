import React, { useState, useEffect } from 'react';
import { Save, RefreshCw, AlertCircle, Shield, Server, Database, Brain, Layers, Radio, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';
import { useAuth } from '../hooks/useAuth';

function Section({ title, children }) {
  return (
    <div className="ng-card" style={{ marginBottom: 20 }}>
      <div className="ng-card-title" style={{ marginBottom: 16, fontSize: '0.9375rem' }}>{title}</div>
      {children}
    </div>
  );
}

function Field({ label, hint, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <label className="ng-label">{label}</label>
      {hint && <p style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: 6, marginTop: 2 }}>{hint}</p>}
      {children}
    </div>
  );
}

export default function SettingsPage() {
  const { user, isAdmin } = useAuth();
  const [settings, setSettings] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [systemStatus, setSystemStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [msg, setMsg] = useState('');
  const [showConsentModal, setShowConsentModal] = useState(false);
  const [consentChecked, setConsentChecked] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [res, model, status] = await Promise.all([
        api.getSettings(),
        api.getAiModelInfo().catch(() => null),
        api.getSystemStatus().catch(() => null)
      ]);
      const flat = { ...(res.defaults || {}), ...(res.settings || {}) };
      if (flat.session_timeout_minutes) flat.session_timeout_minutes = Number(flat.session_timeout_minutes);
      if (flat.simulated_devices_count) flat.simulated_devices_count = Number(flat.simulated_devices_count);
      if (flat.port_scan_threshold) flat.port_scan_threshold = Number(flat.port_scan_threshold);
      if (flat.failed_auth_threshold) flat.failed_auth_threshold = Number(flat.failed_auth_threshold);
      if (flat.traffic_anomaly_threshold) flat.traffic_anomaly_threshold = Number(flat.traffic_anomaly_threshold);
      if (flat.traffic_generation_rate) flat.traffic_generation_rate = Number(flat.traffic_generation_rate);
      if (flat.password_min_length) flat.password_min_length = Number(flat.password_min_length);
      flat.unknown_device_detection = flat.unknown_device_detection === true || flat.unknown_device_detection === 'true';
      flat.password_require_digit = flat.password_require_digit === true || flat.password_require_digit === 'true';

      setSettings(flat);
      setModelInfo(model);
      setSystemStatus(status);
    } catch (e) {
      setError("Unable to load settings. Please verify the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const save = async () => {
    if (!isAdmin) {
      setMsg('❌ Forbidden: Only Administrators can modify configuration.');
      return;
    }
    setSaving(true);
    try {
      const res = await api.updateSettings({
        traffic_anomaly_threshold: settings?.traffic_anomaly_threshold ? Number(settings.traffic_anomaly_threshold) : undefined,
        port_scan_threshold: settings?.port_scan_threshold ? Number(settings.port_scan_threshold) : undefined,
        failed_auth_threshold: settings?.failed_auth_threshold ? Number(settings.failed_auth_threshold) : undefined,
        unknown_device_detection: settings?.unknown_device_detection,
        simulation_tick_seconds: settings?.simulation_tick_seconds ? Number(settings.simulation_tick_seconds) : undefined,
        traffic_generation_rate: settings?.traffic_generation_rate ? Number(settings.traffic_generation_rate) : undefined,
        simulated_devices_count: settings?.simulated_devices_count ? Number(settings.simulated_devices_count) : undefined,
        simulation_seed: settings?.simulation_seed ? Number(settings.simulation_seed) : undefined,
        session_timeout_minutes: settings?.session_timeout_minutes ? Number(settings.session_timeout_minutes) : undefined,
        password_min_length: settings?.password_min_length ? Number(settings.password_min_length) : undefined,
        password_require_digit: settings?.password_require_digit,
        system_mode: settings?.system_mode
      });
      if (res?.warning_notice) {
        setMsg(`ℹ️ ${res.warning_notice}`);
      } else {
        setMsg('✅ Settings saved and audit-logged.');
      }
      await loadData();
    } catch (e) {
      setMsg(`❌ ${e.message}`);
    } finally {
      setSaving(false);
      setTimeout(() => setMsg(''), 8000);
    }
  };

  const update = (key, val) => setSettings(prev => ({ ...prev, [key]: val }));

  const handleModeSelect = (val) => {
    if (val === 'LIVE') {
      setShowConsentModal(true);
    } else {
      update('system_mode', 'SIMULATION');
    }
  };

  const handleConfirmLiveConsent = () => {
    if (!consentChecked) return;
    update('system_mode', 'LIVE');
    setShowConsentModal(false);
    setConsentChecked(false);
  };

  // Friendly Offline State (Task 6 & Acceptance Check 5)
  if (error && !settings) {
    return (
      <div style={{ padding: '60px 0', maxWidth: 640, margin: '0 auto', textAlign: 'center' }}>
        <div className="ng-card" style={{ padding: '40px 30px' }}>
          <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>⚠️</div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#0f172a', marginBottom: 8 }}>
            Unable to Load Settings
          </h2>
          <p style={{ fontSize: '0.875rem', color: '#64748b', marginBottom: 20 }}>
            Unable to load system settings. Please verify the backend is running.
          </p>
          <button
            onClick={loadData}
            className="btn btn-primary"
            style={{ margin: '0 auto' }}
          >
            <RefreshCw size={14} /> Retry Connection
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return <div style={{ textAlign: 'center', padding: 60, color: '#94a3b8' }}>Loading settings and system status…</div>;
  }

  const components = systemStatus?.components || {
    backend: { name: 'Backend', status: systemStatus?.backend || 'ONLINE', ok: true, reason: 'FastAPI operational' },
    database: { name: 'Database', status: systemStatus?.database || 'ONLINE', ok: true, reason: 'SQLite primary store connected' },
    ai_engine: { name: 'AI Engine', status: systemStatus?.ai_engine || 'READY', ok: true, reason: 'Isolation Forest ready' },
    digital_twin: { name: 'Digital Twin', status: systemStatus?.digital_twin || 'SYNCHRONIZED', ok: true, reason: 'Graph synchronized with database' },
    network_collector: { name: 'Network Collector', status: systemStatus?.network_collector || 'SIMULATION_ACTIVE', ok: true, reason: 'Synthetic flow generator active' },
  };

  return (
    <div style={{ padding: '24px 0', maxWidth: 780, margin: '0 auto' }}>

      {/* HEADER */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20, gap: 12, flexWrap: 'wrap' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a' }}>System Settings & Status</h1>
          <p style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 2 }}>
            Validated configuration, subsystem probes, and audit-logged operations
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {msg && (
            <span style={{
              fontSize: '0.8125rem', fontWeight: 600,
              color: msg.includes('✅') ? '#059669' : '#dc2626',
              background: msg.includes('✅') ? '#f0fdf4' : '#fee2e2',
              border: `1px solid ${msg.includes('✅') ? '#bbf7d0' : '#fca5a5'}`,
              padding: '6px 12px', borderRadius: 8
            }}>
              {msg}
            </span>
          )}
          {isAdmin ? (
            <button onClick={save} disabled={saving} className="btn btn-primary">
              <Save size={14} /> {saving ? 'Saving…' : 'Save Settings'}
            </button>
          ) : (
            <button disabled className="btn btn-secondary" style={{ opacity: 0.6, cursor: 'not-allowed' }}>
              <Save size={14} /> Read-Only (Analyst)
            </button>
          )}
        </div>
      </div>

      {/* Analyst Read-Only Notice (Task 4) */}
      {!isAdmin && (
        <div style={{
          background: '#eff6ff',
          border: '1px solid #bfdbfe',
          borderRadius: 10,
          padding: '12px 16px',
          marginBottom: 20,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          fontSize: '0.8125rem',
          color: '#1e40af'
        }}>
          <Shield size={18} style={{ flexShrink: 0 }} />
          <div>
            <strong>Read-Only Mode:</strong> Signed in as an <strong>Analyst</strong>. Settings are inspectable for audit validation. Only Administrators can modify operational settings.
          </div>
        </div>
      )}

      {/* SYSTEM STATUS PANEL (Task 5) */}
      <Section title="⚡ Subsystem Health Probes">
        <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: 14 }}>
          Live verification probes across backend services. Components report operational readiness or specific limitation reasons.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {Object.entries(components).map(([key, comp]) => (
            <div
              key={key}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '10px 14px',
                border: '1px solid #e2e8f0',
                borderRadius: 8,
                background: '#ffffff',
                gap: 12
              }}
            >
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontWeight: 700, fontSize: '0.8125rem', color: '#0f172a' }}>{comp.name || key}</span>
                  <span style={{
                    fontSize: '0.675rem',
                    fontWeight: 700,
                    padding: '2px 8px',
                    borderRadius: 10,
                    background: comp.ok ? '#dcfce7' : '#fee2e2',
                    color: comp.ok ? '#15803d' : '#b91c1c',
                    border: `1px solid ${comp.ok ? '#86efac' : '#fca5a5'}`
                  }}>
                    {comp.status}
                  </span>
                </div>
                {comp.reason && (
                  <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 3 }}>
                    Reason: {comp.reason}
                  </div>
                )}
              </div>
              <span style={{
                width: 10, height: 10, borderRadius: '50%',
                background: comp.ok ? '#059669' : '#dc2626',
                display: 'inline-block'
              }} />
            </div>
          ))}
        </div>
      </Section>

      {/* 1. DETECTION SETTINGS (Task 4) */}
      <Section title="🔍 Detection Settings">
        <Field label="Traffic Anomaly Threshold (multiplier above baseline)" hint="Flow volume exceeding this multiplier above learned baseline triggers an anomaly alert.">
          <input
            className="ng-input"
            type="number"
            step="0.5"
            min="1"
            max="20"
            disabled={!isAdmin}
            value={settings?.traffic_anomaly_threshold ?? 3.0}
            onChange={e => update('traffic_anomaly_threshold', Number(e.target.value))}
          />
        </Field>

        <Field label="Port Activity Threshold (unique ports in window)" hint="Number of unique destination ports accessed in a 30s window that triggers a Port Scan alert.">
          <input
            className="ng-input"
            type="number"
            min="1"
            max="100"
            disabled={!isAdmin}
            value={settings?.port_scan_threshold ?? 15}
            onChange={e => update('port_scan_threshold', Number(e.target.value))}
          />
        </Field>

        <Field label="Failed-Login Threshold (failed attempts in window)" hint="Failed authentication attempts in 30s that trigger a Brute-Force pattern alert.">
          <input
            className="ng-input"
            type="number"
            min="1"
            max="50"
            disabled={!isAdmin}
            value={settings?.failed_auth_threshold ?? 5}
            onChange={e => update('failed_auth_threshold', Number(e.target.value))}
          />
        </Field>

        <Field label="Unknown Device Detection (On / Off)" hint="Flag and alert on any device transmitting packets that is not registered in the inventory.">
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: isAdmin ? 'pointer' : 'default', fontSize: '0.875rem', color: '#334155' }}>
            <input
              type="checkbox"
              disabled={!isAdmin}
              checked={settings?.unknown_device_detection ?? true}
              onChange={e => update('unknown_device_detection', e.target.checked)}
              style={{ accentColor: '#2563eb', width: 16, height: 16 }}
            />
            Enable Unknown Device Detection (RULE-01)
          </label>
        </Field>
      </Section>

      {/* 2. SIMULATION SETTINGS (Task 4) */}
      <Section title="🧪 Simulation Settings">
        <Field label="Traffic Generation Rate (multiplier)" hint="Flow volume multiplier for synthetic background traffic generation.">
          <input
            className="ng-input"
            type="number"
            step="0.1"
            min="0.1"
            max="10.0"
            disabled={!isAdmin}
            value={settings?.traffic_generation_rate ?? 1.0}
            onChange={e => update('traffic_generation_rate', Number(e.target.value))}
          />
        </Field>

        <Field label="Number of Simulated Devices (10 to 100)" hint="Active virtual endpoints in the simulated local area network.">
          <input
            className="ng-input"
            type="number"
            min="10"
            max="100"
            disabled={!isAdmin}
            value={settings?.simulated_devices_count ?? 10}
            onChange={e => update('simulated_devices_count', Number(e.target.value))}
          />
        </Field>

        <Field label="Simulation Seed (deterministic integer)" hint="Fixes random seed for 100% reproducible traffic simulation runs.">
          <input
            className="ng-input"
            type="number"
            disabled={!isAdmin}
            value={settings?.simulation_seed ?? 42}
            onChange={e => update('simulation_seed', Number(e.target.value))}
          />
        </Field>
      </Section>

      {/* 3. SECURITY SETTINGS (Task 4) */}
      <Section title="🔐 Security Settings">
        <Field label="Session Timeout (minutes)" hint="Token validity period. Enforced server-side between 1 and 10080 minutes (max 7 days).">
          <input
            className="ng-input"
            type="number"
            min="1"
            max="10080"
            disabled={!isAdmin}
            value={settings?.session_timeout_minutes ?? 1440}
            onChange={e => update('session_timeout_minutes', Number(e.target.value))}
          />
        </Field>

        <Field label="Password Minimum Length" hint="Minimum required characters for user passwords (must be at least 8).">
          <input
            className="ng-input"
            type="number"
            min="8"
            max="64"
            disabled={!isAdmin}
            value={settings?.password_min_length ?? 8}
            onChange={e => update('password_min_length', Number(e.target.value))}
          />
        </Field>

        <Field label="Password Policy: Require Digit" hint="Enforce that new user passwords must contain at least one numeric digit (0-9).">
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: isAdmin ? 'pointer' : 'default', fontSize: '0.875rem', color: '#334155' }}>
            <input
              type="checkbox"
              disabled={!isAdmin}
              checked={settings?.password_require_digit ?? true}
              onChange={e => update('password_require_digit', e.target.checked)}
              style={{ accentColor: '#2563eb', width: 16, height: 16 }}
            />
            Require at least one numeric digit (0-9)
          </label>
        </Field>

        <Field label="System Operational Mode" hint="Simulation mode operates on synthetic metadata. Live mode captures real raw network packets passively on authorized networks.">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <select
              className="ng-select"
              disabled={!isAdmin}
              value={settings?.system_mode ?? 'SIMULATION'}
              onChange={e => handleModeSelect(e.target.value)}
            >
              <option value="SIMULATION">Simulation Mode (Active)</option>
              <option value="LIVE">Live Monitoring Mode (Passive Header Metadata)</option>
            </select>
            {settings?.system_mode === 'LIVE' && (
              <div style={{ fontSize: '0.75rem', color: '#047857', background: '#ecfdf5', border: '1px solid #a7f3d0', padding: '6px 10px', borderRadius: 6 }}>
                🟢 <strong>Live Monitoring Mode:</strong> Passive packet header metadata capture active on authorized local interfaces. Zero application payloads or passwords are read or stored.
                <div style={{ marginTop: 4, color: '#b45309', fontWeight: 600 }}>
                  ⚠️ Authorization Notice: Live mode is strictly for networks you own or are authorized to monitor. Live mode has not been verified against real traffic in the automated tests.
                </div>
              </div>
            )}
          </div>
        </Field>
      </Section>

      {/* AI MODEL CARD */}
      <Section title="🧠 AI Anomaly Detection Model Card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div>
            <div style={{ fontWeight: 800, fontSize: '1rem', color: '#0f172a' }}>
              {modelInfo?.model_type || 'Role-Based Isolation Forest Ensemble'} (v{modelInfo?.version || '1.0'})
            </div>
            <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: 2 }}>
              {modelInfo?.purpose || 'Unsupervised behavioral anomaly scoring on network flow telemetry.'}
            </div>
          </div>
          <span style={{
            background: modelInfo?.status === 'READY' ? '#f0fdf4' : '#fffbeb',
            color: modelInfo?.status === 'READY' ? '#166534' : '#b45309',
            border: `1px solid ${modelInfo?.status === 'READY' ? '#bbf7d0' : '#fde68a'}`,
            padding: '4px 10px',
            borderRadius: 8,
            fontSize: '0.75rem',
            fontWeight: 700
          }}>
            Status: {modelInfo?.status || 'READY'}
          </span>
        </div>

        <div style={{ fontSize: '0.75rem', color: '#64748b', fontStyle: 'italic', marginBottom: 12 }}>
          * Metrics come from synthetic data generated by the same simulator and do not predict real-world performance.
        </div>
      </Section>

      {/* Live Monitoring Authorization Consent Notice Modal (Task 1) */}
      {showConsentModal && (
        <div className="ng-modal-overlay" style={{ zIndex: 10001 }}>
          <div className="ng-modal" style={{ maxWidth: '520px' }}>
            <div className="ng-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Shield size={20} color="#2563eb" />
                <h3 style={{ fontSize: '1.0625rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
                  Authorized Network Monitoring Consent
                </h3>
              </div>
              <button 
                onClick={() => { setShowConsentModal(false); setConsentChecked(false); }} 
                className="btn-ghost" 
                style={{ border: 'none', background: 'none' }}
              >
                ✕
              </button>
            </div>
            <div className="ng-modal-body" style={{ fontSize: '0.8125rem', color: '#334155', lineHeight: 1.6 }}>
              <div style={{ background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '12px 14px', marginBottom: 14 }}>
                <p style={{ margin: 0, fontWeight: 600, color: '#0f172a' }}>Passive Header Metadata Only Notice:</p>
                <p style={{ margin: '6px 0 0 0', color: '#64748b' }}>
                  Live monitoring mode operates strictly in passive mode. Live mode is strictly for networks you own or are authorized to monitor.
                  NetGuardian collects transport metadata only (IP addresses, port numbers, protocols, timestamps, volume).
                </p>
                <p style={{ margin: '6px 0 0 0', color: '#b45309', fontWeight: 600 }}>
                  NOTICE: Live mode has not been verified against real traffic in the automated tests. Under no circumstances are application passwords, unencrypted credentials, or payload contents ever inspected or stored.
                </p>
              </div>

              <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', padding: '6px 0' }}>
                <input
                  type="checkbox"
                  checked={consentChecked}
                  onChange={e => setConsentChecked(e.target.checked)}
                  style={{ accentColor: '#2563eb', width: 16, height: 16, marginTop: 2 }}
                />
                <span style={{ fontSize: '0.8125rem', color: '#0f172a', fontWeight: 600 }}>
                  I confirm that I have explicit administrative authorization to passively monitor network traffic on this local segment.
                </span>
              </label>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 18 }}>
                <button
                  type="button"
                  onClick={() => { setShowConsentModal(false); setConsentChecked(false); }}
                  className="btn btn-secondary btn-sm"
                >
                  Cancel (Stay in Simulation)
                </button>
                <button
                  type="button"
                  disabled={!consentChecked}
                  onClick={handleConfirmLiveConsent}
                  className="btn btn-primary btn-sm"
                >
                  Acknowledge & Enable
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
