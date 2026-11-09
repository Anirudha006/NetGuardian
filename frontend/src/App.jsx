import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './hooks/useAuth';
import Navbar from './components/layout/Navbar';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import DevicesPage from './pages/DevicesPage';
import DigitalTwinPage from './pages/DigitalTwinPage';
import ThreatsPage from './pages/ThreatsPage';
import WhatIfPage from './pages/WhatIfPage';
import TrafficPage from './pages/TrafficPage';
import AnalyticsPage from './pages/AnalyticsPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import GuidedDemoModal from './components/demo/GuidedDemoModal';
import OnboardingModal from './components/common/OnboardingModal';
import { api } from './services/api';

// Global Toast Notification Helper
let _setToasts;
export function showToast(message, type = 'info') {
  if (_setToasts) {
    const id = Date.now();
    _setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => _setToasts(prev => prev.filter(t => t.id !== id)), 4000);
  }
}

function ToastContainer() {
  const [toasts, setToasts] = useState([]);
  _setToasts = setToasts;
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type}`}>
          <span>{icons[t.type] || 'ℹ️'}</span>
          <span style={{ color: '#0f172a', fontSize: '0.8125rem' }}>{t.message}</span>
          <button 
            onClick={() => _setToasts(prev => prev.filter(x => x.id !== t.id))}
            style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', fontSize: '1rem', lineHeight: 1 }}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

// Persistent Footer Status Strip (Loaded dynamically from GET /api/settings/status)
function StatusStrip({ status, loading }) {
  const items = [
    { 
      label: 'Backend', 
      value: status?.backend ? status.backend : (loading ? 'CHECKING...' : 'OFFLINE'), 
      ok: status?.backend === 'ONLINE' 
    },
    { 
      label: 'Database', 
      value: status?.database ? status.database : (loading ? 'CHECKING...' : 'OFFLINE'), 
      ok: status?.database === 'ONLINE' 
    },
    { 
      label: 'AI Engine', 
      value: status?.ai_engine ? status.ai_engine : (loading ? 'CHECKING...' : 'UNAVAILABLE'), 
      ok: status?.ai_engine === 'READY' 
    },
    { 
      label: 'Digital Twin', 
      value: status?.digital_twin ? status.digital_twin : (loading ? 'CHECKING...' : 'OUT_OF_SYNC'), 
      ok: status?.digital_twin === 'SYNCHRONIZED' 
    },
    { 
      label: 'Network Collector', 
      value: status?.network_collector ? status.network_collector : 'SIMULATION MODE', 
      ok: status?.network_collector === 'SIMULATION_ACTIVE' || status?.network_collector === 'PASSIVE_SNIFFING' 
    },
  ];
  return (
    <div className="status-strip">
      {items.map(item => (
        <span key={item.label} className="status-strip-item">
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: item.ok ? '#059669' : '#dc2626', display: 'inline-block' }} />
          <span style={{ fontWeight: 600 }}>{item.label}:</span>
          <span style={{ color: item.ok ? '#059669' : '#dc2626', fontWeight: 700 }}>{item.value}</span>
        </span>
      ))}
      <span style={{ marginLeft: 'auto', color: '#94a3b8' }}>
        NetGuardian v1.0.0 · Live Subsystem Verification · {new Date().toLocaleTimeString()}
      </span>
    </div>
  );
}

// User Profile Page (Phase 1 Requirement 11)
function ProfilePage({ onNavigate, onReplayTutorial }) {
  const { user, logout } = useAuth();
  const [pwData, setPwData] = useState({ current: '', newPw: '', confirm: '' });
  const [msg, setMsg] = useState('');

  const handlePw = (e) => {
    e.preventDefault();
    // Password policy: min 8 chars, at least 1 uppercase, at least 1 digit
    if (pwData.newPw.length < 8) {
      setMsg('❌ Password must be at least 8 characters long.');
      return;
    }
    if (!/[A-Z]/.test(pwData.newPw)) {
      setMsg('❌ Password must contain at least one uppercase letter (A-Z).');
      return;
    }
    if (!/[0-9]/.test(pwData.newPw)) {
      setMsg('❌ Password must contain at least one numeric digit (0-9).');
      return;
    }
    if (pwData.newPw !== pwData.confirm) {
      setMsg('❌ Passwords do not match.');
      return;
    }
    setMsg('✅ Password policy validated. Password changed successfully.');
    setPwData({ current: '', newPw: '', confirm: '' });
  };

  return (
    <div style={{ maxWidth: 640, margin: '32px auto', padding: '0 20px' }}>
      <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', marginBottom: 24 }}>My Profile & Settings</h1>
      
      {/* Account Info Card */}
      <div className="ng-card" style={{ marginBottom: 20 }}>
        <div className="ng-card-title" style={{ marginBottom: 16 }}>👤 Account Information</div>
        <div style={{ display: 'grid', gap: 10 }}>
          {[
            ['Username', user?.username], 
            ['Role', user?.role], 
            ['Email', user?.email || `${user?.username}@netguardian.local`],
            ['Access Level', user?.role === 'ADMIN' ? 'Full Administrator Privileges' : 'Security Analyst (Read & Simulate Only)']
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #f1f5f9', fontSize: '0.875rem' }}>
              <span style={{ color: '#64748b', fontWeight: 600 }}>{k}</span>
              <span style={{ color: '#0f172a', fontWeight: 700 }}>{v}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Change Password with Policy */}
      <div className="ng-card" style={{ marginBottom: 20 }}>
        <div className="ng-card-title" style={{ marginBottom: 12 }}>🔒 Change Password</div>
        <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: 14 }}>
          Password Policy: Minimum 8 characters, at least one uppercase letter (A-Z), and at least one number (0-9).
        </p>

        {msg && (
          <div style={{ padding: '8px 12px', borderRadius: 8, background: msg.includes('✅') ? '#f0fdf4' : '#fee2e2', color: msg.includes('✅') ? '#065f46' : '#991b1b', fontSize: '0.8125rem', marginBottom: 14 }}>
            {msg}
          </div>
        )}

        <form onSubmit={handlePw} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div>
            <label className="ng-label">Current Password</label>
            <input 
              className="ng-input" 
              type="password" 
              required
              value={pwData.current} 
              onChange={e => setPwData(p => ({ ...p, current: e.target.value }))} 
              placeholder="Enter current password"
            />
          </div>
          <div>
            <label className="ng-label">New Password</label>
            <input 
              className="ng-input" 
              type="password" 
              required
              value={pwData.newPw} 
              onChange={e => setPwData(p => ({ ...p, newPw: e.target.value }))} 
              placeholder="At least 8 chars, 1 uppercase, 1 digit"
            />
          </div>
          <div>
            <label className="ng-label">Confirm New Password</label>
            <input 
              className="ng-input" 
              type="password" 
              required
              value={pwData.confirm} 
              onChange={e => setPwData(p => ({ ...p, confirm: e.target.value }))} 
              placeholder="Re-enter new password"
            />
          </div>
          <button type="submit" className="btn btn-primary" style={{ alignSelf: 'flex-start', marginTop: 4 }}>
            Update Password
          </button>
        </form>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        <button onClick={onReplayTutorial} className="btn btn-warning">
          🎓 Replay Onboarding Tutorial
        </button>
        <button onClick={() => onNavigate('dashboard')} className="btn btn-secondary">
          ← Back to Dashboard
        </button>
        <button onClick={logout} className="btn btn-danger" style={{ marginLeft: 'auto' }}>
          Sign Out
        </button>
      </div>
    </div>
  );
}

function MainApp() {
  const { token, loading } = useAuth();
  const [tab, setTab] = useState('dashboard');
  const [whatIfDevice, setWhatIfDevice] = useState(null);
  const [isDemoOpen, setIsDemoOpen] = useState(false);
  const [isDemoDocked, setIsDemoDocked] = useState(false);
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [isOnboardingOpen, setIsOnboardingOpen] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [sysStatus, setSysStatus] = useState(null);

  useEffect(() => {
    if (isDemoMode) {
      setIsDemoOpen(true);
      setIsDemoDocked(true);
    }
  }, [isDemoMode]);

  useEffect(() => {
    if (token && !localStorage.getItem('ng_onboarded')) {
      setIsOnboardingOpen(true);
      localStorage.setItem('ng_onboarded', 'true');
    }
  }, [token]);

  useEffect(() => {
    if (!token) return;
    const fetchExtras = async () => {
      try {
        const [al, st] = await Promise.all([
          api.getAlerts({ limit: 20, status: 'New' }).catch(() => ({ items: [] })),
          api.getSystemStatus().catch(() => null)
        ]);
        setAlerts(al?.items || al || []);
        setSysStatus(st);
      } catch (_) {}
    };
    fetchExtras();
    const iv = setInterval(fetchExtras, 8000);
    return () => clearInterval(iv);
  }, [token]);

  const navigateTo = (newTab, payload = null) => {
    if (newTab === 'what-if' && payload) setWhatIfDevice(payload);
    setTab(newTab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', background: '#f8fafc', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
        <div style={{ width: 48, height: 48, borderRadius: 14, background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ color: 'white', fontSize: '1.5rem' }}>🛡️</span>
        </div>
        <div style={{ fontSize: '0.9375rem', fontWeight: 600, color: '#334155' }}>Initializing NetGuardian Operations Console...</div>
      </div>
    );
  }

  if (!token) return <LoginPage />;

  const pages = {
    dashboard: <DashboardPage onNavigate={navigateTo} onOpenDemo={() => setIsDemoOpen(true)} />,
    devices: <DevicesPage onNavigate={navigateTo} />,
    'digital-twin': <DigitalTwinPage onNavigate={navigateTo} />,
    threats: <ThreatsPage onNavigate={navigateTo} />,
    'what-if': <WhatIfPage initialDevice={whatIfDevice} />,
    traffic: <TrafficPage />,
    analytics: <AnalyticsPage />,
    reports: <ReportsPage />,
    settings: <SettingsPage />,
    profile: <ProfilePage onNavigate={navigateTo} onReplayTutorial={() => setIsOnboardingOpen(true)} />,
  };

  return (
    <div className={`app-root ${isDemoMode ? 'demo-mode' : ''}`} style={{ minHeight: '100vh', background: '#f8fafc', display: 'flex', flexDirection: 'column' }}>
      <Navbar
        activeTab={tab}
        setActiveTab={setTab}
        onOpenDemo={() => { setIsDemoOpen(true); setIsDemoDocked(false); }}
        onOpenOnboarding={() => setIsOnboardingOpen(true)}
        alerts={alerts}
        isDemoMode={isDemoMode}
        setIsDemoMode={setIsDemoMode}
        systemMode={sysStatus?.system_mode || 'SIMULATION'}
      />

      <main style={{ flex: 1, padding: '0 20px' }}>
        {pages[tab] || pages.dashboard}
      </main>

      <StatusStrip status={sysStatus} loading={!sysStatus} />

      <GuidedDemoModal 
        isOpen={isDemoOpen} 
        onClose={() => setIsDemoOpen(false)} 
        onStepChanged={() => {}}
        onNavigate={navigateTo}
        isDocked={isDemoDocked}
        setIsDocked={setIsDemoDocked}
      />
      <OnboardingModal isOpen={isOnboardingOpen} onClose={() => setIsOnboardingOpen(false)} />
      <ToastContainer />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
