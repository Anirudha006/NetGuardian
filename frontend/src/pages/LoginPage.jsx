import React, { useState } from 'react';
import { Shield, Lock, User, ArrowRight, AlertCircle, Eye, EyeOff, Activity, Network, Brain } from 'lucide-react';
import { useAuth } from '../hooks/useAuth';

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
    } catch (err) {
      setError(err.message || 'Incorrect username or password. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const fill = (u, p) => { 
    setUsername(u); 
    setPassword(p); 
    setError('');
  };

  const features = [
    { icon: Activity, label: 'Real-Time Monitoring', desc: 'Live traffic & device telemetry metadata' },
    { icon: Brain, label: 'AI Anomaly Detection', desc: 'Isolation Forest machine learning engine' },
    { icon: Network, label: 'Digital Twin', desc: 'Safe graph-based What-If attack simulation' },
  ];

  const workflow = ['Observe', 'Analyze', 'Visualize', 'Simulate', 'Recommend', 'Respond'];
  const showDemoLogins = import.meta.env.VITE_ENABLE_DEMO_LOGINS !== 'false';

  return (
    <div style={{ minHeight: '100vh', background: '#f8fafc', display: 'flex', flexDirection: 'column' }}>

      {/* Sticky top bar */}
      <div style={{ background: '#ffffff', borderBottom: '1px solid #e2e8f0', padding: '12px 24px', display: 'flex', alignItems: 'center', gap: 10 }}>
        <div className="ng-nav-logo">
          <Shield size={18} />
        </div>
        <span style={{ fontWeight: 800, fontSize: '1.1rem', color: '#0f172a', letterSpacing: '-0.02em' }}>
          NET<span style={{ color: '#2563eb' }}>GUARDIAN</span>
        </span>
        <span style={{ fontSize: '0.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: 20, background: '#dbeafe', color: '#1d4ed8', border: '1px solid #bfdbfe', marginLeft: 4 }}>
          MODE: SIMULATION
        </span>
      </div>

      <div style={{ flex: 1, display: 'flex', alignItems: 'stretch' }}>

        {/* LEFT — Brand & Mission Overview */}
        <div style={{ flex: 1, background: 'linear-gradient(135deg, #1e40af 0%, #1d4ed8 40%, #2563eb 100%)', color: '#ffffff', padding: '60px 48px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 40 }}>

          <div style={{ maxWidth: 500 }}>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'rgba(255,255,255,0.15)', padding: '6px 14px', borderRadius: 20, fontSize: '0.75rem', fontWeight: 600, marginBottom: 24, backdropFilter: 'blur(4px)' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#34d399', display: 'inline-block' }} />
              Defensive Education & Threat Simulation
            </div>

            <h1 style={{ fontSize: '2.5rem', fontWeight: 900, lineHeight: 1.15, letterSpacing: '-0.03em', marginBottom: 16 }}>
              AI-Powered Digital Twin<br />for Network Security
            </h1>
            <p style={{ fontSize: '1.05rem', opacity: 0.9, lineHeight: 1.6, fontWeight: 500, marginBottom: 12 }}>
              See your network. Understand the risk.<br />
              Simulate the threat. Protect the system.
            </p>
            <p style={{ fontSize: '0.85rem', opacity: 0.8, lineHeight: 1.6, marginBottom: 30 }}>
              Combines passive network monitoring, machine learning anomaly detection, and graph-based Digital Twin modeling to help administrators explore threat scenarios safely without risking live systems.
            </p>

            {/* Workflow steps */}
            <div style={{ marginBottom: 32 }}>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', opacity: 0.85, marginBottom: 10 }}>
                Workflow: How It Works
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                {workflow.map((step, i) => (
                  <React.Fragment key={step}>
                    <span style={{ background: 'rgba(255,255,255,0.2)', padding: '4px 10px', borderRadius: 6, fontSize: '0.75rem', fontWeight: 600 }}>
                      {step}
                    </span>
                    {i < workflow.length - 1 && <span style={{ color: 'rgba(255,255,255,0.6)', fontSize: '0.8rem' }}>→</span>}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Feature cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {features.map(({ icon: Icon, label, desc }) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 12, background: 'rgba(255,255,255,0.1)', borderRadius: 10, padding: '12px 14px', backdropFilter: 'blur(4px)' }}>
                  <div style={{ width: 36, height: 36, borderRadius: 8, background: 'rgba(255,255,255,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <Icon size={16} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.875rem' }}>{label}</div>
                    <div style={{ fontSize: '0.75rem', opacity: 0.8 }}>{desc}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* RIGHT — Light Theme Login Form */}
        <div style={{ width: 440, background: '#ffffff', display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '48px 40px', borderLeft: '1px solid #e2e8f0' }}>

          <div style={{ marginBottom: 32 }}>
            <div style={{ width: 48, height: 48, borderRadius: 14, background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 16, boxShadow: '0 4px 12px rgba(37,99,235,0.25)' }}>
              <Shield size={22} color="white" />
            </div>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#0f172a', marginBottom: 4 }}>Sign in to NetGuardian</h2>
            <p style={{ fontSize: '0.875rem', color: '#64748b' }}>Enter your credentials to access the console</p>
          </div>

          {error && (
            <div style={{ background: '#fee2e2', border: '1px solid #fca5a5', borderRadius: 8, padding: '10px 14px', marginBottom: 20, display: 'flex', alignItems: 'flex-start', gap: 8 }}>
              <AlertCircle size={15} color="#dc2626" style={{ marginTop: 2, flexShrink: 0 }} />
              <span style={{ fontSize: '0.8125rem', color: '#991b1b', lineHeight: 1.4 }}>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label className="ng-label">Username</label>
              <div style={{ position: 'relative' }}>
                <User size={15} color="#94a3b8" style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  className="ng-input"
                  style={{ paddingLeft: 36 }}
                  type="text"
                  required
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="Enter username"
                  autoFocus
                />
              </div>
            </div>

            <div>
              <label className="ng-label">Password</label>
              <div style={{ position: 'relative' }}>
                <Lock size={15} color="#94a3b8" style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)' }} />
                <input
                  className="ng-input"
                  style={{ paddingLeft: 36, paddingRight: 40 }}
                  type={showPw ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Enter password"
                />
                <button type="button" onClick={() => setShowPw(!showPw)} style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#94a3b8', padding: 2 }}>
                  {showPw ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{ width: '100%', justifyContent: 'center', padding: '11px 16px', fontSize: '0.9375rem', marginTop: 4 }}
            >
              {loading ? 'Signing in...' : 'Sign In'}
              {!loading && <ArrowRight size={16} />}
            </button>
          </form>

          {/* Demo credentials (Configurable via VITE_ENABLE_DEMO_LOGINS) */}
          {showDemoLogins && (
            <div style={{ marginTop: 28, paddingTop: 24, borderTop: '1px solid #e2e8f0' }}>
              <p style={{ fontSize: '0.75rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 10, textAlign: 'center' }}>
                Demo Credentials (DEMO ONLY)
              </p>
              <div style={{ display: 'flex', gap: 8 }}>
                <button 
                  type="button"
                  onClick={() => fill('admin', 'admin123')} 
                  style={{ flex: 1, background: '#f0f9ff', border: '1px solid #bae6fd', borderRadius: 8, padding: '9px 12px', cursor: 'pointer', textAlign: 'left', transition: 'all 0.12s' }}
                >
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#0369a1' }}>🛡️ Admin</div>
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: 1 }}>Full access (All features)</div>
                </button>
                <button 
                  type="button"
                  onClick={() => fill('analyst', 'analyst123')} 
                  style={{ flex: 1, background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '9px 12px', cursor: 'pointer', textAlign: 'left', transition: 'all 0.12s' }}
                >
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#475569' }}>👤 Analyst</div>
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: 1 }}>Operations (No admin rights)</div>
                </button>
              </div>
            </div>
          )}

          <p style={{ marginTop: 24, fontSize: '0.7rem', color: '#94a3b8', textAlign: 'center', lineHeight: 1.6 }}>
            NetGuardian is a defensive cybersecurity prototype.<br />
            All attacks are simulated. No real network is harmed.
          </p>
        </div>
      </div>
    </div>
  );
}
