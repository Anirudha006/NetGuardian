import React, { useState, useEffect } from 'react';
import { 
  Play, Pause, RotateCcw, ChevronRight, ChevronLeft, 
  X, CheckCircle, AlertTriangle, ShieldCheck, Zap, AlertCircle, Minimize2, Maximize2
} from 'lucide-react';
import { api } from '../../services/api';

export default function GuidedDemoModal({ 
  isOpen, 
  onClose, 
  onStepChanged = () => {},
  onNavigate = () => {},
  isDocked = false,
  setIsDocked = () => {}
}) {
  const [currentStep, setCurrentStep] = useState(1);
  const [stepData, setStepData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [autoPlay, setAutoPlay] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [confirmResetOpen, setConfirmResetOpen] = useState(false);
  const [resetting, setResetting] = useState(false);

  const stepsList = [
    { num: 1, title: 'Network Setup', label: 'Baseline Network', page: 'devices' },
    { num: 2, title: 'Traffic Pulse', label: 'Normal Traffic', page: 'traffic' },
    { num: 3, title: 'Rogue Device', label: 'Unknown Device', page: 'devices' },
    { num: 4, title: 'Port Recon', label: 'Simulated Probe', page: 'threats' },
    { num: 5, title: 'Rule Detection', label: 'Rule Engine Flag', page: 'threats' },
    { num: 6, title: 'AI Anomaly', label: 'Isolation Forest', page: 'threats' },
    { num: 7, title: 'Alert Raised', label: 'Dashboard Alert', page: 'dashboard' },
    { num: 8, title: 'Twin Highlight', label: 'Node Pulsing', page: 'digital-twin' },
    { num: 9, title: 'What-If Query', label: 'Compromise Model', page: 'what-if' },
    { num: 10, title: 'Attack Path', label: 'Database Path', page: 'what-if' },
    { num: 11, title: 'Isolation', label: 'Simulated Sever', page: 'what-if' },
    { num: 12, title: 'Restoration', label: 'Threat Contained', page: 'what-if' },
  ];

  const runStep = async (stepNum) => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await api.stepDemo(stepNum);
      setStepData(res);
      setCurrentStep(stepNum);
      onStepChanged(stepNum);
      // Auto-jump to the relevant page for each step (Task 4)
      if (res?.target_page) {
        onNavigate(res.target_page);
      }
      window.dispatchEvent(new CustomEvent('netguardian_refresh', { detail: { step: stepNum } }));
    } catch (err) {
      console.error("Step execution error:", err);
      setErrorMsg(err.message || "Failed to execute simulation step.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && !stepData) {
      runStep(1);
    }
  }, [isOpen]);

  useEffect(() => {
    let timer;
    if (autoPlay && currentStep < 12) {
      timer = setTimeout(() => {
        runStep(currentStep + 1);
      }, 3500);
    } else if (currentStep >= 12) {
      setAutoPlay(false);
    }
    return () => clearTimeout(timer);
  }, [autoPlay, currentStep]);

  const handleExecuteReset = async () => {
    setAutoPlay(false);
    setResetting(true);
    setErrorMsg('');
    try {
      await api.resetDemo();
      setConfirmResetOpen(false);
      setCurrentStep(1);
      onNavigate('dashboard');
      await runStep(1);
      window.dispatchEvent(new CustomEvent('netguardian_refresh', { detail: { reset: true } }));
    } catch (err) {
      setErrorMsg(err.message || "Failed to reset demo. Admin privileges required.");
    } finally {
      setResetting(false);
    }
  };

  if (!isOpen) return null;

  // DOCKED / MINIMIZED CONTROLLER VIEW (Task 4 & 6: Presenter dock)
  if (isDocked) {
    return (
      <div style={{
        position: 'fixed', bottom: 16, left: '50%', transform: 'translateX(-50%)',
        background: '#ffffff', border: '2px solid #2563eb', borderRadius: 14,
        boxShadow: '0 12px 32px rgba(37,99,235,0.18)', padding: '10px 18px',
        display: 'flex', alignItems: 'center', gap: 14, zIndex: 9999,
        maxWidth: '92vw'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            background: '#eff6ff', color: '#1d4ed8', border: '1px solid #bfdbfe',
            fontWeight: 800, fontSize: '0.75rem', padding: '3px 8px', borderRadius: 6
          }}>
            STEP {currentStep}/12
          </span>
          <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a', whiteSpace: 'nowrap' }}>
            {stepData?.title || 'Guided Demo'}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <button
            type="button"
            disabled={currentStep <= 1 || loading}
            onClick={() => runStep(currentStep - 1)}
            className="btn btn-secondary btn-sm"
            title="Previous Step"
          >
            <ChevronLeft size={14} />
          </button>

          <button
            type="button"
            disabled={currentStep >= 12 || loading}
            onClick={() => runStep(currentStep + 1)}
            className="btn btn-primary btn-sm"
          >
            <span>{loading ? 'Processing...' : 'Next'}</span>
            <ChevronRight size={14} />
          </button>

          <button
            type="button"
            onClick={() => setAutoPlay(!autoPlay)}
            className={autoPlay ? "btn btn-warning btn-sm" : "btn btn-secondary btn-sm"}
            title="Auto-play narration"
          >
            {autoPlay ? <Pause size={13} /> : <Play size={13} />}
            <span>{autoPlay ? 'Pause' : 'Auto'}</span>
          </button>

          <button
            type="button"
            onClick={() => setConfirmResetOpen(true)}
            className="btn btn-secondary btn-sm"
            title="Reset Demo"
          >
            <RotateCcw size={13} />
          </button>

          <button
            type="button"
            onClick={() => setIsDocked(false)}
            className="btn btn-ghost btn-sm"
            title="Expand to Full Modal"
          >
            <Maximize2 size={14} />
          </button>

          <button
            type="button"
            onClick={onClose}
            className="btn btn-ghost btn-sm"
            title="Close Demo"
          >
            <X size={14} />
          </button>
        </div>

        {/* Confirmation Modal for Reset */}
        {confirmResetOpen && (
          <div className="ng-modal-overlay" style={{ zIndex: 10001 }}>
            <div className="ng-modal" style={{ maxWidth: '440px' }}>
              <div className="ng-modal-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <AlertTriangle size={18} color="#dc2626" />
                  <h3 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>Reset Demonstration?</h3>
                </div>
                <button onClick={() => setConfirmResetOpen(false)} className="btn-ghost" style={{ border: 'none', background: 'none' }}><X size={16} /></button>
              </div>
              <div className="ng-modal-body" style={{ fontSize: '0.8125rem', color: '#475569', lineHeight: 1.5 }}>
                <p>This will restore the 12-device network back to pristine baseline, clear all simulated alerts, security events, traffic records, and attack paths. Health will return to 100%.</p>
                <p style={{ marginTop: 8, fontWeight: 600, color: '#0f172a' }}>User accounts, audit logs, and settings will remain completely intact.</p>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
                  <button onClick={() => setConfirmResetOpen(false)} className="btn btn-secondary btn-sm">Cancel</button>
                  <button onClick={handleExecuteReset} disabled={resetting} className="btn btn-danger btn-sm">
                    {resetting ? 'Resetting...' : 'Confirm Reset'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // STANDARD MODAL VIEW
  return (
    <div className="ng-modal-overlay" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="ng-modal" style={{ maxWidth: '680px' }}>
        
        {/* Header */}
        <div className="ng-modal-header" style={{ alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '36px', height: '36px', borderRadius: '10px',
              background: '#fef3c7', color: '#d97706',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              border: '1px solid #fde68a'
            }}>
              <Zap size={18} />
            </div>
            <div>
              <span style={{ fontSize: '0.65rem', fontWeight: 700, color: '#2563eb', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Automated Guided Demonstration · 12 Steps
              </span>
              <h2 style={{ fontSize: '1.125rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>
                Incident Lifecycle & Digital Twin Walkthrough
              </h2>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <button
              onClick={() => setIsDocked(true)}
              className="btn btn-ghost btn-sm"
              title="Dock to bottom of screen"
              style={{ padding: '6px' }}
            >
              <Minimize2 size={16} color="#64748b" />
            </button>
            <button 
              onClick={onClose}
              className="btn btn-ghost btn-sm"
              style={{ padding: '6px' }}
            >
              <X size={18} color="#64748b" />
            </button>
          </div>
        </div>

        <div className="ng-modal-body">
          {errorMsg && (
            <div style={{
              marginBottom: '16px', padding: '10px 14px', borderRadius: '8px',
              background: '#fee2e2', border: '1px solid #fca5a5',
              color: '#991b1b', fontSize: '0.8125rem', display: 'flex', alignItems: 'center', gap: '8px'
            }}>
              <AlertCircle size={16} />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* Step Progress Number Buttons */}
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '4px', marginBottom: '16px'
          }}>
            {stepsList.map((s) => {
              const isDone = s.num < currentStep;
              const isCurrent = s.num === currentStep;
              return (
                <button
                  key={s.num}
                  type="button"
                  onClick={() => runStep(s.num)}
                  style={{
                    padding: '8px 2px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: 700,
                    fontFamily: 'monospace', textAlign: 'center', cursor: 'pointer', transition: 'all 0.12s',
                    border: isCurrent ? '2px solid #2563eb' : isDone ? '1px solid #bfdbfe' : '1px solid #e2e8f0',
                    background: isCurrent ? '#2563eb' : isDone ? '#eff6ff' : '#f8fafc',
                    color: isCurrent ? '#ffffff' : isDone ? '#1d4ed8' : '#64748b'
                  }}
                  title={`${s.num}. ${s.title}: ${s.label}`}
                >
                  {s.num}
                </button>
              );
            })}
          </div>

          {/* Current Step Content Box */}
          <div style={{
            padding: '16px 20px', borderRadius: '12px', background: '#f8fafc',
            border: '1px solid #e2e8f0', marginBottom: '20px'
          }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              paddingBottom: '8px', borderBottom: '1px solid #e2e8f0'
            }}>
              <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: '#d97706', display: 'flex', gap: '6px' }}>
                <span>Step {currentStep} of 12:</span>
                <span style={{ color: '#0f172a' }}>{stepData?.title || 'Loading Step...'}</span>
              </span>
              <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#64748b' }}>
                Target: <strong style={{ color: '#2563eb' }}>{stepData?.affected_device || 'Baseline Network'}</strong>
              </span>
            </div>

            <p style={{ marginTop: '12px', fontSize: '0.875rem', color: '#334155', lineHeight: 1.6 }}>
              {stepData?.narration || stepData?.description}
            </p>

            <div style={{
              marginTop: '12px', paddingTop: '10px', borderTop: '1px solid #e2e8f0',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              fontSize: '0.75rem', color: '#64748b', flexWrap: 'wrap', gap: '8px'
            }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span className="status-dot normal pulse"></span>
                <span>Active View: <strong style={{ color: '#2563eb', textTransform: 'uppercase' }}>{stepData?.target_page || 'dashboard'}</strong></span>
              </span>
              <span style={{ fontWeight: 600 }}>
                {currentStep <= 2 && "🟢 Health: 100% (HEALTHY)"}
                {currentStep >= 3 && currentStep <= 6 && "🟡 Health: 80% (DEGRADED)"}
                {currentStep >= 7 && currentStep <= 10 && "🔴 Health: 62% (ELEVATED RISK)"}
                {currentStep >= 11 && "🟢 Health: 100% (THREAT CONTAINED)"}
              </span>
            </div>
          </div>

          {/* Navigation & Auto-Play Controls */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            paddingTop: '12px', borderTop: '1px solid #e2e8f0'
          }}>
            <button
              type="button"
              onClick={() => setConfirmResetOpen(true)}
              className="btn btn-secondary btn-sm"
            >
              <RotateCcw size={13} color="#64748b" />
              <span>Reset Demo</span>
            </button>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <button
                type="button"
                onClick={() => setAutoPlay(!autoPlay)}
                className={autoPlay ? "btn btn-warning btn-sm" : "btn btn-secondary btn-sm"}
              >
                {autoPlay ? <Pause size={13} /> : <Play size={13} />}
                <span>{autoPlay ? 'Pause Auto' : 'Auto Play'}</span>
              </button>

              <button
                type="button"
                disabled={currentStep <= 1 || loading}
                onClick={() => runStep(currentStep - 1)}
                className="btn btn-secondary btn-sm"
                title="Previous Step"
              >
                <ChevronLeft size={14} />
              </button>

              <button
                type="button"
                disabled={currentStep >= 12 || loading}
                onClick={() => runStep(currentStep + 1)}
                className="btn btn-primary btn-sm"
              >
                <span>{loading ? 'Processing...' : 'Next Step'}</span>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>

        </div>

      </div>

      {/* Confirmation Modal for Reset (Task 5) */}
      {confirmResetOpen && (
        <div className="ng-modal-overlay" style={{ zIndex: 10001 }}>
          <div className="ng-modal" style={{ maxWidth: '440px' }}>
            <div className="ng-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertTriangle size={18} color="#dc2626" />
                <h3 style={{ fontSize: '1rem', fontWeight: 800, color: '#0f172a', margin: 0 }}>Reset Demonstration?</h3>
              </div>
              <button onClick={() => setConfirmResetOpen(false)} className="btn-ghost" style={{ border: 'none', background: 'none' }}><X size={16} /></button>
            </div>
            <div className="ng-modal-body" style={{ fontSize: '0.8125rem', color: '#475569', lineHeight: 1.5 }}>
              <p>This will restore the 12-device network back to pristine baseline, clear all simulated alerts, security events, traffic records, and attack paths. Health will return to 100%.</p>
              <p style={{ marginTop: 8, fontWeight: 600, color: '#0f172a' }}>User accounts, audit logs, and settings will remain completely intact.</p>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
                <button onClick={() => setConfirmResetOpen(false)} className="btn btn-secondary btn-sm">Cancel</button>
                <button onClick={handleExecuteReset} disabled={resetting} className="btn btn-danger btn-sm">
                  {resetting ? 'Resetting...' : 'Confirm Reset'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
