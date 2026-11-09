import React, { useState } from 'react';
import { Shield, Network, AlertTriangle, Layers, ChevronRight, X } from 'lucide-react';

const STEPS = [
  {
    icon: <Shield size={28} color="#2563eb" />,
    title: 'Choose Your Mode',
    desc: 'NetGuardian runs in Simulation Mode by default — a fully virtual network that works on any laptop. Live Monitoring Mode can passively monitor a real authorized network interface.',
    note: '📌 Simulation Mode is active. Live Monitoring is coming soon.',
    action: 'Simulation Mode is Active',
  },
  {
    icon: <Network size={28} color="#059669" />,
    title: 'Review Your Network Topology',
    desc: 'The Dashboard and Digital Twin pages show a live map of all simulated devices. Click any node to inspect its risk score, connections, and security status.',
    note: '📌 Go to Network → see all devices in a table view.',
    action: 'Understood',
  },
  {
    icon: <AlertTriangle size={28} color="#d97706" />,
    title: 'Monitor Security Events',
    desc: 'The Threats page lists all security events detected by rules and AI. Use "Simulate Security Event" on the Dashboard to see the system respond to a port scan, unknown device, or traffic spike.',
    note: '📌 Every alert shows its source, severity, confidence, and recommended action.',
    action: 'Got it',
  },
  {
    icon: <Layers size={28} color="#7c3aed" />,
    title: 'Use the Digital Twin for What-If Analysis',
    desc: 'Select any device and click "Run What-If Simulation" to safely explore what would happen if that device were compromised. The engine computes potential attack paths — no real network is touched.',
    note: '📌 All What-If results are clearly labelled HYPOTHETICAL.',
    action: 'Let\'s Start',
  },
];

export default function OnboardingModal({ isOpen, onClose }) {
  const [step, setStep] = useState(0);
  if (!isOpen) return null;

  const isLast = step === STEPS.length - 1;
  const s = STEPS[step];

  return (
    <div className="ng-modal-overlay" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="ng-modal" style={{ maxWidth: 500 }}>
        {/* Header */}
        <div className="ng-modal-header">
          <div>
            <div style={{ fontWeight: 800, fontSize: '1.0625rem', color: '#0f172a' }}>
              Welcome to NetGuardian 👋
            </div>
            <div style={{ fontSize: '0.8125rem', color: '#64748b', marginTop: 2 }}>
              Step {step + 1} of {STEPS.length} — Quick setup tour
            </div>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-sm"><X size={16} color="#64748b" /></button>
        </div>

        {/* Progress bar */}
        <div style={{ height: 3, background: '#e2e8f0' }}>
          <div style={{ height: '100%', background: '#2563eb', width: `${((step + 1) / STEPS.length) * 100}%`, transition: 'width 0.3s ease', borderRadius: '0 20px 20px 0' }} />
        </div>

        <div className="ng-modal-body">
          {/* Icon */}
          <div style={{ width: 60, height: 60, borderRadius: 16, background: '#f8fafc', border: '2px solid #e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20 }}>
            {s.icon}
          </div>

          <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#0f172a', marginBottom: 10 }}>{s.title}</h2>
          <p style={{ fontSize: '0.9rem', color: '#334155', lineHeight: 1.7, marginBottom: 14 }}>{s.desc}</p>

          <div style={{ background: '#f0f9ff', border: '1px solid #bae6fd', borderRadius: 8, padding: '10px 14px', fontSize: '0.8125rem', color: '#0369a1' }}>
            {s.note}
          </div>
        </div>

        <div className="ng-modal-footer">
          <button onClick={onClose} className="btn btn-ghost">
            Skip Tutorial
          </button>
          <button
            onClick={() => { if (isLast) onClose(); else setStep(s => s + 1); }}
            className="btn btn-primary"
          >
            {isLast ? '✅ Get Started' : `Next: ${STEPS[step + 1].title}`}
            {!isLast && <ChevronRight size={14} />}
          </button>
        </div>
      </div>
    </div>
  );
}
