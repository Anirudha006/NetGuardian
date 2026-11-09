import React, { useState, useEffect } from 'react';
import {
  Shield, Activity, Network, AlertTriangle, Crosshair,
  BarChart3, FileText, Settings, LogOut, User, Play,
  Layers, HelpCircle, Bell, ChevronDown, Search, X, Radio, Check, Tv
} from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';
import { api } from '../../services/api';

function getNotifCategory(alert) {
  const sev = (alert.severity || '').toUpperCase();
  const type = (alert.event_type || alert.rule_name || '').toUpperCase();

  if (sev === 'CRITICAL' || sev === 'HIGH' || type.includes('COMPROMISED') || type.includes('PORT_SCAN') || type.includes('FAILED_AUTH')) {
    return {
      icon: '🔴',
      label: 'High-risk device',
      color: '#dc2626',
      bg: '#fef2f2',
      border: '#fecaca'
    };
  }
  if (sev === 'MEDIUM' || type.includes('TRAFFIC_ANOMALY') || type.includes('UNKNOWN_DEVICE')) {
    return {
      icon: '🟡',
      label: 'Traffic anomaly',
      color: '#d97706',
      bg: '#fffbeb',
      border: '#fde68a'
    };
  }
  return {
    icon: '🟢',
    label: 'Simulation completed',
    color: '#059669',
    bg: '#f0fdf4',
    border: '#bbf7d0'
  };
}

export default function Navbar({ 
  activeTab, 
  setActiveTab, 
  onOpenDemo, 
  onOpenOnboarding, 
  alerts = [],
  isDemoMode = false,
  setIsDemoMode = () => {},
  systemMode = 'SIMULATION'
}) {
  const { user, logout, isAdmin } = useAuth();
  const [profileOpen, setProfileOpen] = useState(false);
  const [notifOpen, setNotifOpen] = useState(false);
  const [readNotifIds, setReadNotifIds] = useState(() => {
    try {
      const stored = localStorage.getItem('ng_read_notifs');
      return stored ? JSON.parse(stored) : [];
    } catch (_) {
      return [];
    }
  });

  // Sync server-side notification read state (Task 6)
  useEffect(() => {
    let mounted = true;
    api.getReadAlerts()
      .then(res => {
        if (mounted && res && Array.isArray(res.read_alert_ids)) {
          setReadNotifIds(res.read_alert_ids);
          try {
            localStorage.setItem('ng_read_notifs', JSON.stringify(res.read_alert_ids));
          } catch (_) {}
        }
      })
      .catch(() => {});
    return () => { mounted = false; };
  }, []);

  const navItems = [
    { id: 'dashboard',    label: 'Dashboard',     icon: Activity },
    { id: 'devices',      label: 'Network',        icon: Network },
    { id: 'digital-twin', label: 'Digital Twin',   icon: Layers },
    { id: 'threats',      label: 'Threats',        icon: AlertTriangle },
    { id: 'what-if',      label: 'Simulation',     icon: Crosshair },
    { id: 'analytics',    label: 'Analytics',      icon: BarChart3 },
    { id: 'reports',      label: 'Reports',        icon: FileText },
    { id: 'settings',     label: 'Settings',       icon: Settings },
    { id: 'profile',      label: 'Profile',        icon: User },
  ];

  // One notification per new event, avoiding spam
  const unreadAlerts = alerts.filter(a => !readNotifIds.includes(a.id));
  const unreadCount = unreadAlerts.length;

  const handleMarkAllRead = async () => {
    const allIds = alerts.map(a => a.id);
    const updated = Array.from(new Set([...readNotifIds, ...allIds]));
    setReadNotifIds(updated);
    try {
      localStorage.setItem('ng_read_notifs', JSON.stringify(updated));
    } catch (_) {}
    try {
      await api.markAllAlertsRead();
    } catch (_) {}
  };

  const handleMarkSingleRead = async (id, e) => {
    e && e.stopPropagation && e.stopPropagation();
    const updated = Array.from(new Set([...readNotifIds, id]));
    setReadNotifIds(updated);
    try {
      localStorage.setItem('ng_read_notifs', JSON.stringify(updated));
    } catch (_) {}
    try {
      await api.markAlertRead(id);
    } catch (_) {}
  };

  const handleNotificationClick = (alert) => {
    handleMarkSingleRead(alert.id);
    setActiveTab('threats');
    setNotifOpen(false);
  };

  return (
    <header className="ng-navbar">
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 20px' }}>

        {/* TOP ROW: Brand + Actions */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 56, borderBottom: '1px solid #f1f5f9' }}>

          {/* Brand */}
          <button onClick={() => setActiveTab('dashboard')} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
            <div className="ng-nav-logo">
              <Shield size={18} />
            </div>
            <div style={{ textAlign: 'left' }}>
              <div style={{ fontWeight: 800, fontSize: '1.0625rem', color: '#0f172a', letterSpacing: '-0.02em', lineHeight: 1.1 }}>
                NET<span style={{ color: '#2563eb' }}>GUARDIAN</span>
              </div>
              <div style={{ fontSize: '0.675rem', color: '#64748b', display: 'none' }} className="sm-show">
                AI-Powered Network Digital Twin
              </div>
            </div>
            <span className={`ng-mode-badge ${systemMode === 'LIVE' ? 'live' : 'sim'}`} style={{ marginLeft: 4 }}>
              MODE: {systemMode === 'LIVE' ? 'LIVE MONITORING' : 'SIMULATION'}
            </span>
          </button>

          {/* Right actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {/* Demo Mode Button (Task 6) */}
            <button 
              onClick={() => setIsDemoMode(!isDemoMode)} 
              className={isDemoMode ? "btn btn-primary btn-sm" : "btn btn-secondary btn-sm"} 
              style={{ fontWeight: 700 }}
              title="Toggle Presentation Demo Mode (Task 6: larger visuals, hides config, focused presentation)"
            >
              <Tv size={13} />
              <span>{isDemoMode ? 'Demo Mode: ON' : 'Demo Mode'}</span>
            </button>

            {/* Start Demo */}
            <button onClick={onOpenDemo} className="btn btn-warning btn-sm" style={{ fontWeight: 700 }}>
              <Play size={13} fill="#d97706" />
              Start Demo
            </button>

            {/* Help */}
            <button onClick={onOpenOnboarding} className="btn btn-ghost btn-sm" title="Open Tutorial">
              <HelpCircle size={16} color="#64748b" />
            </button>

            {/* Notification bell (Task 9) */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => { setNotifOpen(!notifOpen); setProfileOpen(false); }}
                className="btn btn-ghost btn-sm"
                title="Notifications"
                style={{ position: 'relative', padding: '5px 8px' }}
              >
                <Bell size={16} color="#64748b" />
                {unreadCount > 0 && (
                  <span style={{ position: 'absolute', top: 2, right: 2, width: 16, height: 16, borderRadius: '50%', background: '#dc2626', color: 'white', fontSize: '0.6rem', fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </span>
                )}
              </button>

              {notifOpen && (
                <div style={{ position: 'absolute', right: 0, top: 'calc(100% + 8px)', width: 340, background: 'white', border: '1px solid #e2e8f0', borderRadius: 12, boxShadow: '0 8px 24px rgba(0,0,0,0.12)', zIndex: 100, overflow: 'hidden' }}>
                  {/* Dropdown Header */}
                  <div style={{ padding: '12px 16px', borderBottom: '1px solid #e2e8f0', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#f8fafc' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontWeight: 700, fontSize: '0.875rem', color: '#0f172a' }}>Notifications</span>
                      {unreadCount > 0 && (
                        <span style={{ background: '#fee2e2', color: '#991b1b', fontSize: '0.675rem', fontWeight: 700, padding: '1px 6px', borderRadius: 10 }}>
                          {unreadCount} new
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {unreadCount > 0 && (
                        <button
                          onClick={handleMarkAllRead}
                          className="btn-ghost"
                          style={{ fontSize: '0.725rem', color: '#2563eb', fontWeight: 600, background: 'none', border: 'none', cursor: 'pointer', padding: '2px 4px' }}
                        >
                          Mark all read
                        </button>
                      )}
                      <button onClick={() => setNotifOpen(false)} className="btn-ghost" style={{ padding: 2, border: 'none', background: 'none', cursor: 'pointer' }}>
                        <X size={14} color="#64748b" />
                      </button>
                    </div>
                  </div>

                  {/* Notification List */}
                  <div style={{ maxHeight: 360, overflowY: 'auto' }}>
                    {alerts.length === 0 ? (
                      <div style={{ padding: '24px 16px', textAlign: 'center', color: '#94a3b8', fontSize: '0.8125rem' }}>
                        No notifications yet
                      </div>
                    ) : (
                      alerts.slice(0, 10).map((a) => {
                        const cat = getNotifCategory(a);
                        const isRead = readNotifIds.includes(a.id);
                        return (
                          <div
                            key={a.id}
                            onClick={() => handleNotificationClick(a)}
                            style={{
                              padding: '10px 14px',
                              borderBottom: '1px solid #f1f5f9',
                              cursor: 'pointer',
                              display: 'flex',
                              gap: 10,
                              alignItems: 'flex-start',
                              background: isRead ? '#ffffff' : '#fafafa',
                              opacity: isRead ? 0.75 : 1,
                              transition: 'background 0.12s'
                            }}
                            onMouseEnter={e => e.currentTarget.style.background = '#f1f5f9'}
                            onMouseLeave={e => e.currentTarget.style.background = isRead ? '#ffffff' : '#fafafa'}
                          >
                            <span style={{ fontSize: '0.95rem', marginTop: 1, flexShrink: 0 }}>
                              {cat.icon}
                            </span>

                            <div style={{ flex: 1, minWidth: 0 }}>
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4 }}>
                                <span style={{ fontSize: '0.7rem', fontWeight: 700, color: cat.color, textTransform: 'uppercase' }}>
                                  {cat.label}
                                </span>
                                <span style={{ fontSize: '0.675rem', color: '#94a3b8', whiteSpace: 'nowrap' }}>
                                  {new Date(a.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                </span>
                              </div>

                              <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#0f172a', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: 1 }}>
                                {a.title}
                              </div>

                              <div style={{ fontSize: '0.725rem', color: '#64748b', marginTop: 1 }}>
                                {a.source_ip ? `Host: ${a.source_ip}` : 'Subsystem event'}
                              </div>
                            </div>

                            {!isRead && (
                              <button
                                onClick={(e) => handleMarkSingleRead(a.id, e)}
                                className="btn btn-ghost btn-sm"
                                title="Mark as read"
                                style={{ padding: '3px 6px', fontSize: '0.675rem', color: '#64748b' }}
                              >
                                <Check size={12} />
                              </button>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>

                  {alerts.length > 0 && (
                    <div style={{ padding: '8px 14px', background: '#f8fafc', borderTop: '1px solid #e2e8f0', textAlign: 'center' }}>
                      <button
                        onClick={() => { setActiveTab('threats'); setNotifOpen(false); }}
                        className="btn-ghost"
                        style={{ fontSize: '0.75rem', fontWeight: 600, color: '#2563eb', background: 'none', border: 'none', cursor: 'pointer' }}
                      >
                        View all threats in Threats Page →
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Profile */}
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => { setProfileOpen(!profileOpen); setNotifOpen(false); }}
                style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8, padding: '6px 10px', cursor: 'pointer', transition: 'all 0.12s' }}
              >
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: '#dbeafe', color: '#2563eb', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.8125rem', fontWeight: 700, border: '1.5px solid #bfdbfe', flexShrink: 0 }}>
                  {user?.username?.charAt(0).toUpperCase() || 'U'}
                </div>
                <div style={{ textAlign: 'left' }}>
                  <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#0f172a', lineHeight: 1.2 }}>{user?.username}</div>
                  <div style={{ fontSize: '0.65rem', color: '#2563eb', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.04em' }}>{user?.role}</div>
                </div>
                <ChevronDown size={13} color="#94a3b8" />
              </button>

              {profileOpen && (
                <div style={{ position: 'absolute', right: 0, top: 'calc(100% + 8px)', width: 200, background: 'white', border: '1px solid #e2e8f0', borderRadius: 12, boxShadow: '0 8px 24px rgba(0,0,0,0.12)', zIndex: 100, overflow: 'hidden' }}>
                  <div style={{ padding: '12px 14px', borderBottom: '1px solid #f1f5f9', background: '#f8fafc' }}>
                    <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#0f172a' }}>{user?.username}</div>
                    <div style={{ fontSize: '0.7rem', color: '#2563eb', fontWeight: 700, textTransform: 'uppercase', marginTop: 2 }}>{user?.role} Access</div>
                  </div>
                  <button onClick={() => { setActiveTab('settings'); setProfileOpen(false); }}
                    style={{ width: '100%', textAlign: 'left', padding: '9px 14px', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem', color: '#334155' }}
                    onMouseEnter={e => e.currentTarget.style.background = '#f8fafc'}
                    onMouseLeave={e => e.currentTarget.style.background = 'none'}
                  >
                    <Settings size={14} color="#64748b" /> Settings
                  </button>
                  <button onClick={() => { setActiveTab('profile'); setProfileOpen(false); }}
                    style={{ width: '100%', textAlign: 'left', padding: '9px 14px', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem', color: '#334155' }}
                    onMouseEnter={e => e.currentTarget.style.background = '#f8fafc'}
                    onMouseLeave={e => e.currentTarget.style.background = 'none'}
                  >
                    <User size={14} color="#64748b" /> Profile
                  </button>
                  <div style={{ borderTop: '1px solid #f1f5f9' }}>
                    <button onClick={logout}
                      style={{ width: '100%', textAlign: 'left', padding: '9px 14px', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem', color: '#dc2626' }}
                      onMouseEnter={e => e.currentTarget.style.background = '#fff5f5'}
                      onMouseLeave={e => e.currentTarget.style.background = 'none'}
                    >
                      <LogOut size={14} /> Sign Out
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* NAV ROW (Task 6: hides configuration pages in Demo Mode) */}
        <div style={{ height: 44, display: 'flex', alignItems: 'center' }}>
          <nav className="ng-navlist">
            {(isDemoMode ? navItems.filter(i => i.id !== 'settings' && i.id !== 'profile') : navItems).map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`ng-navitem${isActive ? ' active' : ''}`}
                >
                  <Icon size={14} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>
        </div>
      </div>
    </header>
  );
}
