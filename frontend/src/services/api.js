const BASE_URL = '/api';

function getCookie(name) {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[2]) : null;
}

function getCsrfHeader() {
  const csrf = getCookie('ng_csrf') || (typeof sessionStorage !== 'undefined' ? sessionStorage.getItem('ng_csrf') : null);
  return csrf ? { 'X-CSRF-Token': csrf } : {};
}

async function handleResponse(response) {
  if (!response.ok) {
    let errorDetail = 'Network response was not ok';
    try {
      const err = await response.json();
      errorDetail = err.detail || err.message || errorDetail;
    } catch (_) {}
    throw new Error(errorDetail);
  }
  return response.json();
}

async function request(endpoint, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = {
    Accept: 'application/json',
    ...(options.headers || {})
  };

  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfHeaders = getCsrfHeader();
    Object.assign(headers, csrfHeaders);
  }

  const response = await fetch(`${BASE_URL}${endpoint}`, {
    ...options,
    method,
    headers,
    credentials: 'include',
  });
  return handleResponse(response);
}

export const api = {
  // Authentication
  async login(username, password) {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });
    const data = await handleResponse(res);
    if (data.csrf_token && typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem('ng_csrf', data.csrf_token);
    }
    return data;
  },

  async logout() {
    try {
      await request('/auth/logout', { method: 'POST' });
    } catch (_) {}
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem('ng_csrf');
    }
  },

  async getCurrentUser() {
    return request('/auth/me');
  },

  // Dashboard
  async getDashboardSummary() {
    return request('/dashboard');
  },

  // Devices
  async getDevices(params = {}) {
    const query = new URLSearchParams(params).toString();
    return request(`/devices${query ? `?${query}` : ''}`);
  },

  async getDevice(id) {
    return request(`/devices/${id}`);
  },

  async getDeviceRiskBreakdown(id) {
    return request(`/devices/${id}/risk-breakdown`);
  },

  async createDevice(deviceData) {
    return request('/devices', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(deviceData)
    });
  },

  async updateDevice(id, updateData) {
    return request(`/devices/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updateData)
    });
  },

  // Digital Twin
  async getDigitalTwinTopology() {
    return request('/digital-twin/topology');
  },

  async syncDigitalTwin() {
    return request('/digital-twin/sync', { method: 'POST' });
  },

  // What-If Simulation
  async runWhatIfSimulation(targetDeviceId, scenario = "COMPROMISED_HOST") {
    return request('/simulation/what-if', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_device_id: targetDeviceId, scenario })
    });
  },

  async isolateDevice(targetDeviceId, reason = "Manual isolation triggered") {
    return request('/simulation/isolate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_device_id: targetDeviceId, reason })
    });
  },

  async restoreDevice(targetDeviceId) {
    return request(`/simulation/restore/${targetDeviceId}`, { method: 'POST' });
  },

  async getSimulationRuns() {
    return request('/simulation/runs');
  },

  async getSimulationHistory() {
    return request('/simulation/history');
  },

  async triggerSecurityEvent(eventType, sourceIp, targetIp = null) {
    return request('/simulation/trigger-event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        event_type: eventType,
        source_ip: sourceIp,
        target_ip: targetIp || null
      })
    });
  },

  // Demo Guided Walkthrough
  async stepDemo(stepNumber) {
    return request('/simulation/demo/step', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ step_number: stepNumber })
    });
  },

  async resetDemo() {
    return request('/simulation/demo/reset', { method: 'POST' });
  },

  // Traffic
  async getTraffic(limit = 50, anomaliesOnly = false) {
    return request(`/traffic?limit=${limit}&anomalies_only=${anomaliesOnly}`);
  },

  async pulseTraffic(count = 5) {
    return request(`/traffic/pulse?count=${count}`, { method: 'POST' });
  },

  async pauseTraffic() {
    return request('/traffic/pause', { method: 'POST' });
  },

  async resumeTraffic() {
    return request('/traffic/resume', { method: 'POST' });
  },

  async stepTraffic(count = 5) {
    return request(`/traffic/step?count=${count}`, { method: 'POST' });
  },

  async getTrafficControl() {
    return request('/traffic/control');
  },

  async getTrafficStats() {
    return request('/traffic/stats');
  },

  // Alerts & Threats
  async getAlerts(params = {}) {
    const query = new URLSearchParams(params).toString();
    return request(`/alerts${query ? `?${query}` : ''}`);
  },

  async updateAlertStatus(id, status) {
    return request(`/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
  },

  async getReadAlerts() {
    return request('/alerts/read-state');
  },

  async markAlertRead(alertId) {
    return request('/alerts/read-state', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_id: alertId })
    });
  },

  async markAllAlertsRead() {
    return request('/alerts/read-all', {
      method: 'POST'
    });
  },

  // Analytics
  async getAnalytics(params = {}) {
    const query = new URLSearchParams(params).toString();
    return request(`/analytics${query ? `?${query}` : ''}`);
  },

  // Reports
  async getReportSummary(params = {}) {
    const query = new URLSearchParams(params).toString();
    return request(`/reports/summary${query ? `?${query}` : ''}`);
  },

  getReportPdfUrl(params = {}) {
    const query = new URLSearchParams(params).toString();
    return `${BASE_URL}/reports/export-pdf${query ? `?${query}` : ''}`;
  },

  getReportHtmlUrl(params = {}) {
    const query = new URLSearchParams(params).toString();
    return `${BASE_URL}/reports/export-html${query ? `?${query}` : ''}`;
  },

  // Settings & System
  async getSettings() {
    return request('/settings');
  },

  async updateSettings(settingsData) {
    return request('/settings', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settingsData)
    });
  },

  async getSystemStatus() {
    return request('/settings/status');
  },

  async getAiModelInfo() {
    return request('/settings/ai-model-info');
  },

  // Live Packet Collector (Phase 7B)
  async getCollectorStatus() {
    return request('/collector/status');
  },

  async toggleLiveMode(enabled, consentGranted = false) {
    return request('/collector/live-toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, consent_granted: consentGranted })
    });
  },

  async injectPacket(packetData) {
    return request('/collector/inject-packet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(packetData)
    });
  }
};
