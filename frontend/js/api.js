/**
 * HINDSIGHT SEC-OPS - API CLIENT
 */

const API_BASE = window.location.origin.includes(':8000') || window.location.origin.includes('localhost') 
  ? '/api' 
  : '/api';

class ApiClient {
  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    try {
      const response = await fetch(url, { ...options, headers });
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || `Request failed with status ${response.status}`);
      }
      return await response.json();
    } catch (err) {
      console.error(`[API] Error on ${endpoint}:`, err);
      throw err;
    }
  }

  // Health
  getHealth() {
    return this.request('/health');
  }

  // Incidents
  listIncidents() {
    return this.request('/incidents');
  }

  getIncident(id) {
    return this.request(`/incidents/${id}`);
  }

  createIncident(payload, autoRetain = false) {
    return this.request(`/incidents?auto_retain=${autoRetain}`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  retainIncident(id) {
    return this.request(`/incidents/${id}/retain`, {
      method: 'POST',
    });
  }

  updateRemediationStep(incidentId, stepId, status = 'VERIFIED') {
    return this.request(`/incidents/${incidentId}/remediation/${stepId}/status?status=${status}`, {
      method: 'POST',
    });
  }

  // Hindsight Memory
  recallMemory(queryText, controlFilter = null) {
    return this.request('/memory/recall', {
      method: 'POST',
      body: JSON.stringify({
        text: queryText,
        control_filter: controlFilter,
        top_k: 4,
        min_similarity: 0.35,
      }),
    });
  }

  getMemoryGraph() {
    return this.request('/memory/graph');
  }

  getTimeline() {
    return this.request('/memory/timeline');
  }

  getRecurringPatterns() {
    return this.request('/intelligence/recurring');
  }

  // Compliance & Audit
  executeAudit(queryText, controlDomain = 'Access Control', framework = 'ALL') {
    return this.request('/compliance/audit', {
      method: 'POST',
      body: JSON.stringify({
        query: queryText,
        control_domain: controlDomain,
        framework: framework,
      }),
    });
  }

  // Demo utilities
  seedDemo() {
    return this.request('/demo/seed', { method: 'POST' });
  }

  resetDemo() {
    return this.request('/demo/reset', { method: 'POST' });
  }
}

const api = new ApiClient();
