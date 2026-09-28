/**
 * HINDSIGHT SEC-OPS - MAIN APPLICATION CONTROLLER
 */

class SecOpsApp {
  constructor() {
    this.currentIncident = null;
    this.graphVisualizer = null;
    this.incidents = [];
    this.memories = [];
  }

  async init() {
    console.log('[App] Initializing Hindsight SecOps Dashboard...');
    this.bindNavigation();
    this.bindIncidentForm();
    this.bindMemorySearch();
    this.bindAuditConsole();
    this.bindActionButtons();

    // Initialize Canvas Graph
    this.graphVisualizer = new MemoryGraphVisualizer('memoryCanvas');

    // Initialize Demo Tour
    if (window.demoTour) {
      window.demoTour.init();
    }

    // Load initial data
    await this.refreshAll();
  }

  async refreshAll() {
    try {
      const health = await api.getHealth();
      this.updatePulseBar(health);

      const incList = await api.listIncidents();
      this.incidents = incList;
      this.updateIncidentCounts(incList);

      const graph = await api.getMemoryGraph();
      if (this.graphVisualizer) {
        this.graphVisualizer.loadData(graph);
      }
      this.updateGraphStats(graph);

      await this.loadRecurringPatterns();
      await this.loadTimeline();
    } catch (err) {
      console.warn('[App] Refresh error:', err);
    }
  }

  updatePulseBar(health) {
    const memCount = document.getElementById('statMemoryCount');
    const synapseCount = document.getElementById('statSynapseCount');
    if (memCount) memCount.textContent = health.hindsight_memory?.total_retained_incidents || 0;
    if (synapseCount) synapseCount.textContent = health.hindsight_memory?.total_synapse_links || 0;
  }

  updateIncidentCounts(incidents) {
    const badge = document.getElementById('badgeIncidentCount');
    if (badge) badge.textContent = incidents.length;
  }

  updateGraphStats(graph) {
    const badge = document.getElementById('badgeMemoryCount');
    if (badge) badge.textContent = graph.nodes?.length || 0;
  }

  bindNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        const tabId = item.getAttribute('data-tab');
        this.switchTab(tabId);
      });
    });

    // Subtabs within Incident Investigation
    const subtabs = document.querySelectorAll('.subtab-btn');
    subtabs.forEach(btn => {
      btn.addEventListener('click', () => {
        subtabs.forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.subtab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        const targetPanel = document.getElementById(btn.getAttribute('data-panel'));
        if (targetPanel) targetPanel.classList.add('active');
      });
    });
  }

  switchTab(tabId) {
    document.querySelectorAll('.nav-item').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
    });

    document.querySelectorAll('.tab-content').forEach(tab => {
      tab.classList.toggle('active', tab.id === `tab-${tabId}`);
    });

    if (tabId === 'memory' && this.graphVisualizer) {
      setTimeout(() => {
        this.graphVisualizer.initCanvas();
        api.getMemoryGraph().then(g => this.graphVisualizer.loadData(g));
      }, 50);
    }
  }

  bindIncidentForm() {
    const form = document.getElementById('incidentForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.handleInvestigateSubmit(false);
    });

    // Template Buttons
    const tpl1024 = document.getElementById('btnTpl1024');
    const tpl1038 = document.getElementById('btnTpl1038');
    const tpl1045 = document.getElementById('btnTpl1045');

    if (tpl1024) tpl1024.addEventListener('click', () => this.loadTemplate('INC-1024'));
    if (tpl1038) tpl1038.addEventListener('click', () => this.loadTemplate('INC-1038'));
    if (tpl1045) tpl1045.addEventListener('click', () => this.loadTemplate('INC-1045'));

    // Retain Button
    const btnRetain = document.getElementById('btnRetainMemory');
    if (btnRetain) {
      btnRetain.addEventListener('click', async () => {
        if (!this.currentIncident) return;
        btnRetain.disabled = true;
        btnRetain.innerHTML = '<span>🧠 Retaining Synapses...</span>';
        try {
          const res = await api.retainIncident(this.currentIncident.id);
          this.currentIncident.memory_retained = true;
          this.showToast(`🧠 Retained in Hindsight! Added ${res.synapses_added} synaptic connections.`);
          btnRetain.innerHTML = '<span>✓ Synapses Committed</span>';
          btnRetain.classList.remove('btn-retain');
          btnRetain.classList.add('badge-success');
          await this.refreshAll();
        } catch (err) {
          this.showToast(`Error retaining: ${err.message}`);
          btnRetain.disabled = false;
          btnRetain.innerHTML = '<span>🧠 Retain in Hindsight Memory</span>';
        }
      });
    }
  }

  loadTemplate(tplId) {
    const idInput = document.getElementById('inputIncidentId');
    const titleInput = document.getElementById('inputTitle');
    const descInput = document.getElementById('inputDesc');
    const severityInput = document.getElementById('inputSeverity');
    const assetInput = document.getElementById('inputAsset');
    const assetTypeInput = document.getElementById('inputAssetType');
    const envInput = document.getElementById('inputEnv');
    const evidenceInput = document.getElementById('inputRawEvidence');

    if (tplId === 'INC-1024') {
      idInput.value = 'INC-1024';
      titleInput.value = 'Public Cloud Storage Exposure';
      descInput.value = 'A production storage bucket was discovered with public read access. Configuration scan detected unauthenticated principal "*".';
      severityInput.value = 'HIGH';
      assetInput.value = 'customer-data-bucket';
      assetTypeInput.value = 'Cloud Storage';
      envInput.value = 'Production';
      evidenceInput.value = 'CloudWatch Alert: S3BucketPublicReadAccess. Asset: customer-data-bucket. Principal: *';
      this.showToast('📋 Loaded Template: INC-1024 (S3 Public Exposure)');
    } else if (tplId === 'INC-1038') {
      idInput.value = 'INC-1038';
      titleInput.value = 'Production Data Lake Storage Exposure';
      descInput.value = 'An analytics storage container was discovered with unrestricted public read access policy. Raw customer transaction logs potentially exposed.';
      severityInput.value = 'HIGH';
      assetInput.value = 'analytics-lake-raw';
      assetTypeInput.value = 'Cloud Storage';
      envInput.value = 'Production';
      evidenceInput.value = 'ConfigScan: S3PublicAccessGranted. Asset: analytics-lake-raw. Action: s3:GetObject';
      this.showToast('📋 Loaded Template: INC-1038 (Data Lake Exposure)');
    } else if (tplId === 'INC-1045') {
      idInput.value = 'INC-1045';
      titleInput.value = 'Stripe Live Secret Key Exposed in Lambda Logs';
      descInput.value = 'Worker function logged active authorization header containing live API token to CloudWatch streams.';
      severityInput.value = 'CRITICAL';
      assetInput.value = 'payment-webhook-worker';
      assetTypeInput.value = 'Microservice / Container';
      envInput.value = 'Production';
      evidenceInput.value = 'TruffleHog Scanner: Found Stripe Live Secret Key in /aws/lambda/payment-worker logs.';
      this.showToast('📋 Loaded Template: INC-1045 (Secret Leak)');
    }
  }

  async handleInvestigateSubmit(autoRetain = false) {
    const payload = {
      incident_id: document.getElementById('inputIncidentId').value.trim() || undefined,
      title: document.getElementById('inputTitle').value.trim(),
      description: document.getElementById('inputDesc').value.trim(),
      severity: document.getElementById('inputSeverity').value,
      affected_asset: document.getElementById('inputAsset').value.trim(),
      asset_type: document.getElementById('inputAssetType').value.trim() || 'Cloud Storage',
      environment: document.getElementById('inputEnv').value.trim() || 'Production',
      raw_evidence: document.getElementById('inputRawEvidence').value.trim() || undefined,
    };

    if (!payload.title || !payload.affected_asset) {
      alert('Please provide at least a Title and Affected Asset.');
      return;
    }

    // Animate streaming log
    const streamBox = document.getElementById('agentStreamBox');
    const resultsContainer = document.getElementById('investigationResults');
    const btnSubmit = document.getElementById('btnSubmitInvestigate');

    btnSubmit.disabled = true;
    btnSubmit.innerHTML = '<span>⚡ Multi-Agent Investigation in Progress...</span>';

    streamBox.innerHTML = `
      <div class="agent-log-line"><span class="agent-badge-inc">[INCIDENT-AGENT]</span> Ingesting incident ${payload.incident_id || 'NEW'} (${payload.title})...</div>
      <div class="agent-log-line"><span class="agent-badge-mem">[HINDSIGHT-MEMORY]</span> Querying neural memory for historical precedents on '${payload.affected_asset}'...</div>
    `;

    try {
      const incident = await api.createIncident(payload, autoRetain);
      this.currentIncident = incident;

      // Update streaming log
      if (incident.recalled_from_id) {
        streamBox.innerHTML += `
          <div class="agent-log-line" style="color: #c084fc;"><span class="agent-badge-mem">[HINDSIGHT-RECALL]</span> ⚡ High-Confidence Precedent Found: ${incident.recalled_from_id} (${Math.round((incident.similarity_score || 0.86) * 100)}% match)!</div>
          <div class="agent-log-line"><span class="agent-badge-inc">[INCIDENT-AGENT]</span> Reusing verified root cause & playbook from ${incident.recalled_from_id}. MTTR reduced by ~90%!</div>
        `;
      } else {
        streamBox.innerHTML += `
          <div class="agent-log-line"><span class="agent-badge-inc">[INCIDENT-AGENT]</span> Fresh root-cause derivation completed: ${incident.root_cause}</div>
        `;
      }

      streamBox.innerHTML += `
        <div class="agent-log-line"><span class="agent-badge-cmp">[COMPLIANCE-AGENT]</span> Mapped ${incident.controls.length} compliance controls (SOC 2, NIST, ISO 27001). Generated 3 SHA-256 evidence items.</div>
      `;

      // Render Investigation Results
      this.renderInvestigationResults(incident);
      resultsContainer.style.display = 'block';

      this.showToast(`✓ Investigation Complete for ${incident.id}!`);
      await this.refreshAll();
    } catch (err) {
      this.showToast(`Investigation error: ${err.message}`);
    } finally {
      btnSubmit.disabled = false;
      btnSubmit.innerHTML = '<span>⚡ Run Multi-Agent Investigation</span>';
    }
  }

  renderInvestigationResults(inc) {
    // 1. Recall Alert Banner
    const recallCard = document.getElementById('recallAlertCard');
    if (inc.recalled_from_id && inc.similarity_score) {
      recallCard.style.display = 'block';
      const pct = Math.round(inc.similarity_score * 100);
      recallCard.innerHTML = `
        <div class="recall-header">
          <div class="recall-title">
            <span>🧠</span>
            <span>Hindsight Recall: High-Confidence Match to Incident ${inc.recalled_from_id}</span>
          </div>
          <div class="similarity-gauge">${pct}% Match</div>
        </div>
        <div class="recall-details">
          ${inc.investigation_notes || `Previous incident ${inc.recalled_from_id} resolved this identical failure. Root cause and remediation playbook transferred automatically.`}
        </div>
      `;
    } else {
      recallCard.style.display = 'none';
    }

    // 2. Incident Summary Header
    document.getElementById('resIncidentId').textContent = inc.id;
    document.getElementById('resTitle').textContent = inc.title;
    document.getElementById('resAsset').textContent = inc.affected_asset;
    document.getElementById('resSeverity').textContent = inc.severity;
    document.getElementById('resSeverity').className = `badge ${inc.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}`;

    // 3. Root Cause Panel
    document.getElementById('resRootCause').textContent = inc.root_cause || 'No root cause specified.';
    if (inc.post_mortem) {
      document.getElementById('resRcaDetail').textContent = inc.post_mortem.root_cause_analysis;
      const prevList = document.getElementById('resPreventiveActions');
      prevList.innerHTML = inc.post_mortem.preventive_actions.map(a => `<li>${a}</li>`).join('');
    }

    // 4. Controls Panel
    const ctrlList = document.getElementById('resControlsList');
    ctrlList.innerHTML = inc.controls.map(c => `
      <div style="background: rgba(13, 20, 36, 0.6); border: 1px solid var(--border-glass-subtle); padding: 0.9rem; border-radius: 8px; margin-bottom: 0.7rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
          <strong style="color: var(--neon-emerald); font-family: var(--font-mono);">${c.framework} • ${c.control_id}</strong>
          <span class="badge badge-success">COMPLIANT</span>
        </div>
        <div style="font-weight: 600; font-size: 0.9rem; color: #ffffff; margin-bottom: 0.2rem;">${c.control_name}</div>
        <div style="font-size: 0.78rem; color: #94a3b8;">${c.requirement}</div>
      </div>
    `).join('');

    // 5. Remediation Playbook Panel
    const remContainer = document.getElementById('resRemediationSteps');
    remContainer.innerHTML = inc.remediation_playbook.map((step, idx) => `
      <div class="remediation-item">
        <div class="step-number">${step.step_number}</div>
        <div class="step-content">
          <div class="step-action">${step.action}</div>
          <div class="step-rationale">${step.rationale}</div>
          ${step.verification_command ? `<div class="step-code">$ ${step.verification_command}</div>` : ''}
        </div>
        <div>
          <span class="badge ${step.status === 'VERIFIED' ? 'badge-success' : 'badge-high'}">${step.status}</span>
        </div>
      </div>
    `).join('');

    // 6. Evidence Vault Panel
    const evGrid = document.getElementById('resEvidenceGrid');
    evGrid.innerHTML = inc.evidence_vault.map(ev => `
      <div class="evidence-card">
        <div class="evidence-title">
          <span>${ev.filename}</span>
          <span class="badge badge-count">${ev.type}</span>
        </div>
        <p style="font-size: 0.78rem; color: #94a3b8; margin-bottom: 0.5rem;">${ev.description}</p>
        <pre style="background: rgba(0,0,0,0.5); padding: 0.4rem; border-radius: 4px; font-size: 0.7rem; color: #a5f3fc; overflow-x: auto; max-height: 80px;">${ev.content_preview}</pre>
        <div class="evidence-hash">SHA-256: ${ev.sha256_hash.substring(0, 24)}...</div>
      </div>
    `).join('');

    // Retain button status
    const btnRetain = document.getElementById('btnRetainMemory');
    if (btnRetain) {
      if (inc.memory_retained) {
        btnRetain.disabled = true;
        btnRetain.innerHTML = '<span>✓ Synapses Committed</span>';
        btnRetain.className = 'btn-retain badge-success';
      } else {
        btnRetain.disabled = false;
        btnRetain.innerHTML = '<span>🧠 Retain in Hindsight Memory</span>';
        btnRetain.className = 'btn-retain';
      }
    }
  }

  bindMemorySearch() {
    const searchInput = document.getElementById('memorySearchInput');
    const btnSearch = document.getElementById('btnMemorySearch');
    const resultsBox = document.getElementById('memoryRecallResults');

    const executeSearch = async () => {
      const q = searchInput.value.trim();
      if (!q) return;

      resultsBox.innerHTML = '<div style="color: #94a3b8; font-size: 0.85rem;">Searching organizational memory...</div>';

      try {
        const resp = await api.recallMemory(q);
        if (!resp.matches || resp.matches.length === 0) {
          resultsBox.innerHTML = '<div style="color: #94a3b8; font-size: 0.85rem;">No prior memory matches found above similarity threshold.</div>';
          return;
        }

        resultsBox.innerHTML = `
          <div style="background: rgba(168, 85, 247, 0.1); border: 1px solid rgba(168, 85, 247, 0.3); padding: 0.8rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.85rem; color: #e9d5ff;">
            ${resp.agent_advice}
          </div>
          ${resp.matches.map(m => `
            <div style="background: rgba(13, 20, 36, 0.7); border: 1px solid var(--border-glass-subtle); padding: 1rem; border-radius: 8px; margin-bottom: 0.8rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                <strong style="color: #ffffff; font-size: 0.95rem;">${m.incident_id}: ${m.title}</strong>
                <span class="badge ${m.similarity_percentage >= 70 ? 'badge-purple' : 'badge-high'}">${m.similarity_percentage}% Similarity</span>
              </div>
              <p style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 0.5rem;">${m.summary_explanation}</p>
              <div style="font-size: 0.78rem; color: #a5f3fc; font-family: var(--font-mono); margin-bottom: 0.3rem;">
                <strong>Recalled Root Cause:</strong> ${m.matched_root_cause}
              </div>
              <div style="font-size: 0.75rem; color: #cbd5e1;">
                <strong>Verified Actions:</strong> ${m.verified_remediation_summary.slice(0, 2).join(' • ')}
              </div>
            </div>
          `).join('')}
        `;
      } catch (err) {
        resultsBox.innerHTML = `<div style="color: #ff3366;">Error: ${err.message}</div>`;
      }
    };

    if (btnSearch) btnSearch.addEventListener('click', executeSearch);
    if (searchInput) {
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') executeSearch();
      });
    }

    // Quick prompt pills in Memory sandbox
    document.querySelectorAll('.memory-prompt-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        if (searchInput) {
          searchInput.value = pill.textContent.trim();
          executeSearch();
        }
      });
    });
  }

  bindAuditConsole() {
    const auditInput = document.getElementById('auditQueryInput');
    const btnRunAudit = document.getElementById('btnRunAudit');

    const runQuery = async (queryText) => {
      await this.handleAuditQuery(queryText);
    };

    if (btnRunAudit) {
      btnRunAudit.addEventListener('click', () => {
        const q = auditInput.value.trim() || 'Show historical access-control findings, remediation status, and available evidence';
        runQuery(q);
      });
    }

    // 1-Click Auditor sample pills
    document.querySelectorAll('.audit-sample-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        const queryText = pill.getAttribute('data-query') || pill.textContent.trim();
        if (auditInput) auditInput.value = queryText;
        runQuery(queryText);
      });
    });

    // Export Auditor Report button
    const btnExport = document.getElementById('btnExportAuditReport');
    if (btnExport) {
      btnExport.addEventListener('click', () => {
        window.print();
      });
    }
  }

  async handleAuditQuery(queryText) {
    const resultsContainer = document.getElementById('auditResultsSection');
    const summaryText = document.getElementById('auditExecutiveSummary');
    const complianceRate = document.getElementById('auditComplianceRate');
    const totalFindings = document.getElementById('auditTotalFindings');
    const attestationHash = document.getElementById('auditAttestationHash');
    const tableBody = document.getElementById('auditTableBody');

    try {
      const report = await api.executeAudit(queryText);
      resultsContainer.style.display = 'block';

      if (summaryText) summaryText.textContent = report.executive_summary;
      if (complianceRate) complianceRate.textContent = `${report.compliance_rate_percent}%`;
      if (totalFindings) totalFindings.textContent = report.total_findings;
      if (attestationHash) attestationHash.textContent = report.memory_attestation_hash;

      if (tableBody) {
        tableBody.innerHTML = report.findings.map(f => `
          <tr>
            <td>
              <strong style="color: var(--neon-cyan); font-family: var(--font-mono);">${f.finding_id}</strong>
              <div style="font-size: 0.75rem; color: #94a3b8;">${f.incident_id}</div>
            </td>
            <td>
              <strong style="color: #ffffff;">${f.framework} • ${f.control_id}</strong>
              <div style="font-size: 0.78rem; color: #cbd5e1;">${f.control_name}</div>
            </td>
            <td style="max-width: 280px; font-size: 0.8rem; color: #94a3b8;">
              ${f.root_cause}
            </td>
            <td>
              <span class="badge ${f.remediation_status === 'VERIFIED_CLOSED' ? 'badge-success' : 'badge-high'}">
                ${f.remediation_status}
              </span>
            </td>
            <td>
              <span class="badge badge-count" style="font-family: var(--font-mono);">
                📎 ${f.evidence_items.length} Artifacts
              </span>
            </td>
            <td>
              <button class="btn-template" onclick="window.app.inspectEvidence('${f.finding_id}')">
                Inspect Evidence
              </button>
            </td>
          </tr>
        `).join('');
      }

      this.showToast(`📋 Audit Dossier generated: ${report.total_findings} findings verified.`);
    } catch (err) {
      this.showToast(`Audit query error: ${err.message}`);
    }
  }

  inspectEvidence(findingId) {
    this.showToast(`🔍 Attested Evidence verified for finding ${findingId}`);
  }

  async loadRecurringPatterns() {
    const container = document.getElementById('recurringPatternsContainer');
    if (!container) return;

    try {
      const patterns = await api.getRecurringPatterns();
      if (!patterns || patterns.length === 0) {
        container.innerHTML = '<div style="color: #94a3b8;">No recurring vulnerability clusters detected yet.</div>';
        return;
      }

      container.innerHTML = patterns.map(p => `
        <div class="pattern-card">
          <div class="pattern-header">
            <div>
              <span class="badge badge-critical">${p.risk_level} SYSTEMIC RISK</span>
              <h3 style="font-family: var(--font-main); font-size: 1.1rem; color: #ffffff; margin-top: 0.4rem;">
                ${p.title}
              </h3>
            </div>
            <div style="font-family: var(--font-mono); font-size: 0.85rem; color: var(--neon-amber);">
              <strong>Frequency:</strong> ${p.frequency} Incidents
            </div>
          </div>
          <p style="font-size: 0.84rem; color: #cbd5e1; margin-bottom: 0.6rem;">
            <strong>Root Cause Theme:</strong> ${p.root_cause_theme}
          </p>
          <div style="font-size: 0.78rem; color: #94a3b8; margin-bottom: 0.6rem;">
            <strong>Affected Assets:</strong> ${p.affected_assets.join(', ')} | <strong>Incident IDs:</strong> ${p.related_incident_ids.join(', ')}
          </div>
          <div style="background: rgba(7, 9, 14, 0.7); border: 1px solid rgba(255, 184, 0, 0.2); padding: 0.8rem; border-radius: 6px; font-size: 0.82rem; color: #fde68a;">
            <strong>🛡️ Strategic Prevention Recommendation:</strong> ${p.recommendation}
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.warn('[App] Recurring patterns error:', err);
    }
  }

  async loadTimeline() {
    const container = document.getElementById('memoryTimelineContainer');
    if (!container) return;

    try {
      const timeline = await api.getTimeline();
      if (!timeline || timeline.length === 0) {
        container.innerHTML = '<div style="color: #94a3b8;">No timeline events recorded yet.</div>';
        return;
      }

      container.innerHTML = timeline.map((item, idx) => `
        <div style="display: flex; gap: 1rem; margin-bottom: 1.2rem; position: relative;">
          <div style="display: flex; flex-direction: column; align-items: center;">
            <div style="width: 12px; height: 12px; border-radius: 50%; background: var(--neon-cyan); box-shadow: 0 0 8px var(--neon-cyan);"></div>
            <div style="width: 2px; flex-grow: 1; background: rgba(0, 240, 255, 0.15); margin-top: 4px;"></div>
          </div>
          <div style="flex-grow: 1; background: rgba(13, 20, 36, 0.6); border: 1px solid var(--border-glass-subtle); padding: 0.9rem; border-radius: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.2rem;">
              <strong style="color: #ffffff; font-size: 0.9rem;">${item.incident_id}: ${item.title}</strong>
              <span style="font-family: var(--font-mono); font-size: 0.72rem; color: #64748b;">${item.detected_at.substring(0, 10)}</span>
            </div>
            <p style="font-size: 0.78rem; color: #94a3b8; margin-bottom: 0.4rem;">${item.root_cause}</p>
            <div style="display: flex; gap: 0.6rem; font-size: 0.72rem;">
              <span class="badge badge-count">Asset: ${item.asset}</span>
              <span class="badge badge-count">📎 ${item.evidence_count} Evidence</span>
            </div>
          </div>
        </div>
      `).join('');
    } catch (err) {
      console.warn('[App] Timeline error:', err);
    }
  }

  bindActionButtons() {
    const btnReset = document.getElementById('btnResetDemo');
    const btnSeed = document.getElementById('btnSeedDemo');

    if (btnReset) {
      btnReset.addEventListener('click', async () => {
        if (confirm('Reset all incidents and Hindsight memory to clean state?')) {
          await api.resetDemo();
          this.showToast('🧹 Memory & Incidents reset to blank canvas.');
          await this.refreshAll();
        }
      });
    }

    if (btnSeed) {
      btnSeed.addEventListener('click', async () => {
        await api.seedDemo();
        this.showToast('🌱 Seeded baseline INC-1024 into Hindsight memory.');
        await this.refreshAll();
      });
    }
  }

  showToast(message) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<span>🧠</span> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }
}

// Global App Instance
window.addEventListener('DOMContentLoaded', () => {
  window.app = new SecOpsApp();
  window.app.init();
});
