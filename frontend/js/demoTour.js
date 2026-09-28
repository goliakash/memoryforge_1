/**
 * HINDSIGHT SEC-OPS - GUIDED HACKATHON DEMO TOUR
 * 1-Click Storyteller executing the exact 5-step judge demonstration
 */

class HackathonDemoTour {
  constructor() {
    this.currentStep = 0;
    this.totalSteps = 5;
    this.overlay = null;
    this.isPlaying = false;
  }

  init() {
    this.overlay = document.getElementById('demoModalOverlay');
    const startBtn = document.getElementById('btnStartDemoTour');
    const closeBtn = document.getElementById('btnDemoClose');
    const nextBtn = document.getElementById('btnDemoNext');
    const prevBtn = document.getElementById('btnDemoPrev');

    if (startBtn) startBtn.addEventListener('click', () => this.startTour());
    if (closeBtn) closeBtn.addEventListener('click', () => this.stopTour());
    if (nextBtn) nextBtn.addEventListener('click', () => this.advanceStep());
    if (prevBtn) prevBtn.addEventListener('click', () => this.regressStep());
  }

  startTour() {
    this.currentStep = 1;
    this.showModal();
    this.renderStep();
  }

  stopTour() {
    if (this.overlay) this.overlay.classList.remove('active');
  }

  showModal() {
    if (this.overlay) this.overlay.classList.add('active');
  }

  advanceStep() {
    if (this.currentStep < this.totalSteps) {
      this.currentStep++;
      this.renderStep();
    } else {
      this.stopTour();
      window.app.showToast('🎉 Hackathon Demo Story Complete! The Memory Loop is proven.');
    }
  }

  regressStep() {
    if (this.currentStep > 1) {
      this.currentStep--;
      this.renderStep();
    }
  }

  async renderStep() {
    const badge = document.getElementById('demoStepBadge');
    const title = document.getElementById('demoTitle');
    const desc = document.getElementById('demoDesc');
    const nextBtn = document.getElementById('demoNextText');
    const progressContainer = document.getElementById('demoProgressDots');

    // Update Progress Dots
    if (progressContainer) {
      progressContainer.innerHTML = Array.from({ length: this.totalSteps }, (_, i) => 
        `<div class="demo-progress-dot ${i + 1 <= this.currentStep ? 'active' : ''}"></div>`
      ).join('');
    }

    switch (this.currentStep) {
      case 1:
        badge.textContent = 'STEP 1 OF 5 • FIRST INCIDENT';
        title.textContent = 'Incident #1024 Occurs (S3 Public Exposure)';
        desc.textContent = 
          'A production bucket "customer-data-bucket" was detected with public read access. ' +
          'Our AI Incident Agent performs automated root-cause analysis, maps SOC 2 CC6.1 & NIST PR.AC-3 controls, ' +
          'and synthesizes a 4-step verified remediation playbook.';
        nextBtn.textContent = 'Execute Investigation & Continue ➔';
        
        // Execute Action in UI
        window.app.loadTemplate('INC-1024');
        window.app.switchTab('studio');
        break;

      case 2:
        badge.textContent = 'STEP 2 OF 5 • MEMORY RETENTION';
        title.textContent = 'Commit Learnings to Hindsight Memory 🧠';
        desc.textContent = 
          'Rather than losing this knowledge in closed Jira tickets or chat logs, ' +
          'Hindsight deconstructs the post-mortem into interconnected semantic memory nodes: ' +
          'Incident, Root Cause, Control, Remediation, and Cryptographic Evidence. Watch the neural synapses connect!';
        nextBtn.textContent = 'Retain in Hindsight & Continue ➔';

        // Trigger Investigation and Retain in UI
        await window.app.handleInvestigateSubmit(true);
        window.app.showToast('🧠 INC-1024 committed to persistent organizational memory!');
        break;

      case 3:
        badge.textContent = 'STEP 3 OF 5 • RECURRING INCIDENT & RECALL';
        title.textContent = 'Incident #1038 Occurs: Instant Memory Recall! ⚡';
        desc.textContent = 
          'Later, an analytics storage container "analytics-lake-raw" suffers an unrestricted access policy. ' +
          'Instead of investigating from scratch, Hindsight IMMEDIATELY recalls Incident #1024 with 86%+ similarity! ' +
          'The engineer is handed the proven root cause and verified playbook instantly.';
        nextBtn.textContent = 'Investigate with Recall ➔';

        // Load INC-1038 and run investigation
        window.app.loadTemplate('INC-1038');
        window.app.switchTab('studio');
        await window.app.handleInvestigateSubmit(false);
        break;

      case 4:
        badge.textContent = 'STEP 4 OF 5 • COMPLIANCE AUDIT READY';
        title.textContent = 'Auditor Asks: "Show Access Control Evidence" 👨⚖️';
        desc.textContent = 
          'During an annual SOC 2 or ISO 27001 audit, the auditor requests: ' +
          '"Show historical access-control findings, remediation status, and available evidence." ' +
          'The Compliance Agent queries Hindsight memory and produces defensible evidence, SHA-256 hashes, and verified remediation in 2 seconds.';
        nextBtn.textContent = 'Run Auditor Query ➔';

        // Switch to Compliance Tab and query
        window.app.switchTab('compliance');
        await window.app.handleAuditQuery('Show historical access-control findings, remediation status, and available evidence');
        break;

      case 5:
        badge.textContent = 'STEP 5 OF 5 • ORGANIZATIONAL INTELLIGENCE';
        title.textContent = 'The Memory Loop is Complete! 🧠🛡️';
        desc.textContent = 
          'We have proven the thesis: AI organizational memory turns isolated incidents into permanent institutional wisdom. ' +
          'Hindsight not only accelerates MTTR for future responders, but detects recurring vulnerabilities across infrastructure ' +
          'and maintains audit readiness 365 days a year without manual spreadsheets.';
        nextBtn.textContent = 'Explore Memory Brain ➔';

        window.app.switchTab('memory');
        break;
    }
  }
}

window.demoTour = new HackathonDemoTour();
