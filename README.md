# 🧠 Hindsight SecOps & Compliance Memory Agent
> **Turning Security Incidents into Persistent Organizational Memory**  
> *Built for Hackathon Excellence • The Memory Loop is the Product 🛡️*

[![DevSecOps](https://img.shields.io/badge/DevSecOps-Certified-00ff88?style=flat-square&logo=shield)](https://github.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.128-00f0ff?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)](https://python.org)
[![Compliance](https://img.shields.io/badge/Compliance-SOC2%20%7C%20NIST%20%7C%20ISO27001-a855f7?style=flat-square)](https://csrc.nist.gov)

---

## 🎯 The Core Problem

Security engineers investigate incidents every day, but the hard-won insights — root causes, affected controls, remediations, evidence, and post-mortems — get buried in ticket trackers and chat history. When a similar incident strikes later, engineers start from scratch.

**Without Organizational Memory:**
> *"Investigate the current incident from zero."*

**With Hindsight Organizational Memory:**
> *"This incident resembles Incident #1024. Here is the verified root cause, the proven remediation playbook, and the cryptographic evidence collected previously."*

---

## 🚀 Key Features

1. **Incident Ingestion & Automated AI Triage**: Rapid symptom extraction, severity scoring, and environment tagging.
2. **First-Principles & Precedent Root Cause Analysis**: Identifies misconfigurations, privilege leaks, and exposure vectors.
3. **Semantic Precedent Recall**: Automatically correlates incoming alerts against organizational memory using semantic vectors and SecOps ontology.
4. **Automated Control Mapping**: Maps findings to SOC 2 Type II (CC6.1, CC6.3, CC7.2), NIST CSF 2.0 (PR.AC-3, RS.RP-1), and ISO/IEC 27001 (A.9, A.16).
5. **Verified Remediation Playbooks**: Step-by-step actions with copyable CLI containment commands and verification steps.
6. **Cryptographic Evidence Vault**: Captures configuration snapshots and audit logs with SHA-256 integrity hashes for defensibility.
7. **Interactive Synaptic Knowledge Graph**: HTML5 Canvas physics network visualization showing floating memory nodes (Incidents, Controls, Root Causes, Playbooks, Evidence).
8. **Recurring Risk Intelligence**: Detects systemic blind spots across infrastructure (e.g. repeated public storage policies).
9. **Natural Language Compliance & Audit Vault**: Auditors query organizational memory in plain English; the system returns attested evidence packages in seconds.
10. **1-Click Guided Hackathon Demo Tour**: An automated guided storyteller mode built right into the UI for foolproof judge presentations.

---

## 👥 5-Member Team Workstreams

| Member | Workstream | Key Responsibilities & Delivered Modules |
| :--- | :--- | :--- |
| **Member 1** | **Security Investigation** | `incident_agent.py` — Ingestion, automated root cause derivation, severity triage, post-mortem generation |
| **Member 2** | **Hindsight / Memory** | `hindsight_engine.py`, `hindsight_agent.py` — Vector embeddings, semantic recall, synaptic graph, memory retention |
| **Member 3** | **Compliance & Audit** | `compliance_agent.py`, `models/audit.py` — Control mappings (SOC 2, NIST, ISO), evidence hash verification, audit queries |
| **Member 4** | **Frontend / UX** | `frontend/` — Cyber dark glassmorphism dashboard, Canvas memory graph, live stream telemetry, printable reports |
| **Member 5** | **Integration & DevSecOps** | `orchestrator.py`, `Dockerfile`, `security_scan.py`, `.github/workflows/` — Multi-agent mesh, CI/CD, SAST, secret scanner |

---

## ⚡ Quickstart Guide

### 1. Run Locally (FastAPI + Embedded Web Dashboard)

No complex setup needed — python and dependencies run turnkey out of the box:

```bash
# Navigate to project directory
cd "C:\Users\GOLI AKASH\.gemini\antigravity-ide\scratch\hindsight-secops"

# Launch backend server & dashboard
python backend/run.py
```

Then open your browser at:
👉 **`http://localhost:8000`**

*(Swagger API Documentation available at: `http://localhost:8000/docs`)*

---

### 2. Run DevSecOps Pipeline Checks
Verify SAST, secret detection, and dependency integrity:

```bash
python devsecops/security_scan.py
```

---

### 3. Run with Docker

```bash
cd devsecops
docker-compose up --build
```

---

## 🎬 Live Hackathon Demo Walkthrough

Click the glowing **"▶ Run Hackathon Demo Story"** button on the top-right of the dashboard, or follow the 5-step narrative:

1. **Step 1: Ingest Incident #1024 (S3 Public Storage Exposure)**
   - Click `Load #1024` and hit `⚡ Run Multi-Agent Investigation`.
   - AI derives the root cause (*incorrect access policy*), maps SOC 2 CC6.1, and constructs a 4-step verified playbook.
2. **Step 2: Retain into Hindsight Memory**
   - Click `🧠 Retain in Hindsight Memory`. The knowledge becomes permanent organizational memory.
3. **Step 3: Ingest Similar Incident #1038 (Data Lake Exposure)**
   - Click `Load #1038` and hit `⚡ Run Multi-Agent Investigation`.
   - **The Hackathon Highlight:** Hindsight immediately displays a glowing **Recall Alert (86%+ Match to #1024)**, transferring the previous root cause and playbook in under 1 second!
4. **Step 4: Auditor Query in Natural Language**
   - Open the **Compliance & Audit** tab.
   - Run: *"Show historical access-control findings, remediation status, and available evidence"*.
   - Instant compliance dossier generated with SHA-256 evidence hashes and 100% remediation score.
5. **Step 5: Recurring Vulnerability Detection**
   - Open **Recurring Risks** tab to see Hindsight's proactive alert warning about repeated cloud storage misconfigurations across assets.

---

## 📁 Repository Structure

```
hindsight-secops/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI server & static SPA mount
│   │   ├── config.py                  # Storage paths & configuration
│   │   ├── models/                    # Pydantic schemas (Incident, Memory, Audit)
│   │   ├── agents/                    # Multi-agent mesh (Incident, Compliance, Hindsight, Orchestrator)
│   │   ├── memory/                    # Hindsight semantic vector engine & graph store
│   │   └── seed_data.py               # Baseline realistic incidents (#1024, etc.)
│   ├── data/                          # Persistent JSON memory store
│   ├── requirements.txt               # Dependencies
│   └── run.py                         # Single-command launcher
├── frontend/
│   ├── index.html                     # Cyber dark glassmorphism dashboard
│   ├── css/style.css                  # Custom design tokens, neon glows, animations
│   └── js/
│       ├── app.js                     # Main application logic
│       ├── api.js                     # REST API client
│       ├── memoryGraph.js             # Canvas physics-based synaptic graph
│       └── demoTour.js                # 1-Click guided hackathon story player
├── devsecops/
│   ├── Dockerfile                     # Non-root secure container
│   ├── docker-compose.yml             # Container orchestration
│   └── security_scan.py               # Automated SAST & secret scanner
├── docs/
│   ├── ARCHITECTURE.md                # System design & memory internals
│   ├── HACKATHON_PITCH.md             # 3-minute pitch deck & Q&A guide
│   └── DEMO_STORY.md                  # Step-by-step presentation script
└── README.md
```

---

## 🏆 The Thesis Proven

> «Can an AI agent turn previous security incidents into persistent organizational memory and use that memory to improve future incident response and audit readiness?»

**Yes.** Hindsight proves that organizational memory is the missing link in modern cybersecurity operations. 🧠🛡️
