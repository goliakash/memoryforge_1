# 🏗️ Hindsight SecOps & Compliance Memory Agent — Architecture

## 🧠 System Philosophy
Traditional security operations tools treat every incident as an isolated ticket. Post-mortems and root-cause findings get buried in Notion, Jira, or Google Docs. When a similar incident strikes 3 months later, on-call engineers investigate from scratch, repeating mistakes and re-discovering the same solutions.

**Hindsight turns security investigations into persistent organizational memory.**

```
Security Incident
       ↓
Multi-Agent Investigation (Incident Agent + Compliance Agent)
       ↓
Root Cause + Controls + Remediation + Cryptographic Evidence
       ↓
Post-Mortem Synthesis
       ↓
HINDSIGHT ORGANIZATIONAL MEMORY 🧠
       ↓
Future Incident (Semantic Recall)  ←→  Audit Request (Defensible Evidence)
       ↓                                       ↓
Accelerated MTTR (~90% faster)        Zero-Touch Audit Readiness
```

---

## 🏛️ Multi-Agent Architecture

```
                    ┌─────────────────────────┐
                    │      USER / AUDITOR     │
                    └────────────┬────────────┘
                                 │
                   ┌─────────────▼─────────────┐
                   │ Cyber SOC Dashboard (SPA) │
                   └─────────────┬─────────────┘
                                 │ HTTP / JSON
                   ┌─────────────▼─────────────┐
                   │     FastAPI Gateway       │
                   └─────────────┬─────────────┘
                                 │
                   ┌─────────────▼─────────────┐
                   │     Agent Orchestrator    │
                   └──────┬──────┬──────┬──────┘
                          │      │      │
          ┌───────────────┘      │      └───────────────┐
          ▼                      ▼                      ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Incident Agent  │   │ Compliance Agent │   │  Hindsight Agent │
│ (Investigation)  │   │  (Control Vault) │   │ (Neural Memory)  │
└─────────┬────────┘   └─────────┬────────┘   └─────────┬────────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 ▼
                   ┌───────────────────────────┐
                   │   Hindsight Memory Core   │
                   │  - Semantic Vector Index  │
                   │  - Synaptic Graph Network │
                   │  - Recurring Detector     │
                   └───────────────────────────┘
```

---

## 🧠 Hindsight Memory Engine Internals

1. **Semantic Vector Embedding**:
   - Computes weighted term-frequency representations enriched with a curated cybersecurity ontology (IAM, S3, public access, ACLs, CVEs, credentials, secrets).
   - Calculates cosine similarity against all historical post-mortems in milliseconds.
   - Dual-engine: Offline deterministic SecOps heuristic embedding (no external API required) + optional OpenAI/Gemini embedding integration.

2. **Synaptic Knowledge Graph**:
   - Each retained investigation generates a cluster of semantic nodes:
     - `INCIDENT` Node (ID, severity, asset, environment)
     - `ROOT_CAUSE` Node (Technical hypothesis, failure mechanics)
     - `CONTROL` Node (SOC 2, NIST CSF, ISO 27001 mappings)
     - `REMEDIATION` Node (Step-by-step actions, CLI verification commands)
     - `EVIDENCE` Node (Configuration snapshots, logs, SHA-256 hashes)
   - Relationships: `CAUSED_BY`, `VIOLATES_CONTROL`, `RESOLVED_BY`, `EVIDENCED_BY`, and cross-incident `RESEMBLES` edges.

3. **Recurring Vulnerability Intelligence**:
   - Clusters historical incidents by root cause theme and asset type.
   - Automatically detects systemic organizational blindspots (e.g. repeated public storage policies across buckets).
   - Generates strategic policy-as-code prevention recommendations.

4. **Cryptographic Audit Attestation**:
   - Computes SHA-256 hashes for every captured evidence artifact.
   - Binds findings to SOC 2 Type II (CC6.1, CC6.3, CC7.2), NIST CSF 2.0 (PR.AC-3, RS.RP-1), and ISO 27001 (A.9, A.16).
   - Generates an immutable attestation hash for auditor sign-off.
