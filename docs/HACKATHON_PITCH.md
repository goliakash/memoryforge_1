# 🎤 Hackathon Pitch Deck & 3-Minute Script

## 💡 The Hook (0:00 - 0:30)
> *"Judges, every day, security teams fight incidents. They find the root cause, fix the policy, and write a post-mortem document. But where does that knowledge go? It dies in Jira or Google Drive.*
>
> *Three months later, a different engineer faces the exact same failure on a different cloud asset — and has to investigate from scratch.*
>
> *We built **Hindsight**: an AI-powered Security Operations & Compliance Memory Agent that turns isolated incidents into persistent, long-term organizational memory."*

---

## 🎯 The Problem & Our Solution (0:30 - 1:15)
> *"Organizations don't lack security tools; they lack **organizational memory**.
>
> With Hindsight, we close the loop:
> 1. When an incident occurs, our multi-agent system conducts root-cause analysis, maps compliance controls, captures cryptographic evidence, and generates a post-mortem.
> 2. Then, it retains those learnings into a persistent semantic memory graph.
> 3. When a similar incident occurs later, the agent instantly recalls what happened, what caused it, and what playbook solved it — reducing Mean Time to Remediation by over 80%.
> 4. And when auditors ask for historical evidence, Hindsight pulls defensible findings in seconds."*

---

## 🚀 Live Demo Walkthrough (1:15 - 2:30)
*(Click the glowing **"▶ Run Hackathon Demo Story"** button on the dashboard)*

1. **Step 1: Ingest Incident #1024 (S3 Public Exposure)**
   - Show automated root cause derivation & compliance control mapping.
2. **Step 2: Retain into Hindsight Memory**
   - Click "Retain in Hindsight". Point out the synapse graph connecting Incident, Root Cause, SOC 2 CC6.1, and verified playbook.
3. **Step 3: Ingest Similar Incident #1038**
   - Click Load #1038 (Data Lake Exposure) and hit Investigate.
   - **Show the highlight:** Hindsight immediately triggers a High-Confidence Recall (86%+ match to #1024)! It transfers the proven root cause and verified playbook with 0 wasted hours.
4. **Step 4: Auditor Query**
   - Switch to the Compliance Portal.
   - Auditor asks: *"Show historical access-control findings, remediation status, and available evidence."*
   - Instant response: 100% remediated findings, SOC 2 mapping, SHA-256 evidence hashes.
5. **Step 5: Recurring Vulnerability Detection**
   - Show how the memory brain flags: *"Warning: Public Access misconfigurations detected 3 times across cloud storage. Recommendation: Add CI/CD policy-as-code guardrails."*

---

## 🏆 The Takeaway (2:30 - 3:00)
> *"Hindsight is not another dashboard or SIEM. **The memory loop is the product.**
>
> As more incidents are processed, the organization gets smarter, safer, and audit-ready 365 days a year.
>
> Thank you! We are happy to take questions."*

---

## ❓ Anticipated Judge Q&A

**Q1: How is Hindsight different from vector databases like Pinecone or Chroma?**
*Answer:* Hindsight is not just vector storage. It is an interconnected knowledge graph that couples semantic recall with deterministic compliance controls (SOC 2, NIST), cryptographic evidence attestation, and proactive recurring pattern detection.

**Q2: What happens if an organization doesn't have an OpenAI API key?**
*Answer:* We built Hindsight with a dual-engine architecture: a high-speed, offline-capable cybersecurity heuristic embedding engine that runs locally with zero latency, plus optional support for OpenAI/Gemini models. It runs 100% turnkey out of the box!

**Q3: How does this help auditors?**
*Answer:* Auditors usually spend weeks waiting for security teams to pull historical tickets and logs. Hindsight acts as an autonomous auditor agent that queries organizational memory and generates cryptographic evidence packages on demand.
