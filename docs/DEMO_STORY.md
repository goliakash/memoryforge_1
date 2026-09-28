# 🎬 Guided Hackathon Demo Story

This guide details the exact demo story requested for presenting **Hindsight SecOps & Compliance Memory Agent**.

## Quick Launch
Run the backend server:
```bash
python backend/run.py
```
Open your browser at `http://localhost:8000`.

---

## 5-Step Continuous Story Demonstration

### Option A: 1-Click Automated Tour
Simply click the purple **"▶ Run Hackathon Demo Story"** button in the top navigation bar! It will guide you and the judges through each phase with interactive step cards.

---

### Option B: Manual Live Walkthrough

#### Step 1: Ingest Incident #1024 (The Anchor Incident)
1. Go to the **Incident Studio** tab.
2. Click the quick-load button: `Load #1024 (S3 Public Access)`.
3. Click `⚡ Run Multi-Agent Investigation`.
4. Observe:
   - **Multi-Agent Stream** ingests the alert and analyzes symptoms.
   - **Root Cause Identified:** *Incorrect access policy and missing bucket-level PublicAccessBlock configuration.*
   - **Compliance Controls Mapped:** SOC 2 Type II (CC6.1), NIST CSF (PR.AC-3), ISO 27001 (A.9.2.3).
   - **Remediation Playbook:** 4 verified containment steps with AWS CLI verification commands.
   - **Cryptographic Evidence Vault:** 3 artifacts with SHA-256 integrity hashes.

#### Step 2: Store Knowledge in Hindsight
1. Click the green `🧠 Retain in Hindsight Memory` button.
2. The button confirms: `✓ Synapses Committed`.
3. Switch to the **Memory Brain** tab to show the new interactive nodes and links floating in the synaptic graph!

#### Step 3: Ingest Similar Incident #1038 (The Memory Recall!)
1. Return to the **Incident Studio** tab.
2. Click the template button: `Load #1038 (Data Lake Exposure)`.
3. Click `⚡ Run Multi-Agent Investigation`.
4. **The "Aha!" Moment for Judges:**
   - Look at the glowing purple **Hindsight Recall Alert Banner**:
     ```
     🧠 Hindsight Recall: High-Confidence Match to Incident INC-1024 (86% Match)
     Previous incident INC-1024 resolved this identical failure. Root cause and remediation playbook transferred automatically.
     ```
   - Point out to judges: *The engineer did NOT have to reinvent the wheel. MTTR dropped from 3 hours to 30 seconds.*

#### Step 4: Auditor Mode (Compliance & Defensible Evidence)
1. Switch to the **Compliance & Audit** tab.
2. In the query box, notice the pre-filled prompt:
   `Show historical access-control findings, remediation status, and available evidence`
3. Click `Execute Auditor Query`.
4. Observe the results:
   - **Executive Compliance Summary:** 100% remediation compliance.
   - **Memory Cryptographic Attestation Hash:** Defensible integrity proof.
   - **Findings Table:** Lists both INC-1024 and INC-1038, their controls, root causes, remediation states (`VERIFIED_CLOSED`), and 3 attached evidence files each!
5. Click `📄 Export Audit Package (PDF)` to show printable audit readiness.

#### Step 5: Recurring Vulnerability Detection
1. Switch to the **Recurring Risks** tab.
2. Show the automated intelligence card:
   - **Pattern:** *Recurring Cloud Storage Public Access Policy Misconfigurations (High Risk)*
   - **Affected Assets:** `customer-data-bucket`, `analytics-lake-raw`
   - **Recommendation:** *Deploy Terraform pre-commit Sentinel/Checkov linting to prevent misconfigurations at commit time.*
3. Conclude: **"The memory loop is closed."** 🧠🛡️
