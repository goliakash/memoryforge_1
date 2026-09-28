import json
import re
import math
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from collections import Counter

from ..config import MEMORY_FILE, GRAPH_FILE, DEFAULT_SIMILARITY_THRESHOLD
from ..models.memory import (
    MemoryNode, MemoryNodeType, MemoryLink, MemoryGraph,
    RecallQuery, RecallMatch, RecallResponse, RecurringPattern
)
from ..models.incident import Incident, EvidenceItem, RemediationStep, ControlMapping

# Domain-specific security synonyms & keyword weighting to boost semantic recall
SECOPS_ONTOLOGY = {
    "access_control": [
        "access control", "iam", "public access", "policy", "permission", "bucket policy",
        "acl", "unauthorized", "unrestricted", "principal", "role", "privilege", "s3",
        "cloud storage", "blob", "read access", "world readable"
    ],
    "data_exposure": [
        "exposure", "leak", "sensitive data", "pii", "confidential", "publicly accessible",
        "data loss", "exfiltration", "storage bucket", "customer data"
    ],
    "credential_compromise": [
        "api key", "hardcoded secret", "token", "password", "service account", "leak",
        "github push", "credentials", "compromised"
    ],
    "network_security": [
        "security group", "port open", "ssh", "0.0.0.0/0", "firewall", "ingress",
        "exposed port", "bastion", "unrestricted cidr"
    ]
}

class HindsightMemoryEngine:
    """
    Hindsight Organizational Memory Engine
    
    Transforms isolated security incidents and post-mortems into an interconnected,
    persistent neural-like memory graph that powers instant recall during future
    investigations and compliance audits.
    """
    
    def __init__(self):
        self.memories: Dict[str, Dict[str, Any]] = {}
        self.nodes: Dict[str, MemoryNode] = {}
        self.links: List[MemoryLink] = []
        self._load_memory()

    def _load_memory(self):
        """Load persistent memory from disk if available."""
        try:
            if MEMORY_FILE.exists():
                with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                    self.memories = json.load(f)
            if GRAPH_FILE.exists():
                with open(GRAPH_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.nodes = {k: MemoryNode(**v) for k, v in data.get("nodes", {}).items()}
                    self.links = [MemoryLink(**l) for l in data.get("links", [])]
        except Exception as e:
            print(f"[HindsightEngine] Error loading memory: {e}. Starting fresh.")
            self.memories = {}
            self.nodes = {}
            self.links = []

    def _save_memory(self):
        """Persist current memory and graph to disk."""
        try:
            with open(MEMORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.memories, f, indent=2)
            
            with open(GRAPH_FILE, "w", encoding="utf-8") as f:
                graph_data = {
                    "nodes": {k: v.model_dump() for k, v in self.nodes.items()},
                    "links": [l.model_dump() for l in self.links]
                }
                json.dump(graph_data, f, indent=2)
        except Exception as e:
            print(f"[HindsightEngine] Error saving memory: {e}")

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into lowercase alphanumeric words."""
        return re.findall(r"\b[a-zA-Z0-9_\-\.]{2,}\b", text.lower())

    def _compute_vector(self, text: str) -> Dict[str, float]:
        """Compute term frequency vector with SecOps domain term boosting."""
        tokens = self._tokenize(text)
        counts = Counter(tokens)
        total = max(1, len(tokens))
        vec: Dict[str, float] = {}
        
        for word, count in counts.items():
            weight = 1.0
            # Boost high-signal security tokens
            for domain, keywords in SECOPS_ONTOLOGY.items():
                for kw in keywords:
                    if word in kw:
                        weight += 1.5
            vec[word] = (count / total) * weight
        return vec

    def _cosine_similarity(self, vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
        """Compute cosine similarity between two term frequency vectors."""
        common = set(vec_a.keys()) & set(vec_b.keys())
        if not common:
            return 0.0
        
        dot = sum(vec_a[k] * vec_b[k] for k in common)
        mag_a = math.sqrt(sum(v * v for v in vec_a.values()))
        mag_b = math.sqrt(sum(v * v for v in vec_b.values()))
        
        if mag_a == 0 or mag_b == 0:
            return 0.0
        
        sim = dot / (mag_a * mag_b)
        return min(1.0, max(0.0, sim))

    def retain(self, incident: Incident) -> Dict[str, Any]:
        """
        Retain an incident investigation into Hindsight Organizational Memory.
        Breaks down incident into semantic memory nodes and graph links.
        """
        inc_id = incident.id
        summary_text = f"{incident.title} {incident.description} {incident.affected_asset} {incident.root_cause or ''}"
        
        # 1. Save memory record
        memory_record = {
            "incident_id": inc_id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity.value,
            "affected_asset": incident.affected_asset,
            "asset_type": incident.asset_type,
            "root_cause": incident.root_cause or "Investigation Pending",
            "controls": [c.model_dump() for c in incident.controls],
            "remediation_playbook": [r.model_dump() for r in incident.remediation_playbook],
            "evidence_vault": [e.model_dump() for e in incident.evidence_vault],
            "post_mortem": incident.post_mortem.model_dump() if incident.post_mortem else None,
            "detected_at": incident.detected_at,
            "retained_at": datetime.utcnow().isoformat() + "Z",
            "search_vector": self._compute_vector(summary_text),
            "tags": [incident.asset_type.lower(), incident.severity.value.lower()] + [c.control_id.lower() for c in incident.controls]
        }
        self.memories[inc_id] = memory_record

        # 2. Build Memory Graph Nodes
        # Main Incident Node
        inc_node_id = f"node_inc_{inc_id}"
        self.nodes[inc_node_id] = MemoryNode(
            id=inc_node_id,
            type=MemoryNodeType.INCIDENT,
            label=f"{inc_id}: {incident.title}",
            details={
                "incident_id": inc_id,
                "severity": incident.severity.value,
                "asset": incident.affected_asset,
                "status": incident.status.value
            },
            incident_id=inc_id,
            tags=["incident", incident.severity.value]
        )

        # Root Cause Node
        if incident.root_cause:
            rc_node_id = f"node_rc_{inc_id}"
            self.nodes[rc_node_id] = MemoryNode(
                id=rc_node_id,
                type=MemoryNodeType.ROOT_CAUSE,
                label=f"Root Cause ({inc_id}): {incident.root_cause[:45]}...",
                details={"full_text": incident.root_cause},
                incident_id=inc_id,
                tags=["root_cause"]
            )
            self.links.append(MemoryLink(
                id=f"link_{inc_id}_rc",
                source=inc_node_id,
                target=rc_node_id,
                relationship="CAUSED_BY"
            ))

        # Control Nodes
        for ctrl in incident.controls:
            ctrl_node_id = f"node_ctrl_{ctrl.control_id}"
            if ctrl_node_id not in self.nodes:
                self.nodes[ctrl_node_id] = MemoryNode(
                    id=ctrl_node_id,
                    type=MemoryNodeType.CONTROL,
                    label=f"{ctrl.framework} {ctrl.control_id}",
                    details={
                        "framework": ctrl.framework,
                        "control_id": ctrl.control_id,
                        "control_name": ctrl.control_name,
                        "requirement": ctrl.requirement
                    },
                    incident_id=inc_id,
                    tags=["control", ctrl.framework.lower()]
                )
            self.links.append(MemoryLink(
                id=f"link_{inc_id}_ctrl_{ctrl.control_id}",
                source=inc_node_id,
                target=ctrl_node_id,
                relationship="VIOLATES_CONTROL"
            ))

        # Remediation Nodes
        if incident.remediation_playbook:
            rem_node_id = f"node_rem_{inc_id}"
            steps_preview = [s.action for s in incident.remediation_playbook[:3]]
            self.nodes[rem_node_id] = MemoryNode(
                id=rem_node_id,
                type=MemoryNodeType.REMEDIATION,
                label=f"Playbook ({inc_id}): {len(incident.remediation_playbook)} Actions",
                details={"steps": steps_preview},
                incident_id=inc_id,
                tags=["remediation"]
            )
            self.links.append(MemoryLink(
                id=f"link_{inc_id}_rem",
                source=inc_node_id,
                target=rem_node_id,
                relationship="RESOLVED_BY"
            ))

        # Evidence Nodes
        for ev in incident.evidence_vault:
            ev_node_id = f"node_ev_{ev.id}"
            self.nodes[ev_node_id] = MemoryNode(
                id=ev_node_id,
                type=MemoryNodeType.EVIDENCE,
                label=f"Evidence: {ev.filename}",
                details={
                    "type": ev.type,
                    "sha256": ev.sha256_hash[:16] + "...",
                    "description": ev.description
                },
                incident_id=inc_id,
                tags=["evidence", ev.type.lower()]
            )
            self.links.append(MemoryLink(
                id=f"link_{inc_id}_ev_{ev.id}",
                source=inc_node_id,
                target=ev_node_id,
                relationship="EVIDENCED_BY"
            ))

        # Cross-incident resemblance links
        for other_id, other_mem in self.memories.items():
            if other_id == inc_id:
                continue
            sim = self._cosine_similarity(memory_record["search_vector"], other_mem["search_vector"])
            if sim >= 0.65:
                other_node_id = f"node_inc_{other_id}"
                link_id = f"link_sim_{min(inc_id, other_id)}_{max(inc_id, other_id)}"
                if not any(l.id == link_id for l in self.links):
                    self.links.append(MemoryLink(
                        id=link_id,
                        source=inc_node_id,
                        target=other_node_id,
                        relationship="RESEMBLES",
                        confidence=round(sim, 2)
                    ))

        self._save_memory()
        return {
            "status": "RETAINED",
            "incident_id": inc_id,
            "synapses_added": len([l for l in self.links if inc_id in l.id]),
            "timestamp": memory_record["retained_at"]
        }

    def recall(self, query: RecallQuery, exclude_id: Optional[str] = None) -> RecallResponse:
        """
        Recall past incidents and post-mortems from organizational memory.
        Calculates similarity using semantic vectors, ontology boosting, and asset correlation.
        """
        query_vec = self._compute_vector(query.text)
        matches: List[RecallMatch] = []

        for inc_id, mem in self.memories.items():
            if exclude_id and inc_id == exclude_id:
                continue
            
            # Base semantic similarity
            sim = self._cosine_similarity(query_vec, mem["search_vector"])
            
            # Additional heuristic boosts:
            # 1. Asset similarity boost
            if any(term in mem["affected_asset"].lower() for term in self._tokenize(query.text)):
                sim = min(1.0, sim + 0.15)
            
            # 2. Control domain boost
            if query.control_filter:
                ctrl_match = any(
                    query.control_filter.lower() in c.get("control_name", "").lower() or
                    query.control_filter.lower() in c.get("framework", "").lower()
                    for c in mem.get("controls", [])
                )
                if ctrl_match:
                    sim = min(1.0, sim + 0.12)

            if sim >= query.min_similarity:
                playbook = mem.get("remediation_playbook", [])
                remediation_summary = [step.get("action", "") for step in playbook]
                ctrl_names = [f"{c.get('framework', '')} {c.get('control_id', '')}: {c.get('control_name', '')}" for c in mem.get("controls", [])]

                matches.append(RecallMatch(
                    incident_id=inc_id,
                    title=mem["title"],
                    similarity_score=round(sim, 3),
                    similarity_percentage=int(round(sim * 100)),
                    matched_root_cause=mem.get("root_cause", "No root cause documented"),
                    matched_controls=ctrl_names,
                    verified_remediation_summary=remediation_summary,
                    evidence_count=len(mem.get("evidence_vault", [])),
                    detected_at=mem.get("detected_at", ""),
                    summary_explanation=(
                        f"Previous incident {inc_id} ({mem['title']}) matches this scenario with {int(round(sim * 100))}% confidence. "
                        f"Root cause was diagnosed as '{mem.get('root_cause', '')[:80]}...'. "
                        f"A verified remediation playbook with {len(playbook)} steps is available to reuse immediately."
                    )
                ))

        # Sort by similarity descending
        matches.sort(key=lambda x: x.similarity_score, reverse=True)
        top_matches = matches[:query.top_k]

        highest_sim = top_matches[0].similarity_score if top_matches else 0.0

        # Construct Agent synthesis advice
        if top_matches and highest_sim >= 0.70:
            best = top_matches[0]
            agent_advice = (
                f"🚨 Hindsight High-Confidence Recall ({best.similarity_percentage}% match to {best.incident_id}): "
                f"We previously investigated a nearly identical failure on '{best.title}'. "
                f"The verified root cause was '{best.matched_root_cause}'. "
                f"Recommended immediate action: Apply the existing {len(best.verified_remediation_summary)}-step verified playbook "
                f"to accelerate MTTR (Mean Time to Remediation) without starting from scratch."
            )
        elif top_matches:
            agent_advice = (
                f"🧠 Hindsight Recall: Found {len(top_matches)} related prior investigations. "
                f"Closest precedent is {top_matches[0].incident_id} ({top_matches[0].similarity_percentage}% similarity). "
                f"Review prior remediation and access-control mappings before proceeding."
            )
        else:
            agent_advice = "ℹ️ No direct high-similarity precedents found in organizational memory. Proceeding with fresh automated SecOps root-cause investigation."

        return RecallResponse(
            query=query.text,
            total_matches=len(matches),
            highest_similarity=highest_sim,
            matches=top_matches,
            agent_advice=agent_advice
        )

    def detect_recurring_patterns(self) -> List[RecurringPattern]:
        """
        Analyze organizational memory to identify recurring vulnerabilities,
        repeat asset misconfigurations, and systemic blind spots.
        """
        patterns: List[RecurringPattern] = []
        
        # 1. Check for recurring Cloud Storage Access Control exposures
        storage_incidents = [
            m for m in self.memories.values()
            if "storage" in m.get("asset_type", "").lower() or "bucket" in m.get("title", "").lower() or "storage" in m.get("title", "").lower()
        ]
        
        if len(storage_incidents) >= 2:
            inc_ids = [m["incident_id"] for m in storage_incidents]
            assets = list(set(m["affected_asset"] for m in storage_incidents))
            patterns.append(RecurringPattern(
                id="PAT-STORAGE-ACCESS-01",
                title="Recurring Cloud Storage Public Access Policy Misconfigurations",
                root_cause_theme="Incorrect access policy / IAM principal misconfiguration across cloud object storage",
                control_category="Access Control (SOC 2 CC6.1, NIST PR.AC-3)",
                affected_assets=assets,
                related_incident_ids=inc_ids,
                frequency=len(storage_incidents),
                risk_level="HIGH" if len(storage_incidents) < 3 else "CRITICAL",
                recommendation=(
                    "Enforce organization-wide preventive guardrails: Activate AWS S3 Block Public Access at account level, "
                    "add Terraform pre-commit Sentinel/Checkov linting to reject public bucket policies, "
                    "and conduct automated quarterly IAM policy audits."
                ),
                first_seen=min(m.get("detected_at", "") for m in storage_incidents),
                last_seen=max(m.get("detected_at", "") for m in storage_incidents)
            ))

        # 2. Check for recurring Credential / Secret Leaks
        secret_incidents = [
            m for m in self.memories.values()
            if "secret" in m.get("title", "").lower() or "credential" in m.get("title", "").lower() or "token" in m.get("title", "").lower()
        ]
        if len(secret_incidents) >= 2:
            patterns.append(RecurringPattern(
                id="PAT-SECRET-LEAK-02",
                title="Repeated Hardcoded API Tokens & Service Key Exposure",
                root_cause_theme="Developer local environment configurations committed to version control",
                control_category="Data Protection & Key Management (ISO 27001 A.10.1)",
                affected_assets=[m["affected_asset"] for m in secret_incidents],
                related_incident_ids=[m["incident_id"] for m in secret_incidents],
                frequency=len(secret_incidents),
                risk_level="CRITICAL",
                recommendation="Deploy automated git-secrets pre-push hooks and integrate HashiCorp Vault or AWS Secrets Manager.",
                first_seen=min(m.get("detected_at", "") for m in secret_incidents),
                last_seen=max(m.get("detected_at", "") for m in secret_incidents)
            ))

        return patterns

    def get_memory_graph(self) -> MemoryGraph:
        """Return full memory graph for visualization."""
        node_counts = Counter(n.type.value for n in self.nodes.values())
        return MemoryGraph(
            nodes=list(self.nodes.values()),
            links=self.links,
            stats={
                "total_memories": len(self.memories),
                "total_nodes": len(self.nodes),
                "total_synapse_links": len(self.links),
                "node_distribution": dict(node_counts)
            }
        )

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Return chronological timeline of retained security knowledge."""
        timeline_items = []
        for inc_id, mem in sorted(self.memories.items(), key=lambda x: x[1].get("detected_at", "")):
            timeline_items.append({
                "incident_id": inc_id,
                "title": mem["title"],
                "severity": mem["severity"],
                "asset": mem["affected_asset"],
                "root_cause": mem.get("root_cause", ""),
                "detected_at": mem.get("detected_at", ""),
                "retained_at": mem.get("retained_at", ""),
                "controls_count": len(mem.get("controls", [])),
                "evidence_count": len(mem.get("evidence_vault", []))
            })
        return timeline_items

    def reset_memory(self):
        """Clear all memories (used for demo resets)."""
        self.memories.clear()
        self.nodes.clear()
        self.links.clear()
        self._save_memory()

# Global singleton instance
hindsight = HindsightMemoryEngine()
