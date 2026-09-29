import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional
from ..models.incident import Incident, IncidentCreate, IncidentStatus, EvidenceItem, EvidenceSourceState
from ..models.audit import AuditQuery, AuditReport
from ..models.memory import RecallQuery, RecallResponse, MemoryGraph, RecurringPattern
from ..memory.storage import incident_store
from ..memory.hindsight_engine import hindsight
from .incident_agent import incident_agent
from .compliance_agent import compliance_agent
from .hindsight_agent import hindsight_agent

class AgentOrchestrator:
    """
    Member 5 Workstream: Agent Orchestrator & DevSecOps Coordinator
    Coordinates the multi-agent SecOps & Compliance lifecycle:
    Incident Ingestion -> Investigation -> Memory Recall -> Control Mapping -> Remediation -> Memory Retain -> Audit Readiness
    """
    
    def __init__(self):
        self.incident_agent = incident_agent
        self.compliance_agent = compliance_agent
        self.hindsight_agent = hindsight_agent
        self.store = incident_store

    def process_incident(self, incident_create: IncidentCreate, auto_retain: bool = False) -> Incident:
        """Execute full multi-agent investigation pipeline for an incoming incident."""
        # 1. Incident Agent performs investigation & memory check
        incident = self.incident_agent.investigate(incident_create)
        
        # 2. Persist in incident store
        self.store.save(incident)
        
        # 3. If auto_retain requested, retain immediately into Hindsight memory
        if auto_retain:
            self.retain_in_memory(incident.id)
            incident.memory_retained = True
            self.store.save(incident)
            
        return incident

    def execute_step_remediation(self, incident_id: str, step_id: str, target_status: str = "VERIFIED") -> Incident:
        """Execute and verify a single remediation step in a demo-safe manner."""
        incident = self.store.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found.")

        target_step = None
        for step in incident.remediation_playbook:
            if step.id == step_id:
                step.status = target_status
                target_step = step
                break

        if not target_step:
            raise ValueError(f"Step {step_id} not found in incident {incident_id}.")

        # Generate demo-safe verification evidence artifact
        ev_id = f"EV-{incident_id}-V-{step_id[:8]}"
        v_log = (
            f"Command Executed (SIMULATED): {target_step.verification_command or 'aws s3api get-public-access-block'}\n"
            f"Asset Target: {incident.affected_asset}\n"
            f"Status: SUCCESS ({target_status})\n"
            f"Timestamp: {datetime.utcnow().isoformat()}Z"
        )
        verif_ev = EvidenceItem(
            id=ev_id,
            filename=f"verification_{step_id}.log",
            type="Remediation Verification (SIMULATED)",
            description=f"Execution & Verification proof for action: {target_step.action} (SIMULATED)",
            content_preview=v_log,
            sha256_hash=hashlib.sha256(v_log.encode("utf-8")).hexdigest(),
            source_state=EvidenceSourceState.VERIFIED
        )

        # Avoid duplicate evidence
        if not any(e.id == ev_id for e in incident.evidence_vault):
            incident.evidence_vault.append(verif_ev)

        # Check overall remediation lifecycle transition
        all_verified = all(s.status == "VERIFIED" for s in incident.remediation_playbook)
        any_remediated = any(s.status in ["REMEDIATED", "VERIFIED"] for s in incident.remediation_playbook)

        if all_verified:
            incident.status = IncidentStatus.VERIFIED
            for c in incident.controls:
                c.audit_status = "VERIFIED"
        elif any_remediated:
            incident.status = IncidentStatus.REMEDIATED
            for c in incident.controls:
                c.audit_status = "IN_PROGRESS"

        self.store.save(incident)
        if incident.memory_retained:
            hindsight.retain(incident)

        return incident

    def execute_full_remediation(self, incident_id: str) -> Incident:
        """Execute and verify all remediation playbook steps for an incident."""
        incident = self.store.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found.")

        for step in incident.remediation_playbook:
            self.execute_step_remediation(incident_id, step.id, target_status="VERIFIED")

        return self.store.get(incident_id)

    def retain_in_memory(self, incident_id: str) -> Dict[str, Any]:
        """Explicitly commit an investigated incident to Hindsight persistent memory."""
        incident = self.store.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found in database.")
        
        result = self.hindsight_agent.retain_investigation(incident)
        incident.memory_retained = True
        self.store.save(incident)
        return result

    def query_audit(self, audit_query: AuditQuery) -> AuditReport:
        """Execute auditor request against Hindsight organizational memory."""
        return self.compliance_agent.answer_audit_response(audit_query) if hasattr(self.compliance_agent, "answer_audit_response") else self.compliance_agent.answer_audit_query(audit_query)

    def query_memory_recall(self, query_text: str, control_filter: Optional[str] = None) -> RecallResponse:
        """Directly query Hindsight memory for prior incidents or root causes."""
        return self.hindsight_agent.recall_prior_knowledge(query_text, control_filter=control_filter)

    def get_memory_graph(self) -> MemoryGraph:
        """Retrieve organizational memory knowledge graph."""
        return self.hindsight_agent.get_memory_graph()

    def get_recurring_patterns(self) -> List[RecurringPattern]:
        """Detect repeating vulnerabilities in organizational memory."""
        return self.hindsight_agent.get_recurring_patterns()

orchestrator = AgentOrchestrator()
