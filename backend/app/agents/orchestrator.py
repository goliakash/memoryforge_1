from typing import Dict, Any, List, Optional
from ..models.incident import Incident, IncidentCreate
from ..models.audit import AuditQuery, AuditReport
from ..models.memory import RecallQuery, RecallResponse, MemoryGraph, RecurringPattern
from ..memory.storage import incident_store
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
