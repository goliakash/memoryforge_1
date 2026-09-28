from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from .incident import EvidenceItem

class AuditQuery(BaseModel):
    query: str = "Show historical access-control findings, remediation status, and available evidence"
    control_domain: Optional[str] = "Access Control"  # Access Control, Data Protection, Incident Response, etc.
    framework: Optional[str] = "ALL"  # SOC2, NIST, ISO27001, ALL
    include_remediated_only: bool = False

class AuditFinding(BaseModel):
    finding_id: str
    incident_id: str
    title: str
    control_id: str
    framework: str
    control_name: str
    root_cause: str
    remediation_status: str  # "VERIFIED_CLOSED", "REMEDIATED", "IN_PROGRESS"
    remediation_actions: List[str]
    evidence_items: List[EvidenceItem]
    detected_at: str
    remediated_at: Optional[str] = None
    auditor_signoff_ready: bool = True

class AuditReport(BaseModel):
    report_id: str
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    auditor_query: str
    control_domain: str
    frameworks_covered: List[str]
    total_findings: int
    remediated_findings: int
    compliance_rate_percent: float
    findings: List[AuditFinding]
    executive_summary: str
    memory_attestation_hash: str
