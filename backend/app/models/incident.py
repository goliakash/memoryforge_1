from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    REMEDIATED = "REMEDIATED"
    CLOSED = "CLOSED"
    RECURRING = "RECURRING"

class EvidenceItem(BaseModel):
    id: str
    filename: str
    type: str  # e.g., "Configuration Scan", "CloudTrail Log", "Security Finding", "Terraform Diff"
    description: str
    content_preview: str
    sha256_hash: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

class RemediationStep(BaseModel):
    id: str
    step_number: int
    action: str
    rationale: str
    status: str = "PENDING"  # PENDING, APPLIED, VERIFIED
    verification_command: Optional[str] = None

class ControlMapping(BaseModel):
    framework: str  # "SOC 2 Type II", "NIST CSF 2.0", "ISO/IEC 27001", "CIS Benchmark"
    control_id: str  # e.g., "CC6.1", "PR.AC-3", "A.9.2.3"
    control_name: str
    requirement: str
    audit_status: str = "COMPLIANT_POST_REMEDIATION"

class PostMortem(BaseModel):
    summary: str
    root_cause_analysis: str
    preventive_actions: List[str] = Field(default_factory=list)
    lessons_learned: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, str]] = Field(default_factory=list)

class IncidentCreate(BaseModel):
    incident_id: Optional[str] = None
    title: str
    description: str
    severity: IncidentSeverity = IncidentSeverity.HIGH
    affected_asset: str
    asset_type: Optional[str] = "Cloud Storage"
    environment: Optional[str] = "Production"
    raw_evidence: Optional[str] = None

class Incident(BaseModel):
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    affected_asset: str
    asset_type: str = "Cloud Storage"
    environment: str = "Production"
    raw_evidence: Optional[str] = None
    detected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    status: IncidentStatus = IncidentStatus.DETECTED
    
    # AI Investigation Outputs
    root_cause: Optional[str] = None
    controls: List[ControlMapping] = Field(default_factory=list)
    remediation_playbook: List[RemediationStep] = Field(default_factory=list)
    evidence_vault: List[EvidenceItem] = Field(default_factory=list)
    post_mortem: Optional[PostMortem] = None
    
    # Hindsight Memory Links
    memory_retained: bool = False
    retained_at: Optional[str] = None
    recalled_from_id: Optional[str] = None
    similarity_score: Optional[float] = None
    investigation_notes: Optional[str] = None
