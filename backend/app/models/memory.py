from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class MemoryNodeType(str, Enum):
    INCIDENT = "INCIDENT"
    ROOT_CAUSE = "ROOT_CAUSE"
    CONTROL = "CONTROL"
    REMEDIATION = "REMEDIATION"
    EVIDENCE = "EVIDENCE"

class MemoryNetworkType(str, Enum):
    WORLD = "WORLD"
    EXPERIENCE = "EXPERIENCE"
    OBSERVATION = "OBSERVATION"
    OPINION = "OPINION"

class MemoryNode(BaseModel):
    id: str
    type: MemoryNodeType
    label: str
    details: Dict[str, Any] = Field(default_factory=dict)
    incident_id: str
    tags: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

class MemoryLink(BaseModel):
    id: str
    source: str
    target: str
    relationship: str  # "CAUSED_BY", "VIOLATES_CONTROL", "RESOLVED_BY", "EVIDENCED_BY", "RESEMBLES"
    confidence: float = 1.0

class MemoryGraph(BaseModel):
    nodes: List[MemoryNode] = Field(default_factory=list)
    links: List[MemoryLink] = Field(default_factory=list)
    stats: Dict[str, Any] = Field(default_factory=dict)

class RecallQuery(BaseModel):
    text: str
    control_filter: Optional[str] = None
    severity_filter: Optional[str] = None
    top_k: int = 5
    min_similarity: float = 0.35

class RecallMatch(BaseModel):
    incident_id: str
    title: str
    similarity_score: float  # 0.0 to 1.0
    similarity_percentage: int
    matched_root_cause: str
    matched_controls: List[str]
    verified_remediation_summary: List[str]
    evidence_count: int
    detected_at: str
    summary_explanation: str
    signal_breakdown: Optional[Dict[str, float]] = None
    recurrence_rationale: Optional[str] = None

class RecallResponse(BaseModel):
    query: str
    total_matches: int
    highest_similarity: float
    matches: List[RecallMatch] = Field(default_factory=list)
    agent_advice: str

class RecurringPattern(BaseModel):
    id: str
    title: str
    root_cause_theme: str
    control_category: str
    affected_assets: List[str]
    related_incident_ids: List[str]
    frequency: int
    risk_level: str  # "HIGH", "CRITICAL"
    recommendation: str
    first_seen: str
    last_seen: str
