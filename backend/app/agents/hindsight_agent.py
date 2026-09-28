from typing import Dict, Any, List, Optional
from ..memory.hindsight_engine import hindsight
from ..models.incident import Incident
from ..models.memory import RecallQuery, RecallResponse, MemoryGraph, RecurringPattern

class HindsightAgent:
    """
    Member 2 Workstream: Hindsight / Memory Agent
    Manages persistent organizational security memory, semantic recall,
    synaptic graph generation, and recurring threat detection.
    """
    
    def __init__(self):
        self.engine = hindsight

    def recall_prior_knowledge(self, query_text: str, control_filter: Optional[str] = None, exclude_id: Optional[str] = None) -> RecallResponse:
        """Recall relevant prior security investigations and playbooks."""
        query = RecallQuery(
            text=query_text,
            control_filter=control_filter,
            min_similarity=0.35,
            top_k=4
        )
        return self.engine.recall(query, exclude_id=exclude_id)

    def retain_investigation(self, incident: Incident) -> Dict[str, Any]:
        """Commit an analyzed incident and its post-mortem to long-term memory."""
        result = self.engine.retain(incident)
        return result

    def get_memory_graph(self) -> MemoryGraph:
        """Fetch full memory graph nodes and relationships."""
        return self.engine.get_memory_graph()

    def get_recurring_patterns(self) -> List[RecurringPattern]:
        """Analyze memory to detect repeating vulnerabilities across infrastructure."""
        return self.engine.detect_recurring_patterns()

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Return memory evolution timeline."""
        return self.engine.get_timeline()

hindsight_agent = HindsightAgent()
