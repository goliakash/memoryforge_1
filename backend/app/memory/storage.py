import json
from pathlib import Path
from typing import Dict, List, Optional
from ..config import INCIDENTS_FILE
from ..models.incident import Incident

class IncidentStore:
    def __init__(self):
        self._incidents: Dict[str, Incident] = {}
        self._load()

    def _load(self):
        try:
            if INCIDENTS_FILE.exists():
                with open(INCIDENTS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._incidents = {k: Incident(**v) for k, v in data.items()}
        except Exception as e:
            print(f"[IncidentStore] Error loading incidents: {e}")
            self._incidents = {}

    def _save(self):
        try:
            with open(INCIDENTS_FILE, "w", encoding="utf-8") as f:
                data = {k: v.model_dump() for k, v in self._incidents.items()}
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[IncidentStore] Error saving incidents: {e}")

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def list_all(self) -> List[Incident]:
        return list(self._incidents.values())

    def save(self, incident: Incident) -> Incident:
        self._incidents[incident.id] = incident
        self._save()
        return incident

    def remove(self, incident_id: str) -> bool:
        if incident_id in self._incidents:
            del self._incidents[incident_id]
            self._save()
            return True
        return False

    def clear(self):
        self._incidents.clear()
        self._save()

incident_store = IncidentStore()
