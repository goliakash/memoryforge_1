import os
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from .config import PROJECT_NAME, PROJECT_TAGLINE, VERSION
from .models.incident import Incident, IncidentCreate, IncidentStatus
from .models.memory import RecallQuery, RecallResponse, MemoryGraph, RecurringPattern
from .models.audit import AuditQuery, AuditReport
from .agents.orchestrator import orchestrator
from .memory.hindsight_engine import hindsight
from .memory.storage import incident_store
from .seed_data import seed_baseline_data

# Initialize FastAPI app
app = FastAPI(
    title=PROJECT_NAME,
    description=PROJECT_TAGLINE,
    version=VERSION
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

@app.on_event("startup")
async def startup_event():
    """Ensure baseline memory is ready if empty."""
    if not hindsight.memories:
        print("[Startup] Initializing baseline organizational memory...")
        seed_baseline_data(reset_first=False)

# --- System & Health Endpoints ---

@app.get("/api/health")
def get_system_health():
    """Return status of all SecOps agents and Hindsight memory engine."""
    graph = hindsight.get_memory_graph()
    return {
        "status": "OPERATIONAL",
        "project": PROJECT_NAME,
        "version": VERSION,
        "agents": {
            "incident_agent": {"status": "ONLINE", "workstream": "Security Investigation & Root Cause"},
            "hindsight_agent": {"status": "ONLINE", "workstream": "Persistent Organizational Memory"},
            "compliance_agent": {"status": "ONLINE", "workstream": "Control Mapping & Audit Readiness"},
            "orchestrator": {"status": "ONLINE", "workstream": "DevSecOps & Multi-Agent Coordination"}
        },
        "hindsight_memory": {
            "total_retained_incidents": len(hindsight.memories),
            "total_synapse_nodes": len(graph.nodes),
            "total_synapse_links": len(graph.links)
        }
    }

# --- Incident Ingestion & Investigation Endpoints ---

@app.get("/api/incidents", response_model=List[Incident])
def list_incidents():
    """Retrieve all ingested and investigated incidents."""
    return incident_store.list_all()

@app.get("/api/incidents/{incident_id}", response_model=Incident)
def get_incident(incident_id: str):
    """Retrieve a single incident by ID."""
    inc = incident_store.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    return inc

@app.post("/api/incidents", response_model=Incident)
def create_and_investigate_incident(payload: IncidentCreate, auto_retain: bool = Query(False)):
    """
    Ingest a new security incident, trigger AI multi-agent investigation,
    conduct root-cause derivation, check Hindsight memory for prior precedent,
    and optionally commit to long-term memory.
    """
    incident = orchestrator.process_incident(payload, auto_retain=auto_retain)
    return incident

@app.post("/api/incidents/{incident_id}/retain")
def retain_incident_in_memory(incident_id: str):
    """Explicitly retain an investigated incident in Hindsight organizational memory."""
    try:
        res = orchestrator.retain_in_memory(incident_id)
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/incidents/{incident_id}/remediation/{step_id}/status")
def update_remediation_status(incident_id: str, step_id: str, status: str = Query("VERIFIED")):
    """Update status of a remediation step."""
    inc = incident_store.get(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found.")
    
    found = False
    for step in inc.remediation_playbook:
        if step.id == step_id:
            step.status = status
            found = True
            break
            
    if not found:
        raise HTTPException(status_code=404, detail=f"Step {step_id} not found in incident {incident_id}.")
        
    incident_store.save(inc)
    return {"status": "UPDATED", "incident_id": incident_id, "step_id": step_id, "new_status": status}

# --- Hindsight Memory Recall & Graph Endpoints ---

@app.post("/api/memory/recall", response_model=RecallResponse)
def recall_memory(payload: RecallQuery):
    """
    Semantic recall query against Hindsight organizational memory.
    Returns matched incidents, similarity scores, and verified remediation playbooks.
    """
    return orchestrator.query_memory_recall(payload.text, control_filter=payload.control_filter)

@app.get("/api/memory/graph", response_model=MemoryGraph)
def get_memory_graph():
    """Retrieve full knowledge graph for 2D/3D visual memory neural map."""
    return orchestrator.get_memory_graph()

@app.get("/api/memory/timeline")
def get_memory_timeline():
    """Retrieve chronological timeline of organizational security learnings."""
    return hindsight.get_timeline()

@app.get("/api/intelligence/recurring", response_model=List[RecurringPattern])
def get_recurring_patterns():
    """Detect recurring vulnerabilities and organizational systemic blindspots."""
    return orchestrator.get_recurring_patterns()

# --- Compliance & Audit Endpoints ---

@app.post("/api/compliance/audit", response_model=AuditReport)
def execute_audit_query(payload: AuditQuery):
    """
    Process natural language auditor query against Hindsight organizational memory.
    Returns formatted audit findings, remediation verification status, and evidence artifacts.
    """
    return orchestrator.query_audit(payload)

# --- Demo & Reset Utilities ---

@app.post("/api/demo/seed")
def seed_demo_data():
    """Seed baseline incident INC-1024 and related security history."""
    res = seed_baseline_data(reset_first=True)
    return res

@app.post("/api/demo/reset")
def reset_demo_state():
    """Wipe memory and incident database clean for live hackathon presentation."""
    hindsight.reset_memory()
    incident_store.clear()
    return {"status": "RESET_COMPLETE", "memories": 0, "incidents": 0}

# --- Static Frontend Mount ---
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

@app.get("/")
def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"message": "Hindsight SecOps Backend Running. Place frontend files in frontend/"}

# Fallback for SPA routing
@app.get("/{full_path:path}")
def serve_spa_paths(full_path: str):
    file_path = FRONTEND_DIR / full_path
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    index_file = FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse(status_code=404, content={"detail": "Not Found"})
