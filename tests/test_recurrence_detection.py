import pytest
from backend.app.models.incident import IncidentCreate, IncidentSeverity
from backend.app.agents.orchestrator import orchestrator

def test_multi_signal_fusion_recurrence():
    # 1. Ingest and retain base anchor incident INC-1024
    inc1 = orchestrator.process_incident(IncidentCreate(
        incident_id="INC-1024",
        title="Public S3 Bucket Policy Exposure",
        description="Public bucket policy detected on raw-data-bucket allowing unauthenticated principal access",
        severity=IncidentSeverity.HIGH,
        affected_asset="raw-data-bucket",
        asset_type="Cloud Storage"
    ), auto_retain=True)

    # 2. Ingest similar incident INC-1038
    inc2 = orchestrator.process_incident(IncidentCreate(
        incident_id="INC-1038",
        title="Data Lake Storage Public Exposure",
        description="Unrestricted read permission detected on analytics-lake-raw storage bucket",
        severity=IncidentSeverity.CRITICAL,
        affected_asset="analytics-lake-raw",
        asset_type="Cloud Storage"
    ))

    # Recall check
    resp = orchestrator.query_memory_recall("Data Lake Storage Public Exposure analytics-lake-raw")
    assert resp.total_matches >= 1
    best_match = resp.matches[0]

    assert best_match.incident_id == "INC-1024"
    assert best_match.similarity_score > 0.60
    assert best_match.signal_breakdown is not None
    assert "semantic_text_similarity" in best_match.signal_breakdown
    assert best_match.recurrence_rationale is not None
