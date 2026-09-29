import pytest
from backend.app.models.incident import IncidentCreate, IncidentSeverity
from backend.app.models.audit import AuditQuery
from backend.app.agents.orchestrator import orchestrator

def test_full_orchestrator_memory_loop():
    # 1. Incident INC-1024 arrives
    inc1 = orchestrator.process_incident(IncidentCreate(
        incident_id="INC-1024",
        title="S3 Bucket Public Access Exposure",
        description="Public bucket policy detected on raw-data-bucket",
        severity=IncidentSeverity.HIGH,
        affected_asset="raw-data-bucket",
        asset_type="Cloud Storage"
    ), auto_retain=True)

    # 2. Before remediation execution, audit query returns ACTION_REQUIRED (0% verified compliance)
    report_initial = orchestrator.query_audit(AuditQuery(query="Show access control findings"))
    assert report_initial.total_findings >= 1
    finding_1 = next(f for f in report_initial.findings if f.incident_id == "INC-1024")
    assert finding_1.remediation_status in ["ACTION_REQUIRED", "IN_PROGRESS"]
    assert finding_1.auditor_signoff_ready is False

    # 3. Execute and verify remediation for INC-1024
    orchestrator.execute_full_remediation("INC-1024")

    # 4. Ingest similar incident INC-1038
    inc2 = orchestrator.process_incident(IncidentCreate(
        incident_id="INC-1038",
        title="Data Lake Storage Public Exposure",
        description="Public bucket policy on analytics-lake-raw",
        severity=IncidentSeverity.CRITICAL,
        affected_asset="analytics-lake-raw",
        asset_type="Cloud Storage"
    ), auto_retain=True)

    # Memory recall check: INC-1038 recalls INC-1024
    assert inc2.recalled_from_id == "INC-1024"
    assert inc2.similarity_score > 0.50

    # Execute remediation for INC-1038
    orchestrator.execute_full_remediation("INC-1038")

    # 5. After remediation execution and verification, audit query confirms VERIFIED_CLOSED and 100% compliance
    report_final = orchestrator.query_audit(AuditQuery(query="Show access control findings"))
    finding_1_final = next(f for f in report_final.findings if f.incident_id == "INC-1024")
    finding_2_final = next(f for f in report_final.findings if f.incident_id == "INC-1038")

    assert finding_1_final.remediation_status == "VERIFIED_CLOSED"
    assert finding_1_final.auditor_signoff_ready is True
    assert finding_2_final.remediation_status == "VERIFIED_CLOSED"
    assert finding_2_final.auditor_signoff_ready is True
    assert report_final.compliance_rate_percent == 100.0
    assert report_final.memory_attestation_hash is not None
