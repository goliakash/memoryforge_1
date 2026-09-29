import pytest
from backend.app.models.incident import IncidentCreate, IncidentSeverity, IncidentStatus
from backend.app.agents.incident_agent import incident_agent
from backend.app.agents.orchestrator import orchestrator

def test_incident_initialization_lifecycle():
    payload = IncidentCreate(
        title="Unauthorized S3 Bucket Exposure",
        description="Public bucket policy detected on raw-data-bucket",
        severity=IncidentSeverity.HIGH,
        affected_asset="raw-data-bucket",
        asset_type="Cloud Storage"
    )

    incident = incident_agent.investigate(payload)

    # Newly investigated incident MUST start in IN_PROGRESS, NOT REMEDIATED or VERIFIED
    assert incident.status == IncidentStatus.IN_PROGRESS

    # Remediation playbook steps MUST start in PENDING/IN_PROGRESS
    for step in incident.remediation_playbook:
        assert step.status in ["PENDING", "IN_PROGRESS"]

    # Controls MUST indicate action required before verification
    for control in incident.controls:
        assert control.audit_status == "ACTION_REQUIRED"

def test_remediation_execution_and_verification():
    payload = IncidentCreate(
        title="Public Access S3 Bucket Leak",
        description="Bucket customer-data-bucket exposed publicly",
        severity=IncidentSeverity.HIGH,
        affected_asset="customer-data-bucket",
        asset_type="Cloud Storage"
    )

    incident = orchestrator.process_incident(payload)
    inc_id = incident.id
    assert incident.status == IncidentStatus.IN_PROGRESS

    # Execute step 1
    step_1_id = incident.remediation_playbook[0].id
    orchestrator.execute_step_remediation(inc_id, step_1_id, target_status="REMEDIATED")

    inc_after_step1 = orchestrator.store.get(inc_id)
    assert inc_after_step1.status == IncidentStatus.REMEDIATED

    # Execute full remediation
    orchestrator.execute_full_remediation(inc_id)
    inc_final = orchestrator.store.get(inc_id)

    # After full execution, status MUST transition to VERIFIED
    assert inc_final.status == IncidentStatus.VERIFIED
    for step in inc_final.remediation_playbook:
        assert step.status == "VERIFIED"
    for control in inc_final.controls:
        assert control.audit_status == "VERIFIED"
    assert any("Remediation Verification" in ev.type for ev in inc_final.evidence_vault)
