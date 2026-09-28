from datetime import datetime, timedelta
from .models.incident import IncidentCreate, IncidentSeverity
from .agents.orchestrator import orchestrator
from .memory.hindsight_engine import hindsight
from .memory.storage import incident_store

def seed_baseline_data(reset_first: bool = True):
    """
    Populate organizational memory with baseline incidents so the demo can run
    both from scratch and with pre-existing security memory.
    """
    if reset_first:
        hindsight.reset_memory()
        incident_store.clear()

    now = datetime.utcnow()
    
    # 1. Incident INC-1024: The canonical anchor incident from user specification!
    inc_1024_input = IncidentCreate(
        incident_id="INC-1024",
        title="Public Cloud Storage Exposure",
        description="A production storage bucket was discovered with public read access. Configuration scan detected unauthenticated principal '*'.",
        severity=IncidentSeverity.HIGH,
        affected_asset="customer-data-bucket",
        asset_type="Cloud Storage",
        environment="Production",
        raw_evidence="CloudWatch Alert: S3BucketPublicReadAccess. Asset: customer-data-bucket. Principal: *"
    )
    inc_1024 = orchestrator.process_incident(inc_1024_input, auto_retain=True)

    # 2. Incident INC-1012: Historical SSH Exposure
    inc_1012_input = IncidentCreate(
        incident_id="INC-1012",
        title="Unrestricted SSH Port 22 Ingress",
        description="Security group sg-0a8b9f for backend bastion host permitted 0.0.0.0/0 ingress on port 22.",
        severity=IncidentSeverity.HIGH,
        affected_asset="prod-bastion-sg",
        asset_type="Network Security Group",
        environment="Production",
        raw_evidence="GuardDuty Alert: UnauthorizedAccess:EC2/SSHBruteForce. Ingress: 0.0.0.0/0:22"
    )
    inc_1012 = orchestrator.process_incident(inc_1012_input, auto_retain=True)

    # 3. Incident INC-1018: Secret token exposure in dev logs
    inc_1018_input = IncidentCreate(
        incident_id="INC-1018",
        title="Production Stripe API Secret Exposed in Logs",
        description="Application container logged unredacted Stripe API authorization token to CloudWatch log stream.",
        severity=IncidentSeverity.CRITICAL,
        affected_asset="billing-service-worker",
        asset_type="Microservice / Container",
        environment="Production",
        raw_evidence="SecretScanner: Matched pattern 'sk_live_[0-9a-zA-Z]{24}' in /aws/lambda/billing-processor"
    )
    inc_1018 = orchestrator.process_incident(inc_1018_input, auto_retain=True)

    print(f"[Seed] Baseline memory initialized with 3 incidents ({len(hindsight.memories)} memories, {len(hindsight.nodes)} nodes).")
    return {
        "status": "SEEDED",
        "incidents_seeded": ["INC-1024", "INC-1012", "INC-1018"],
        "memory_nodes": len(hindsight.nodes),
        "synapse_links": len(hindsight.links)
    }

if __name__ == "__main__":
    seed_baseline_data()
