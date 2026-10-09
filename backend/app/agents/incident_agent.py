
import hashlib
import uuid
from datetime import datetime
from typing import List, Optional, Tuple

from ..models.incident import (
    Incident,
    IncidentCreate,
    IncidentStatus,
    EvidenceItem,
    EvidenceSourceState,
    RemediationStep,
    PostMortem,
)
from .compliance_agent import compliance_agent
from .hindsight_agent import hindsight_agent


class IncidentAgent:
    """
    MemoryForge Security Investigation Agent.

    Responsibilities:
    1. Classify an incoming incident.
    2. Query organizational memory for historical precedents.
    3. Derive a preliminary, evidence-aware root cause.
    4. Generate a domain-specific remediation playbook.
    5. Map relevant compliance controls.
    6. Preserve evidence with SHA-256 hashes.
    7. Generate a post-mortem that distinguishes proposed work
       from completed and verified remediation.

    Important:
    - Historical memory is advisory, not proof.
    - This agent does not execute real remediation commands.
    - Generated evidence is explicitly marked as simulated.
    """

    def __init__(self):
        self.memory_agent = hindsight_agent
        self.compliance = compliance_agent

    @staticmethod
    def _generate_sha256(content: str) -> str:
        """Return the SHA-256 digest of a string."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _classify_domain(text: str) -> str:
        """
        Classify an incident using simple, explainable rules.

        This is a preliminary classifier, not a replacement for
        investigation or validation against actual evidence.
        """
        value = text.lower()

        ssh_terms = (
            "ssh",
            "port 22",
            "administrative port",
            "brute-force",
            "brute force",
            "login failure",
            "authentication failure",
            "repeated login",
            "rate limiting",
        )

        secret_terms = (
            "api key",
            "credential",
            "secret exposed",
            "exposed secret",
            "token exposed",
            "hardcoded password",
            "password leak",
        )

        storage_terms = (
            "s3",
            "bucket",
            "cloud storage",
            "public storage",
            "public read access",
            "storage exposure",
        )

        if any(term in value for term in ssh_terms):
            return "ssh"

        if any(term in value for term in secret_terms):
            return "secrets"

        if any(term in value for term in storage_terms):
            return "storage"

        return "general"

    def _identify_domain(self, incident_create: IncidentCreate) -> str:
        """
        Prefer the incident title, description and asset type.
        Use raw evidence as a secondary source when needed.
        """
        primary_text = " ".join(
            [
                incident_create.title,
                incident_create.description,
                incident_create.asset_type or "",
            ]
        )

        domain = self._classify_domain(primary_text)

        if domain != "general":
            return domain

        return self._classify_domain(
            incident_create.raw_evidence or ""
        )

    def _derive_root_cause(
        self,
        incident_create: IncidentCreate,
        domain: str,
    ) -> str:
        """
        Produce a preliminary root-cause hypothesis.

        A retrieved memory does not automatically override the
        current incident's evidence.
        """
        if domain == "ssh":
            return (
                "Potentially excessive SSH exposure, repeated "
                "authentication attempts, or insufficient "
                "authentication controls. Confirm the effective "
                "network rules and authentication logs."
            )

        if domain == "secrets":
            return (
                "Potential exposure of a credential or secret. "
                "Confirm where the secret was exposed, whether it "
                "remains valid, and whether unauthorized use occurred."
            )

        if domain == "storage":
            return (
                "Potentially excessive public access to cloud storage. "
                "Validate the effective resource policy, access "
                "settings, and available audit evidence."
            )

        return (
            "Root cause has not been established. Investigate the "
            "affected asset, observed evidence, access controls, "
            "and relevant logs before selecting a remediation."
        )

    def _build_remediation_playbook(
        self,
        incident_id: str,
        domain: str,
        affected_asset: str,
    ) -> List[RemediationStep]:
        """
        Generate a domain-specific remediation checklist.

        These steps are proposed actions. Their status remains
        PENDING until the application records a subsequent status
        transition. The checklist does not execute real commands.
        """
        playbooks = {
            "ssh": [
                (
                    "Review SSH ingress rules and restrict access "
                    "to approved source IPs or VPN ranges.",
                    "Reduce exposure of administrative access.",
                    "Inspect effective security-group or firewall rules.",
                ),
                (
                    "Review authentication logs for repeated failures "
                    "and suspicious successful logins.",
                    "Establish the scope and timeline of possible access.",
                    "Inspect SSH authentication logs for the relevant period.",
                ),
                (
                    "Review SSH daemon configuration and disable "
                    "password or root login where appropriate.",
                    "Reduce exposure to credential-based attacks.",
                    "Review effective SSH configuration with sshd -T "
                    "where supported.",
                ),
                (
                    "Evaluate rate limiting or an approved "
                    "intrusion-prevention control.",
                    "Reduce repeated authentication attempts.",
                    "Inspect the configured control and subsequent "
                    "authentication logs.",
                ),
            ],
            "secrets": [
                (
                    "Revoke and rotate the potentially exposed credential.",
                    "Prevent continued use of a compromised secret.",
                    "Verify that the old credential is rejected and "
                    "the replacement works.",
                ),
                (
                    "Review audit logs for use of the exposed credential.",
                    "Determine whether unauthorized access occurred.",
                    "Inspect relevant audit logs for suspicious activity.",
                ),
                (
                    "Remove the secret from active code and configuration.",
                    "Prevent continued exposure through application files.",
                    "Scan the current code and deployment configuration "
                    "without printing secret values.",
                ),
                (
                    "Introduce secret-manager storage and automated "
                    "secret scanning.",
                    "Reduce the likelihood of recurring exposure.",
                    "Verify the secret-scanning control in the "
                    "development pipeline.",
                ),
            ],
            "storage": [
                (
                    "Review and remove unauthorized public bucket access.",
                    "Contain unintended data exposure.",
                    "Inspect the bucket policy, ACLs, and effective "
                    "public-access settings.",
                ),
                (
                    "Review appropriate bucket-level and account-level "
                    "Block Public Access settings.",
                    "Prevent unintended public storage access.",
                    "Inspect effective bucket and account-level settings.",
                ),
                (
                    "Review IAM and resource policies for unauthorized "
                    "principals and excessive permissions.",
                    "Enforce least privilege.",
                    "Inspect relevant policies for unintended "
                    "wildcard principals or permissions.",
                ),
                (
                    "Review cloud audit logging and configuration "
                    "drift monitoring.",
                    "Improve detection of access and policy changes.",
                    "Verify the relevant logging and monitoring settings.",
                ),
            ],
            "general": [
                (
                    "Preserve the available evidence and establish "
                    "the scope of the incident.",
                    "Avoid losing useful forensic information.",
                    "Review evidence timestamps, hashes, and source records.",
                ),
                (
                    "Inspect the affected asset's configuration "
                    "and access controls.",
                    "Identify the actual misconfiguration or attack path.",
                    "Review the relevant configuration and access-control evidence.",
                ),
                (
                    "Prepare a remediation plan appropriate to "
                    "the confirmed root cause.",
                    "Avoid applying an unrelated or unverified fix.",
                    "Review the proposed change against the observed finding.",
                ),
                (
                    "Define monitoring and a verification procedure "
                    "for the proposed fix.",
                    "Confirm that the identified risk has been addressed.",
                    "Document the verification results and remaining risks.",
                ),
            ],
        }

        selected_playbook = playbooks[domain]
        remediation_steps: List[RemediationStep] = []

        for index, (action, rationale, verification) in enumerate(
            selected_playbook,
            start=1,
        ):
            remediation_steps.append(
                RemediationStep(
                    id=f"REM-{incident_id}-{index:02d}",
                    step_number=index,
                    action=action,
                    rationale=rationale,
                    status="PENDING",
                    verification_command=verification,
                )
            )

        return remediation_steps

    def _build_evidence(
        self,
        incident_create: IncidentCreate,
        incident_id: str,
        domain: str,
    ) -> List[EvidenceItem]:
        """
        Preserve the evidence supplied to the investigation.

        This method does not fabricate scanner output, successful
        remediation logs, or proof that a real cloud resource was scanned.
        """
        evidence: List[EvidenceItem] = []

        if incident_create.raw_evidence:
            evidence_content = incident_create.raw_evidence
        else:
            evidence_content = (
                f"Incident ID: {incident_id}\n"
                f"Title: {incident_create.title}\n"
                f"Description: {incident_create.description}\n"
                f"Affected asset: {incident_create.affected_asset}\n"
                f"Asset type: {incident_create.asset_type or 'Unknown'}\n"
                f"Environment: {incident_create.environment or 'Unknown'}\n"
                f"Classification: {domain}\n"
                "Note: This is an incident summary, not an independent "
                "scanner result or verified configuration snapshot."
            )

        evidence.append(
            EvidenceItem(
                id=f"EV-{incident_id}-01",
                filename=f"incident_evidence_{incident_id}.txt",
                type="Incident Evidence (UNVERIFIED)",
                description=(
                    "Evidence supplied with the incident or a generated "
                    "incident summary. It has not been independently "
                    "validated by this agent."
                ),
                content_preview=evidence_content,
                sha256_hash=self._generate_sha256(evidence_content),
                source_state=EvidenceSourceState.SIMULATED,
            )
        )

        return evidence

    def investigate(self, incident_create: IncidentCreate) -> Incident:
        """
        Investigate an incoming incident and prepare a proposed response.
        """
        incident_id = (
            incident_create.incident_id
            or f"INC-{uuid.uuid4().hex[:8].upper()}"
        )

        domain = self._identify_domain(incident_create)

        # Step 1: Search organizational memory.
        query_text = " ".join(
            [
                incident_create.title,
                incident_create.description,
                incident_create.affected_asset,
                incident_create.asset_type or "",
                incident_create.raw_evidence or "",
            ]
        )

        recalled_precedent = None
        similarity_score: Optional[float] = None
        investigation_notes = (
            f"Incident classified as '{domain}'. "
            "Root cause and remediation remain subject to evidence review."
        )

        try:
            recall_response = self.memory_agent.recall_prior_knowledge(
                query_text,
                exclude_id=incident_id,
            )

            if (
                recall_response.matches
                and recall_response.highest_similarity >= 0.50
            ):
                candidate = recall_response.matches[0]

                # A similarity score alone does not prove that a
                # precedent belongs to the same incident domain.
                candidate_text = " ".join(
                    [
                        candidate.title,
                        candidate.matched_root_cause,
                        candidate.summary_explanation,
                        " ".join(candidate.matched_controls),
                        " ".join(candidate.verified_remediation_summary),
                    ]
                )

                candidate_domain = self._classify_domain(candidate_text)

                if (
                    domain != "general"
                    and candidate_domain == domain
                ):
                    recalled_precedent = candidate
                    similarity_score = candidate.similarity_score

                    investigation_notes = (
                        f"Historical memory candidate "
                        f"{candidate.incident_id} retrieved with "
                        f"{candidate.similarity_percentage}% similarity. "
                        "This candidate shares the preliminary incident "
                        "domain, but its evidence and remediation must "
                        "still be validated before reuse."
                    )
                else:
                    investigation_notes = (
                        "Historical memory returned a possible precedent, "
                        "but its incident domain could not be safely "
                        "matched. It was not automatically applied."
                    )

        except Exception as exc:
            # The incident can still be investigated if memory recall
            # is temporarily unavailable.
            investigation_notes = (
                "Historical memory recall was unavailable during this "
                "investigation. Root-cause and remediation suggestions "
                f"were generated without a recalled precedent "
                f"({type(exc).__name__})."
            )

        # Step 2: Derive a preliminary root-cause hypothesis.
        root_cause = self._derive_root_cause(
            incident_create,
            domain,
        )

        # Step 3: Build a playbook for the current incident domain.
        # Do not blindly copy historical remediation commands.
        remediation_steps = self._build_remediation_playbook(
            incident_id,
            domain,
            incident_create.affected_asset,
        )

        # Step 4: Map compliance controls.
        controls = self.compliance.map_controls_for_incident(
            incident_create.title,
            incident_create.description,
            incident_create.asset_type or "Unknown",
        )

        # Step 5: Preserve supplied evidence without claiming it
        # was independently observed or verified.
        evidence_vault = self._build_evidence(
            incident_create,
            incident_id,
            domain,
        )

        # Step 6: Prepare an accurate preliminary post-mortem.
        pending_count = sum(
            1
            for step in remediation_steps
            if step.status != "VERIFIED"
        )

        post_mortem = PostMortem(
            summary=(
                f"Incident {incident_id} ({incident_create.title}) "
                f"affects asset '{incident_create.affected_asset}'. "
                f"Preliminary root-cause assessment: {root_cause} "
                f"A playbook containing {len(remediation_steps)} steps "
                f"was generated; {pending_count} steps remain unverified. "
                "This report does not claim remediation is complete."
            ),
            root_cause_analysis=(
                f"Preliminary assessment for the '{domain}' incident "
                f"affecting '{incident_create.affected_asset}': "
                f"{root_cause} Validate this hypothesis against actual "
                "configuration, access logs, and other available evidence "
                "before making a final determination."
                + (
                    f" A potentially related historical incident is "
                    f"{recalled_precedent.incident_id}; its remediation "
                    "has not been automatically applied."
                    if recalled_precedent
                    else ""
                )
            ),
            preventive_actions=[
                "Validate the root cause against collected evidence.",
                "Implement an appropriate preventive control after review.",
                "Verify remediation and monitor for recurrence.",
            ],
            lessons_learned=[
                "Historical similarity is supporting evidence, not proof.",
                "Proposed remediation must be distinguished from completed work.",
                "Preserve evidence provenance and document verification results.",
            ],
            timeline=[
                {
                    "time": datetime.utcnow().isoformat() + "Z",
                    "event": (
                        "Incident received; preliminary investigation, "
                        "memory review, and remediation planning completed. "
                        "Remediation has not been independently verified."
                    ),
                }
            ],
        )

        # Step 7: Construct the incident.
        incident = Incident(
            id=incident_id,
            title=incident_create.title,
            description=incident_create.description,
            severity=incident_create.severity,
            affected_asset=incident_create.affected_asset,
            asset_type=incident_create.asset_type or "Unknown",
            environment=incident_create.environment or "Production",
            raw_evidence=incident_create.raw_evidence,
            status=IncidentStatus.IN_PROGRESS,
            root_cause=root_cause,
            controls=controls,
            remediation_playbook=remediation_steps,
            evidence_vault=evidence_vault,
            post_mortem=post_mortem,
            memory_retained=False,
            recalled_from_id=(
                recalled_precedent.incident_id
                if recalled_precedent
                else None
            ),
            similarity_score=similarity_score,
            investigation_notes=investigation_notes,
        )

        return incident


incident_agent = IncidentAgent()
