import re
from typing import Any, Dict, List, Optional

from ..memory.hindsight_engine import hindsight
from ..memory.hindsight_cloud import hindsight_cloud
from ..models.incident import Incident
from ..models.memory import (
    RecallQuery,
    RecallMatch,
    RecallResponse,
    MemoryGraph,
    RecurringPattern,
)


class HindsightAgent:
    """Coordinates local security memory and Hindsight Cloud."""

    def __init__(self):
        self.engine = hindsight
        self.cloud = hindsight_cloud

    def recall_prior_knowledge(
        self,
        query_text: str,
        control_filter: Optional[str] = None,
        exclude_id: Optional[str] = None,
    ) -> RecallResponse:
        query = RecallQuery(
            text=query_text,
            control_filter=control_filter,
            min_similarity=0.35,
            top_k=4,
        )

        if not self.cloud.enabled:
            result = self.engine.recall(query, exclude_id=exclude_id)
            result.agent_advice = (
                "Hindsight Cloud is not configured; using local memory. "
                + result.agent_advice
            )
            return result

        try:
            cloud_query = query_text
            if control_filter:
                cloud_query += f" Security control: {control_filter}"

            response = self.cloud.recall(cloud_query)
            matches: List[RecallMatch] = []

            for item in response.get("results", []):
                text = str(item.get("text", ""))
                scores = item.get("scores") or {}

                id_match = re.search(
                    r"\bIncident ID:\s*([A-Za-z0-9_.:-]+)",
                    text,
                    re.IGNORECASE,
                )

                incident_id = id_match.group(1) if id_match else None

                if not incident_id:
                    # A cloud document UUID is not necessarily the original incident ID.
                    continue

                if exclude_id and incident_id == exclude_id:
                    continue


                if exclude_id and incident_id == exclude_id:
                    continue

                raw_score = scores.get("semantic")
                if raw_score is None:
                    raw_score = scores.get("final", 0.0)

                score = max(0.0, min(1.0, float(raw_score or 0.0)))
                if score < query.min_similarity:
                    continue

                title_match = re.search(
                    r"\bTitle:\s*(.+?)(?:\s*\|\s*|\n|$)",
                    text,
                    re.IGNORECASE,
                )
                root_match = re.search(
                    r"\bRoot cause:\s*(.+?)(?:\s*\|\s*|\n|$)",
                    text,
                    re.IGNORECASE,
                )

                entities = item.get("entities") or []
                detected_at = str(
                    item.get("occurred_start")
                    or item.get("mentioned_at")
                    or ""
                )

                matches.append(
                    RecallMatch(
                        incident_id=incident_id,
                        title=(
                            title_match.group(1).strip()
                            if title_match
                            else f"Prior security memory: {incident_id}"
                        ),
                        similarity_score=round(score, 3),
                        similarity_percentage=round(score * 100),
                        matched_root_cause=(
                            root_match.group(1).strip()
                            if root_match
                            else text[:500]
                        ),
                        matched_controls=[str(x) for x in entities],
                        verified_remediation_summary=[],
                        evidence_count=0,
                        detected_at=detected_at,
                        summary_explanation=text,
                        signal_breakdown={
                            str(k): float(v)
                            for k, v in scores.items()
                            if isinstance(v, (int, float))
                        },
                        recurrence_rationale=(
                            "Retrieved from Hindsight Cloud. Verify the original "
                            "incident and remediation before reusing a playbook."
                        ),
                    )
                )

            matches.sort(
                key=lambda match: match.similarity_score,
                reverse=True,
            )
            matches = matches[:query.top_k]
            highest = matches[0].similarity_score if matches else 0.0


            if not matches:
                local_result = self.engine.recall(query, exclude_id=exclude_id)
                local_result.agent_advice = (
                    "Hindsight Cloud returned no usable matches; "
                    "falling back to local memory. "
                    + local_result.agent_advice
                )
                return local_result

            advice = f"Hindsight Cloud returned {len(matches)} relevant memories."

            return RecallResponse(
                query=query_text,
                total_matches=len(matches),
                highest_similarity=highest,
                matches=matches,
                agent_advice=advice,
            )


        except Exception as exc:
            local_result = self.engine.recall(query, exclude_id=exclude_id)
            local_result.agent_advice = (
                "WARNING: Hindsight Cloud recall failed; displaying local-memory "
                f"results instead ({type(exc).__name__}). "
                + local_result.agent_advice
            )
            return local_result

    def retain_investigation(self, incident: Incident) -> Dict[str, Any]:
        """Retain an investigation locally and in Hindsight Cloud."""

        # Preserve the existing graph, timeline and local memory.
        local_result = self.engine.retain(incident)

        if not self.cloud.enabled:
            raise RuntimeError(
                "Incident was saved locally, but Hindsight Cloud is not configured."
            )

        controls = [
            (
                f"{c.framework} {c.control_id}: {c.control_name}; "
                f"requirement: {c.requirement}"
            )
            for c in incident.controls
        ]

        remediation = [
            (
                f"{step.action}; status: {step.status}; "
                f"rationale: {step.rationale}"
            )
            for step in incident.remediation_playbook
        ]

        post_mortem = (
            incident.post_mortem.model_dump(mode="json")
            if incident.post_mortem
            else None
        )

        content = (
            f"Incident ID: {incident.id}\n"
            f"Title: {incident.title}\n"
            f"Description: {incident.description}\n"
            f"Severity: {incident.severity.value}\n"
            f"Status: {incident.status.value}\n"
            f"Affected asset: {incident.affected_asset}\n"
            f"Asset type: {incident.asset_type}\n"
            f"Environment: {incident.environment}\n"
            f"Root cause: {incident.root_cause or 'Investigation pending'}\n"
            f"Controls: {'; '.join(controls) or 'None recorded'}\n"
            f"Remediation: {'; '.join(remediation) or 'None recorded'}\n"
            f"Post-mortem: {post_mortem or 'Not available'}\n"
            f"Investigation notes: {incident.investigation_notes or 'None'}"
        )

        # Let exceptions propagate so the caller cannot mistake a failed
        # cloud write for successful cloud retention.
        cloud_result = self.cloud.retain_text(
            content,
            context=(
                "MemoryForge security investigation. Preserve incident details, "
                "root cause, compliance controls, remediation and lessons learned."
            ),
        )

        return {
            **local_result,
            "cloud_status": "RETAINED",
            "cloud_bank_id": self.cloud.bank_id,
            "cloud_response": cloud_result,
        }

    def get_memory_graph(self) -> MemoryGraph:
        return self.engine.get_memory_graph()

    def get_recurring_patterns(self) -> List[RecurringPattern]:
        return self.engine.detect_recurring_patterns()

    def get_timeline(self) -> List[Dict[str, Any]]:
        return self.engine.get_timeline()


hindsight_agent = HindsightAgent()
