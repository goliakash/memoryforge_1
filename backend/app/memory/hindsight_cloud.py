
import requests

from ..config import (
    HINDSIGHT_API_URL,
    HINDSIGHT_API_KEY,
    HINDSIGHT_BANK_ID,
)


class HindsightCloudClient:
    """Client for Hindsight Cloud memory operations."""

    def __init__(self):
        self.base_url = HINDSIGHT_API_URL.rstrip("/")
        self.bank_id = HINDSIGHT_BANK_ID
        self.session = requests.Session()

        if HINDSIGHT_API_KEY:
            self.session.headers.update({
                "Authorization": f"Bearer {HINDSIGHT_API_KEY}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            })

    @property
    def enabled(self):
        return bool(HINDSIGHT_API_KEY)

    def _request(self, method, path, **kwargs):
        if not self.enabled:
            raise RuntimeError(
                "HINDSIGHT_API_KEY is not configured"
            )

        response = self.session.request(
            method,
            f"{self.base_url}{path}",
            timeout=30,
            **kwargs,
        )
        response.raise_for_status()

        if not response.content:
            return {}

        return response.json()

    def check_connection(self):
        return self._request(
            "GET",
            f"/v1/default/banks/{self.bank_id}",
        )

    def retain_text(self, content, context=None):
        item = {"content": content}

        if context:
            item["context"] = context

        return self._request(
            "POST",
            f"/v1/default/banks/{self.bank_id}/memories",
            json={"items": [item]},
        )

    def recall(self, query, **options):
        payload = {"query": query, **options}

        return self._request(
            "POST",
            f"/v1/default/banks/{self.bank_id}/memories/recall",
            json=payload,
        )


hindsight_cloud = HindsightCloudClient()
