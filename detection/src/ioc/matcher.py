"""
IOC Matching Engine — Module 2: Detection & Risk Engine
Matches event attributes against threat intelligence indicators and preserves
evidence traceability (evidence_event_id).
"""

from typing import List, Optional
from pydantic import BaseModel, Field

from detection.src.ioc.client import BaseThreatIntelClient, LocalMockThreatIntelClient
from detection.src.models import NormalizedEvent


class IOCHitMatch(BaseModel):
    """
    Represents a single Indicator of Compromise (IOC) match result.
    Preserves evidence traceability via evidence_event_id.
    """
    ioc_type: str  # 'ip', 'domain', 'url', 'file_hash'
    matched_value: str
    source_field: str  # 'src_ip', 'dst_ip', 'domain', 'url', 'file_hash'
    threat_label: str
    severity: str = "high"
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)
    evidence_event_id: str


class IOCMatcher:
    """
    Evaluates NormalizedEvent fields against threat intelligence indicators.
    """

    def __init__(self, client: Optional[BaseThreatIntelClient] = None) -> None:
        self.client = client if client is not None else LocalMockThreatIntelClient()

    def match_event(self, event: NormalizedEvent) -> List[IOCHitMatch]:
        """
        Extracts indicator fields from NormalizedEvent and queries threat intelligence client.
        Safely handles missing optional normalized fields and sets evidence_event_id.
        """
        hits: List[IOCHitMatch] = []
        normalized_data = event.normalized if isinstance(event.normalized, dict) else {}

        # 1. Check src_ip
        src_ip = normalized_data.get("src_ip")
        if src_ip and isinstance(src_ip, str):
            res = self.client.lookup_ip(src_ip)
            if res:
                hits.append(
                    IOCHitMatch(
                        ioc_type="ip",
                        matched_value=src_ip,
                        source_field="src_ip",
                        threat_label=res.get("threat_label", "Malicious IP"),
                        severity=res.get("severity", "high"),
                        confidence=res.get("confidence", 0.90),
                        evidence_event_id=event.event_id,
                    )
                )

        # 2. Check dst_ip
        dst_ip = normalized_data.get("dst_ip")
        if dst_ip and isinstance(dst_ip, str):
            res = self.client.lookup_ip(dst_ip)
            if res:
                hits.append(
                    IOCHitMatch(
                        ioc_type="ip",
                        matched_value=dst_ip,
                        source_field="dst_ip",
                        threat_label=res.get("threat_label", "Malicious IP"),
                        severity=res.get("severity", "high"),
                        confidence=res.get("confidence", 0.90),
                        evidence_event_id=event.event_id,
                    )
                )

        # 3. Check domain
        domain = normalized_data.get("domain")
        if domain and isinstance(domain, str):
            res = self.client.lookup_domain(domain)
            if res:
                hits.append(
                    IOCHitMatch(
                        ioc_type="domain",
                        matched_value=domain,
                        source_field="domain",
                        threat_label=res.get("threat_label", "Malicious Domain"),
                        severity=res.get("severity", "high"),
                        confidence=res.get("confidence", 0.90),
                        evidence_event_id=event.event_id,
                    )
                )

        # 4. Check url
        url = normalized_data.get("url")
        if url and isinstance(url, str):
            res = self.client.lookup_url(url)
            if res:
                hits.append(
                    IOCHitMatch(
                        ioc_type="url",
                        matched_value=url,
                        source_field="url",
                        threat_label=res.get("threat_label", "Malicious URL"),
                        severity=res.get("severity", "high"),
                        confidence=res.get("confidence", 0.90),
                        evidence_event_id=event.event_id,
                    )
                )

        # 5. Check file_hash
        file_hash = normalized_data.get("file_hash")
        if file_hash and isinstance(file_hash, str):
            res = self.client.lookup_hash(file_hash)
            if res:
                hits.append(
                    IOCHitMatch(
                        ioc_type="file_hash",
                        matched_value=file_hash,
                        source_field="file_hash",
                        threat_label=res.get("threat_label", "Malicious File Hash"),
                        severity=res.get("severity", "high"),
                        confidence=res.get("confidence", 0.90),
                        evidence_event_id=event.event_id,
                    )
                )

        return hits
