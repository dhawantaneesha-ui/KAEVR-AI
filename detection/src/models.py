"""
Module 2 Data Models — Detection & Risk Engine
Conforms strictly to docs/CONTRACT.md schemas.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator


class NormalizedEvent(BaseModel):
    """
    Contract 1 — NormalizedEvent (Module 1 -> Module 2)
    Represents standardized security telemetry received from Ingestion layer.
    """
    event_id: str
    timestamp: str
    source: str
    host: Optional[str] = None
    user: Optional[str] = None
    event_type: str
    severity_hint: Literal["low", "medium", "high", "critical", "unknown"]
    raw: Dict[str, Any] = Field(default_factory=dict)
    normalized: Dict[str, Any] = Field(default_factory=dict)


class RiskFactor(BaseModel):
    """
    Explains individual contributing risk factors to an Alert.
    Part of Contract 2 (Alert).
    """
    factor: str
    weight: float
    evidence_event_id: str


class Alert(BaseModel):
    """
    Contract 2 — Alert (Module 2 -> Module 3)
    Represents evidence-backed threat detection alert sent to Supervisor AI.
    """
    alert_id: str
    created_at: str
    source_event_ids: List[str]
    rule_matched: Optional[str] = None
    risk_score: int = Field(ge=0, le=100)
    risk_factors: List[RiskFactor] = Field(default_factory=list)
    mitre_attack: List[str] = Field(default_factory=list)
    status: Literal["new"] = "new"

    @model_validator(mode="after")
    def validate_evidence_event_ids(self) -> "Alert":
        """
        Evidence-first requirement validation:
        Every RiskFactor.evidence_event_id must reference an ID that exists
        in the Alert.source_event_ids array.
        """
        source_ids_set = set(self.source_event_ids)
        for rf in self.risk_factors:
            if rf.evidence_event_id not in source_ids_set:
                raise ValueError(
                    f"Risk factor evidence_event_id '{rf.evidence_event_id}' "
                    f"is not present in source_event_ids: {self.source_event_ids}"
                )
        return self


class DetectionStatusResponse(BaseModel):
    """
    Status response schema for GET /api/detection/status
    Exposes Detection & Risk Engine metrics.
    """
    rule_count: int = Field(ge=0)
    alerts_last_hour: int = Field(ge=0)
    model_version: str
