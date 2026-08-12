"""
Unit tests for Module 2 Pydantic Data Models
Conforms strictly to docs/CONTRACT.md validation rules.
"""

import pytest
from pydantic import ValidationError
from detection.src.models import (
    NormalizedEvent,
    RiskFactor,
    Alert,
    DetectionStatusResponse,
)


def test_valid_normalized_event():
    """Test creating a valid NormalizedEvent with all fields populated."""
    event_data = {
        "event_id": "evt-123",
        "timestamp": "2026-08-10T12:30:00Z",
        "source": "sysmon",
        "host": "PC-101",
        "user": "admin",
        "event_type": "process_creation",
        "severity_hint": "medium",
        "raw": {"raw_log": "sample log text"},
        "normalized": {
            "process_name": "powershell.exe",
            "command_line": "powershell -enc ...",
        },
    }
    event = NormalizedEvent(**event_data)
    assert event.event_id == "evt-123"
    assert event.timestamp == "2026-08-10T12:30:00Z"
    assert event.source == "sysmon"
    assert event.host == "PC-101"
    assert event.user == "admin"
    assert event.event_type == "process_creation"
    assert event.severity_hint == "medium"
    assert event.raw == {"raw_log": "sample log text"}
    assert event.normalized["process_name"] == "powershell.exe"


def test_normalized_event_null_host_user():
    """Test creating NormalizedEvent where host and user are null (None)."""
    event_data = {
        "event_id": "evt-124",
        "timestamp": "2026-08-10T12:31:00Z",
        "source": "firewall",
        "host": None,
        "user": None,
        "event_type": "network_connection",
        "severity_hint": "low",
        "raw": {},
        "normalized": {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8"},
    }
    event = NormalizedEvent(**event_data)
    assert event.host is None
    assert event.user is None


def test_normalized_event_invalid_severity_hint():
    """Test that invalid severity_hint values trigger a ValidationError."""
    event_data = {
        "event_id": "evt-125",
        "timestamp": "2026-08-10T12:32:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "severity_hint": "super_critical",  # Invalid value
        "raw": {},
        "normalized": {},
    }
    with pytest.raises(ValidationError):
        NormalizedEvent(**event_data)


def test_valid_alert():
    """Test creating a valid Alert adhering to Contract 2 schema."""
    alert_data = {
        "alert_id": "alert-456",
        "created_at": "2026-08-10T12:30:01Z",
        "source_event_ids": ["evt-123"],
        "rule_matched": "suspicious_encoded_powershell",
        "risk_score": 91,
        "risk_factors": [
            {
                "factor": "Encoded PowerShell execution detected",
                "weight": 0.40,
                "evidence_event_id": "evt-123",
            },
            {
                "factor": "Known malicious destination IP",
                "weight": 0.30,
                "evidence_event_id": "evt-123",
            },
        ],
        "mitre_attack": ["T1059.001"],
        "status": "new",
    }
    alert = Alert(**alert_data)
    assert alert.alert_id == "alert-456"
    assert alert.created_at == "2026-08-10T12:30:01Z"
    assert alert.source_event_ids == ["evt-123"]
    assert alert.rule_matched == "suspicious_encoded_powershell"
    assert alert.risk_score == 91
    assert len(alert.risk_factors) == 2
    assert alert.risk_factors[0].evidence_event_id == "evt-123"
    assert alert.mitre_attack == ["T1059.001"]
    assert alert.status == "new"


def test_alert_risk_score_bounds():
    """Test lower (0) and upper (100) risk_score boundary values."""
    base_alert = {
        "alert_id": "alert-bound",
        "created_at": "2026-08-10T12:30:01Z",
        "source_event_ids": ["evt-100"],
        "rule_matched": "test_rule",
        "risk_factors": [],
        "mitre_attack": [],
        "status": "new",
    }

    # Test 0 lower bound
    alert_zero = Alert(**{**base_alert, "risk_score": 0})
    assert alert_zero.risk_score == 0

    # Test 100 upper bound
    alert_hundred = Alert(**{**base_alert, "risk_score": 100})
    assert alert_hundred.risk_score == 100


def test_alert_risk_score_invalid_below_zero():
    """Test that risk_score < 0 is rejected by validation."""
    alert_data = {
        "alert_id": "alert-neg",
        "created_at": "2026-08-10T12:30:01Z",
        "source_event_ids": ["evt-100"],
        "risk_score": -1,
        "status": "new",
    }
    with pytest.raises(ValidationError):
        Alert(**alert_data)


def test_alert_risk_score_invalid_above_hundred():
    """Test that risk_score > 100 is rejected by validation."""
    alert_data = {
        "alert_id": "alert-high",
        "created_at": "2026-08-10T12:30:01Z",
        "source_event_ids": ["evt-100"],
        "risk_score": 101,
        "status": "new",
    }
    with pytest.raises(ValidationError):
        Alert(**alert_data)


def test_alert_status_validation():
    """Test that status must be 'new' and invalid status strings fail validation."""
    base_alert = {
        "alert_id": "alert-status",
        "created_at": "2026-08-10T12:30:01Z",
        "source_event_ids": ["evt-100"],
        "risk_score": 50,
        "status": "investigating",  # Invalid for initial alert creation
    }
    with pytest.raises(ValidationError):
        Alert(**base_alert)


def test_alert_rule_matched_null():
    """Test that rule_matched can be null (None)."""
    alert_data = {
        "alert_id": "alert-no-rule",
        "created_at": "2026-08-10T12:30:01Z",
        "source_event_ids": ["evt-101"],
        "rule_matched": None,
        "risk_score": 45,
        "risk_factors": [
            RiskFactor(
                factor="Anomalous behavior",
                weight=0.45,
                evidence_event_id="evt-101",
            )
        ],
        "mitre_attack": [],
        "status": "new",
    }
    alert = Alert(**alert_data)
    assert alert.rule_matched is None


def test_alert_rejection_missing_evidence_event_id():
    """
    Test critical evidence-first requirement:
    Rejects Alert when risk_factor.evidence_event_id is NOT in source_event_ids.
    """
    alert_data = {
        "alert_id": "alert-bad-evidence",
        "created_at": "2026-08-10T12:30:01Z",
        "source_event_ids": ["evt-123"],
        "rule_matched": "suspicious_powershell",
        "risk_score": 85,
        "risk_factors": [
            {
                "factor": "Malicious activity detected",
                "weight": 0.5,
                "evidence_event_id": "evt-999",  # NOT in source_event_ids!
            }
        ],
        "mitre_attack": ["T1059.001"],
        "status": "new",
    }
    with pytest.raises(ValidationError) as exc_info:
        Alert(**alert_data)
    assert "evt-999" in str(exc_info.value)


def test_valid_detection_status_response():
    """Test creating a valid DetectionStatusResponse model."""
    status_data = {
        "rule_count": 15,
        "alerts_last_hour": 3,
        "model_version": "v1.0.0-ml-shap",
    }
    status = DetectionStatusResponse(**status_data)
    assert status.rule_count == 15
    assert status.alerts_last_hour == 3
    assert status.model_version == "v1.0.0-ml-shap"
