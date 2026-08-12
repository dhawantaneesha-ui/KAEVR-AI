"""
Unit tests for Module 2 Sigma Detection Engine (Phase 2A)
Verifies YAML rule loading, matching logic, safety on missing fields,
and structured match metadata.
"""

from pathlib import Path
import pytest
from detection.src.models import NormalizedEvent
from detection.src.sigma.engine import SigmaEngine, SigmaRuleMatch


@pytest.fixture
def sigma_engine() -> SigmaEngine:
    """Fixture initializing SigmaEngine with rules directory."""
    return SigmaEngine()


def test_rule_loading(sigma_engine: SigmaEngine):
    """Test that valid YAML rules are loaded from default rules directory."""
    assert len(sigma_engine.rules) >= 2
    rule_ids = [r.get("id") for r in sigma_engine.rules]
    assert "sigma-powershell-encoded" in rule_ids
    assert "sigma-failed-login-attempt" in rule_ids


def test_powershell_positive_match(sigma_engine: SigmaEngine):
    """Test that encoded PowerShell execution triggers a match."""
    event = NormalizedEvent(
        event_id="evt-101",
        timestamp="2026-08-12T10:00:00Z",
        source="sysmon",
        host="WORKSTATION-1",
        user="john_doe",
        event_type="process_creation",
        severity_hint="high",
        raw={},
        normalized={
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -enc JABzAD0...",
        },
    )

    matches = sigma_engine.evaluate(event)
    assert len(matches) == 1
    match = matches[0]
    assert isinstance(match, SigmaRuleMatch)
    assert match.rule_id == "sigma-powershell-encoded"
    assert match.title == "Suspicious Encoded PowerShell Execution"
    assert match.severity == "high"
    assert "T1059.001" in match.mitre_attack


def test_powershell_normal_no_match(sigma_engine: SigmaEngine):
    """Test that normal unencoded PowerShell execution produces no match."""
    event = NormalizedEvent(
        event_id="evt-102",
        timestamp="2026-08-12T10:01:00Z",
        source="sysmon",
        host="WORKSTATION-1",
        user="john_doe",
        event_type="process_creation",
        severity_hint="low",
        raw={},
        normalized={
            "process_name": "powershell.exe",
            "command_line": "powershell.exe Get-Process",
        },
    )

    matches = sigma_engine.evaluate(event)
    assert len(matches) == 0


def test_unrelated_event_no_match(sigma_engine: SigmaEngine):
    """Test that an unrelated process execution (cmd.exe) produces no match."""
    event = NormalizedEvent(
        event_id="evt-103",
        timestamp="2026-08-12T10:02:00Z",
        source="sysmon",
        host="WORKSTATION-1",
        user="admin",
        event_type="process_creation",
        severity_hint="low",
        raw={},
        normalized={
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c dir",
        },
    )

    matches = sigma_engine.evaluate(event)
    assert len(matches) == 0


def test_missing_optional_fields_no_crash(sigma_engine: SigmaEngine):
    """Test that events with missing command_line or process_name cause no crash and no match."""
    event_empty_normalized = NormalizedEvent(
        event_id="evt-104",
        timestamp="2026-08-12T10:03:00Z",
        source="sysmon",
        host=None,
        user=None,
        event_type="process_creation",
        severity_hint="unknown",
        raw={},
        normalized={},
    )

    # Should safely return empty matches without raising KeyError or AttributeError
    matches = sigma_engine.evaluate(event_empty_normalized)
    assert len(matches) == 0


def test_failed_login_signal_match(sigma_engine: SigmaEngine):
    """
    Test that a single failed login event matches the failed login signal rule.
    Verifies that a single failed login is represented as an indicator signal,
    and NOT labeled as a confirmed brute-force attack.
    """
    event = NormalizedEvent(
        event_id="evt-105",
        timestamp="2026-08-12T10:04:00Z",
        source="windows",
        host="SERVER-1",
        user="admin",
        event_type="login_attempt",
        severity_hint="low",
        raw={},
        normalized={
            "status": "failure",
            "src_ip": "192.168.1.50",
        },
    )

    matches = sigma_engine.evaluate(event)
    assert len(matches) == 1
    match = matches[0]
    assert match.rule_id == "sigma-failed-login-attempt"
    assert match.title == "Failed Login Attempt Signal"
    assert match.severity == "low"
    # Ensure rule title/ID does NOT claim one failed login is a confirmed brute-force attack
    assert "brute" not in match.rule_id.lower()
    assert "brute" not in match.title.lower()


def test_malformed_rule_handling(tmp_path: Path):
    """Test that malformed YAML files in rules directory are handled gracefully."""
    bad_rule_file = tmp_path / "bad_rule.yml"
    bad_rule_file.write_text("invalid_yaml: [unclosed_bracket", encoding="utf-8")

    incomplete_rule_file = tmp_path / "incomplete.yml"
    incomplete_rule_file.write_text("title: No ID or Detection\nseverity: low", encoding="utf-8")

    engine = SigmaEngine(rules_dir=tmp_path)
    # Should safely skip malformed rules and not crash
    assert len(engine.rules) == 0


def test_structured_match_metadata(sigma_engine: SigmaEngine):
    """Test that returned match metadata object contains all expected fields."""
    event = NormalizedEvent(
        event_id="evt-106",
        timestamp="2026-08-12T10:05:00Z",
        source="sysmon",
        host="PC-2",
        user="test_user",
        event_type="process_creation",
        severity_hint="high",
        raw={},
        normalized={
            "process_name": "C:\\Windows\\System32\\powershell.exe",
            "command_line": "powershell.exe -encodedcommand ZQBjAGgAbwA=",
        },
    )

    matches = sigma_engine.evaluate(event)
    assert len(matches) == 1
    m = matches[0]
    assert hasattr(m, "rule_id")
    assert hasattr(m, "title")
    assert hasattr(m, "severity")
    assert hasattr(m, "mitre_attack")
    assert isinstance(m.mitre_attack, list)
