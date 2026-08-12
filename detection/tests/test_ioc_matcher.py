"""
Unit tests for Module 2 IOC Matching Subsystem (Phase 2B)
Verifies indicator matching for IP, domain, URL, file_hash, evidence traceability,
multiple hits, clean events, and safety on missing fields.
"""

import pytest
from detection.src.ioc.client import LocalMockThreatIntelClient
from detection.src.ioc.database import IOCDatabase
from detection.src.ioc.matcher import IOCHitMatch, IOCMatcher
from detection.src.models import NormalizedEvent


@pytest.fixture
def ioc_matcher() -> IOCMatcher:
    """Fixture initializing IOCMatcher with default LocalMockThreatIntelClient."""
    return IOCMatcher()


def test_malicious_source_ip(ioc_matcher: IOCMatcher):
    """Test matching a malicious source IP address."""
    event = NormalizedEvent(
        event_id="evt-src-ip-1",
        timestamp="2026-08-12T12:00:00Z",
        source="firewall",
        host="FW-01",
        user=None,
        event_type="network_connection",
        severity_hint="high",
        raw={},
        normalized={
            "src_ip": "185.220.101.5",
            "dst_ip": "10.0.0.10",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.ioc_type == "ip"
    assert hit.matched_value == "185.220.101.5"
    assert hit.source_field == "src_ip"
    assert hit.threat_label == "Known CobaltStrike C2 Server"
    assert hit.severity == "high"
    assert hit.evidence_event_id == "evt-src-ip-1"


def test_malicious_destination_ip(ioc_matcher: IOCMatcher):
    """Test matching a malicious destination IP address."""
    event = NormalizedEvent(
        event_id="evt-dst-ip-1",
        timestamp="2026-08-12T12:01:00Z",
        source="firewall",
        host="FW-01",
        user="john",
        event_type="network_connection",
        severity_hint="high",
        raw={},
        normalized={
            "src_ip": "10.0.0.10",
            "dst_ip": "185.220.101.5",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.ioc_type == "ip"
    assert hit.matched_value == "185.220.101.5"
    assert hit.source_field == "dst_ip"
    assert hit.evidence_event_id == "evt-dst-ip-1"


def test_malicious_domain(ioc_matcher: IOCMatcher):
    """Test matching a malicious domain name."""
    event = NormalizedEvent(
        event_id="evt-domain-1",
        timestamp="2026-08-12T12:02:00Z",
        source="dns",
        host="WORKSTATION-5",
        user="alice",
        event_type="network_connection",
        severity_hint="high",
        raw={},
        normalized={
            "domain": "malicious-c2.com",
            "src_ip": "10.0.0.15",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.ioc_type == "domain"
    assert hit.matched_value == "malicious-c2.com"
    assert hit.source_field == "domain"
    assert hit.threat_label == "Known Malware C2 Domain"
    assert hit.evidence_event_id == "evt-domain-1"


def test_malicious_url(ioc_matcher: IOCMatcher):
    """Test matching a malicious URL string."""
    event = NormalizedEvent(
        event_id="evt-url-1",
        timestamp="2026-08-12T12:03:00Z",
        source="web_proxy",
        host="WORKSTATION-5",
        user="bob",
        event_type="network_connection",
        severity_hint="critical",
        raw={},
        normalized={
            "url": "http://malicious-c2.com/payload.exe",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.ioc_type == "url"
    assert hit.matched_value == "http://malicious-c2.com/payload.exe"
    assert hit.source_field == "url"
    assert hit.severity == "critical"
    assert hit.evidence_event_id == "evt-url-1"


def test_malicious_hash(ioc_matcher: IOCMatcher):
    """Test matching a malicious file hash (MD5)."""
    event = NormalizedEvent(
        event_id="evt-hash-1",
        timestamp="2026-08-12T12:04:00Z",
        source="sysmon",
        host="SERVER-9",
        user="admin",
        event_type="file_event",
        severity_hint="critical",
        raw={},
        normalized={
            "file_name": "payload.exe",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.ioc_type == "file_hash"
    assert hit.matched_value == "44d88612fea8a8f36de82e1278abb02f"
    assert hit.source_field == "file_hash"
    assert hit.threat_label == "WannaCry Ransomware MD5"
    assert hit.evidence_event_id == "evt-hash-1"


def test_clean_event(ioc_matcher: IOCMatcher):
    """Test that benign events produce no IOC matches."""
    event = NormalizedEvent(
        event_id="evt-clean-1",
        timestamp="2026-08-12T12:05:00Z",
        source="firewall",
        host="PC-01",
        user="user1",
        event_type="network_connection",
        severity_hint="low",
        raw={},
        normalized={
            "src_ip": "10.0.0.50",
            "dst_ip": "8.8.8.8",
            "domain": "google.com",
            "url": "https://google.com",
            "file_hash": "00000000000000000000000000000000",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 0


def test_missing_fields(ioc_matcher: IOCMatcher):
    """Test that missing or None fields cause no crash and produce no false hits."""
    event = NormalizedEvent(
        event_id="evt-missing-1",
        timestamp="2026-08-12T12:06:00Z",
        source="unknown",
        host=None,
        user=None,
        event_type="process_creation",
        severity_hint="unknown",
        raw={},
        normalized={},
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 0


def test_multiple_ioc_hits(ioc_matcher: IOCMatcher):
    """Test an event containing multiple malicious indicators (e.g. malicious IP + hash)."""
    event = NormalizedEvent(
        event_id="evt-multi-1",
        timestamp="2026-08-12T12:07:00Z",
        source="sysmon",
        host="SERVER-9",
        user="admin",
        event_type="file_event",
        severity_hint="critical",
        raw={},
        normalized={
            "dst_ip": "185.220.101.5",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 2
    matched_fields = {h.source_field for h in hits}
    assert "dst_ip" in matched_fields
    assert "file_hash" in matched_fields
    for h in hits:
        assert h.evidence_event_id == "evt-multi-1"


def test_evidence_traceability(ioc_matcher: IOCMatcher):
    """Test that all returned IOC matches strictly set evidence_event_id equal to source event_id."""
    event_id = "evt-traceability-999"
    event = NormalizedEvent(
        event_id=event_id,
        timestamp="2026-08-12T12:08:00Z",
        source="firewall",
        host="FW-1",
        user="system",
        event_type="network_connection",
        severity_hint="high",
        raw={},
        normalized={
            "src_ip": "185.220.101.5",
            "domain": "malicious-c2.com",
        },
    )

    hits = ioc_matcher.match_event(event)
    assert len(hits) == 2
    for hit in hits:
        assert hit.evidence_event_id == event_id
