"""
Threat Intelligence Client Abstraction — Module 2: Detection & Risk Engine
Provides abstract interface for threat intel lookups and local/mock implementation.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from detection.src.ioc.database import IOCDatabase


class BaseThreatIntelClient(ABC):
    """
    Abstract Base Class for threat intelligence providers.
    Allows easy pluggability for future external APIs (e.g. VirusTotal, AbuseIPDB)
    without modifying the core IOC matching engine.
    """

    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query IP address against threat intelligence provider."""
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query domain name against threat intelligence provider."""
        pass

    @abstractmethod
    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Query URL string against threat intelligence provider."""
        pass

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Query file hash against threat intelligence provider."""
        pass


class LocalMockThreatIntelClient(BaseThreatIntelClient):
    """
    Local / Mock Threat Intelligence Client utilizing static datasets (known_bad.json).
    Requires zero external network calls or API keys.
    """

    def __init__(self, db: Optional[IOCDatabase] = None) -> None:
        self.db = db if db is not None else IOCDatabase()

    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        return self.db.lookup_ip(ip)

    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        return self.db.lookup_domain(domain)

    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        return self.db.lookup_url(url)

    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        return self.db.lookup_hash(file_hash)
