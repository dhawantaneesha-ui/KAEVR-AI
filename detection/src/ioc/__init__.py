"""
IOC Matching Subsystem Package — Module 2: Detection & Risk Engine
"""

from detection.src.ioc.client import BaseThreatIntelClient, LocalMockThreatIntelClient
from detection.src.ioc.database import IOCDatabase
from detection.src.ioc.matcher import IOCHitMatch, IOCMatcher

__all__ = [
    "BaseThreatIntelClient",
    "LocalMockThreatIntelClient",
    "IOCDatabase",
    "IOCMatcher",
    "IOCHitMatch",
]
