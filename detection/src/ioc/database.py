"""
Local Threat Intelligence Database — Module 2: Detection & Risk Engine
Manages loading and querying static/local IOC threat indicator datasets.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union


class IOCDatabase:
    """
    Manages local/mock threat intelligence datasets for offline lookup.
    """

    def __init__(self, data_file: Optional[Union[str, Path]] = None) -> None:
        if data_file is None:
            current_dir = Path(__file__).parent
            data_file = current_dir / "known_bad.json"
        
        self.data_file = Path(data_file)
        self.ips: Dict[str, Dict[str, Any]] = {}
        self.domains: Dict[str, Dict[str, Any]] = {}
        self.urls: Dict[str, Dict[str, Any]] = {}
        self.file_hashes: Dict[str, Dict[str, Any]] = {}
        self.load_database()

    def load_database(self) -> None:
        """
        Loads indicators from JSON file into case-normalized lookup dicts.
        """
        if not self.data_file.exists():
            return

        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if isinstance(data, dict):
                self.ips = {
                    ip.strip().lower(): meta
                    for ip, meta in data.get("ips", {}).items()
                    if isinstance(meta, dict)
                }
                self.domains = {
                    domain.strip().lower(): meta
                    for domain, meta in data.get("domains", {}).items()
                    if isinstance(meta, dict)
                }
                self.urls = {
                    url.strip().lower(): meta
                    for url, meta in data.get("urls", {}).items()
                    if isinstance(meta, dict)
                }
                self.file_hashes = {
                    h.strip().lower(): meta
                    for h, meta in data.get("file_hashes", {}).items()
                    if isinstance(meta, dict)
                }
        except Exception:
            # Handle corrupted or unreadable JSON files safely
            pass

    def lookup_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Lookup an IP address in local dataset."""
        if not ip or not isinstance(ip, str):
            return None
        return self.ips.get(ip.strip().lower())

    def lookup_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Lookup a domain name in local dataset."""
        if not domain or not isinstance(domain, str):
            return None
        return self.domains.get(domain.strip().lower())

    def lookup_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Lookup a URL string in local dataset."""
        if not url or not isinstance(url, str):
            return None
        return self.urls.get(url.strip().lower())

    def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Lookup a file hash (MD5, SHA1, SHA256) in local dataset."""
        if not file_hash or not isinstance(file_hash, str):
            return None
        return self.file_hashes.get(file_hash.strip().lower())
