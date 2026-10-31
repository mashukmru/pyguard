"""
Geo-location lookup service for PyGuard.

Provides IP-to-country mapping using the ipgeolocation.io API
with in-memory caching to minimize external requests.
"""

import os
import requests
from typing import Optional, Dict

class GeoLookup:
    """
    Handles IP to country lookups with caching.
    """

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or os.environ.get("IPGEO_API_KEY")
        self._cache: Dict[str, str] = {}
        self._api_url = "https://api.ipgeolocation.io/ipgeo"

    def set_api_key(self, api_key: str) -> None:
        """Set the API key dynamically."""
        self._api_key = api_key

    def get_country(self, ip: str) -> Optional[str]:
        """
        Get 2-letter country code for a given IP.
        Returns None if lookup fails or IP is invalid/private.
        """
        if not ip or ip in ("127.0.0.1", "localhost", "0.0.0.0"):
            return None

        # Check in-memory cache first
        if ip in self._cache:
            return self._cache[ip]

        if not self._api_key:
            return None

        try:
            params = {
                "apiKey": self._api_key,
                "ip": ip
            }
            response = requests.get(self._api_url, params=params, timeout=3)
            if response.status_code == 200:
                data = response.json()
                country_code = data.get("country_code2")
                if country_code:
                    self._cache[ip] = country_code
                    return country_code
        except Exception:
            # Silent failure for packet inspection loop
            pass

        return None

    def clear_cache(self) -> None:
        """Clear the IP-to-country cache."""
        self._cache.clear()
