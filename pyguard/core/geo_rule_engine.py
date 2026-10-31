"""
Geo-location rule engine for PyGuard.

Manages the list of blocked country codes and provides methods
for checking if a country is blocked.
"""

import json
import os
from threading import Lock
from typing import List, Set, Optional
from pathlib import Path

from pyguard.utils.helpers import get_geo_rules_path

class GeoRuleEngine:
    """
    Manages geo-blocking rules (blocked country codes).
    """

    def __init__(self, rules_path: Optional[Path] = None):
        self._path = rules_path or get_geo_rules_path()
        self._blocked_countries: Set[str] = set()
        self._api_key: str = ""
        self._lock = Lock()
        self.load_rules()

    def load_rules(self) -> None:
        """Load blocked countries and settings from geo_rules.json."""
        with self._lock:
            if not self._path.exists():
                self._blocked_countries = set()
                self._api_key = ""
                return

            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._blocked_countries = set(data.get("blocked_countries", []))
                    self._api_key = data.get("api_key", "")
            except (json.JSONDecodeError, OSError):
                self._blocked_countries = set()
                self._api_key = ""

    def save_rules(self) -> None:
        """Save blocked countries and settings to geo_rules.json."""
        with self._lock:
            try:
                data = {
                    "blocked_countries": sorted(list(self._blocked_countries)),
                    "api_key": self._api_key
                }
                with open(self._path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except OSError:
                pass

    def get_api_key(self) -> str:
        """Return the current API key."""
        with self._lock:
            return self._api_key

    def set_api_key(self, api_key: str) -> None:
        """Set and save the API key."""
        with self._lock:
            self._api_key = api_key
        self.save_rules()

    def is_country_blocked(self, country_code: Optional[str]) -> bool:
        """Check if a 2-letter country code is in the block list."""
        if not country_code:
            return False
        with self._lock:
            return country_code.upper() in self._blocked_countries

    def add_blocked_country(self, country_code: str) -> bool:
        """Add a country code to the block list."""
        if not country_code or len(country_code) != 2:
            return False
        code = country_code.upper()
        with self._lock:
            if code in self._blocked_countries:
                return False
            self._blocked_countries.add(code)
        self.save_rules()
        return True

    def remove_blocked_country(self, country_code: str) -> bool:
        """Remove a country code from the block list."""
        code = country_code.upper()
        with self._lock:
            if code not in self._blocked_countries:
                return False
            self._blocked_countries.remove(code)
        self.save_rules()
        return True

    def get_blocked_countries(self) -> List[str]:
        """Return the list of currently blocked country codes."""
        with self._lock:
            return sorted(list(self._blocked_countries))
