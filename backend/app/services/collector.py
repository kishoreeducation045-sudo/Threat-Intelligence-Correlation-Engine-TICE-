import asyncio
from typing import Dict, Any
import aiohttp
from .utils import with_retries
from ..config import (
    VIRUSTOTAL_API_KEY,
    OTX_API_KEY,
    VIRUSTOTAL_BASE_URL,
    OTX_BASE_URL,
    IPAPI_BASE_URL,
    REQUEST_TIMEOUT,
)


class ThreatIntelCollector:
    """
    Collects threat intelligence data from VirusTotal, AlienVault OTX, and ip-api.com.
    """

    def __init__(self, vt_key: str = None, otx_key: str = None):
        self.vt_key = vt_key or VIRUSTOTAL_API_KEY
        self.otx_key = otx_key or OTX_API_KEY

    async def fetch_all(self, ip: str) -> Dict[str, Any]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as session:
            tasks = [
                self.fetch_virustotal(session, ip),
                self.fetch_otx(session, ip),
                self.fetch_geolocation(session, ip),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        def ok(idx: int) -> Dict[str, Any]:
            val = results[idx]
            return val if not isinstance(val, Exception) else {"error": str(val)}

        return {
            "virustotal": ok(0),
            "otx": ok(1),
            "geolocation": ok(2),
        }

    @with_retries()
    async def fetch_virustotal(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        if not self.vt_key:
            return {"error": "VIRUSTOTAL_API_KEY missing"}
        url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_key}
        async with session.get(url, headers=headers) as resp:
            data = await resp.json(content_type=None)
            if resp.status >= 400:
                return {"error": data}
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "raw": data,
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
                "tags": attrs.get("tags", []),
            }

    @with_retries()
    async def fetch_otx(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """
        Query AlienVault OTX for threat intelligence data.
        Returns pulse count, reputation, and threat categories.
        """
        if not self.otx_key:
            return {"error": "OTX_API_KEY missing"}
        url = f"{OTX_BASE_URL}/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}
        async with session.get(url, headers=headers) as resp:
            if resp.status >= 400:
                error_data = await resp.json(content_type=None) if resp.content_type == "application/json" else {"error": f"HTTP {resp.status}"}
                return {"error": error_data}
            data = await resp.json(content_type=None)
            
            # Extract key metrics from OTX response
            pulse_count = len(data.get("pulses", []))
            reputation = data.get("reputation", 0)
            validation = data.get("validation", [])
            
            # Extract threat types from pulses
            threat_types = set()
            for pulse in data.get("pulses", []):
                for tag in pulse.get("tags", []):
                    threat_types.add(tag.lower())
            
            # Calculate threat confidence based on pulse count and reputation
            # OTX reputation: 0 = malicious, 1 = suspicious, 2 = unknown, 3 = good
            # Convert to confidence score (0-100, higher = more malicious)
            if reputation == 0:  # Malicious
                threat_confidence = min(100, 70 + (pulse_count * 3))
            elif reputation == 1:  # Suspicious
                threat_confidence = min(100, 50 + (pulse_count * 2))
            elif pulse_count > 0:  # Has pulses but unknown reputation
                threat_confidence = min(100, 30 + (pulse_count * 2))
            else:
                threat_confidence = 0
            
            return {
                "raw": data,
                "pulse_count": pulse_count,
                "reputation": reputation,
                "threat_confidence": threat_confidence,
                "threat_types": list(threat_types),
                "validation": validation,
            }

    @with_retries()
    async def fetch_geolocation(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        url = f"{IPAPI_BASE_URL}/json/{ip}"
        async with session.get(url) as resp:
            data = await resp.json(content_type=None)
            if resp.status >= 400:
                return {"error": data}
            return {
                "raw": data,
                "country": data.get("country", "Unknown"),
                "countryCode": data.get("countryCode", "Unknown"),
                "org": data.get("as", "Unknown") or data.get("org", "Unknown"),
                "query": data.get("query", ip),
            }


