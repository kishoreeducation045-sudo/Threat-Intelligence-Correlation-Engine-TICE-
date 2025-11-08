import asyncio
from typing import Dict, Any
import aiohttp
from .utils import with_retries
from ..config import (
    ABUSEIPDB_API_KEY,
    ABUSEIPDB_BASE_URL,
    IPAPI_BASE_URL,
    REQUEST_TIMEOUT,
)


class ThreatIntelCollector:
    """
    Collects threat intelligence data from AbuseIPDB and ip-api.com.
    """

    def __init__(self, abuseipdb_key: str = None):
        self.abuseipdb_key = abuseipdb_key or ABUSEIPDB_API_KEY

    async def fetch_all(self, ip: str) -> Dict[str, Any]:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)) as session:
            tasks = [
                self.fetch_abuseipdb(session, ip),
                self.fetch_geolocation(session, ip),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        def ok(idx: int) -> Dict[str, Any]:
            val = results[idx]
            return val if not isinstance(val, Exception) else {"error": str(val)}

        return {
            "abuseipdb": ok(0),
            "geolocation": ok(1),
        }

    @with_retries()
    async def fetch_abuseipdb(self, session: aiohttp.ClientSession, ip: str) -> Dict[str, Any]:
        """
        Query AbuseIPDB for threat intelligence data.
        Returns abuse confidence score, total reports, and IP details.
        """
        if not self.abuseipdb_key:
            return {"error": "ABUSEIPDB_API_KEY missing"}
        
        url = f"{ABUSEIPDB_BASE_URL}/check"
        headers = {
            "Accept": "application/json",
            "Key": self.abuseipdb_key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        async with session.get(url, headers=headers, params=params) as resp:
            if resp.status >= 400:
                error_data = await resp.json(content_type=None) if resp.content_type == "application/json" else {"error": f"HTTP {resp.status}"}
                return {"error": error_data}
            
            data = await resp.json(content_type=None)
            ip_data = data.get("data", {})
            
            # Extract key metrics from AbuseIPDB response
            abuse_confidence_score = int(ip_data.get("abuseConfidenceScore", 0) or 0)
            total_reports = int(ip_data.get("totalReports", 0) or 0)
            num_distinct_users = int(ip_data.get("numDistinctUsers", 0) or 0)
            is_whitelisted = bool(ip_data.get("isWhitelisted", False))
            is_public = bool(ip_data.get("isPublic", True))
            usage_type = ip_data.get("usageType", "Unknown")
            is_tor = bool(ip_data.get("isTor", False))
            country_code = ip_data.get("countryCode", "Unknown")
            isp = ip_data.get("isp", "Unknown")
            domain = ip_data.get("domain", "")
            hostnames = ip_data.get("hostnames", [])
            last_reported_at = ip_data.get("lastReportedAt", "")
            
            # Calculate threat categories based on AbuseIPDB data
            threat_types = set()
            if abuse_confidence_score >= 75:
                threat_types.add("malware")
            if abuse_confidence_score >= 50:
                threat_types.add("suspicious")
            if is_tor:
                threat_types.add("tor")
            if total_reports >= 10:
                threat_types.add("spam")
            if total_reports >= 5:
                threat_types.add("scanner")
            
            # Determine reputation based on abuse confidence score
            # AbuseIPDB: 0-25 = good, 26-50 = suspicious, 51-75 = high risk, 76-100 = malicious
            if abuse_confidence_score >= 76:
                reputation = 0  # Malicious
            elif abuse_confidence_score >= 51:
                reputation = 1  # Suspicious/High risk
            elif abuse_confidence_score >= 26:
                reputation = 1  # Suspicious
            else:
                reputation = 3 if abuse_confidence_score == 0 and total_reports == 0 else 2  # Good or Unknown
            
            # Use abuse confidence score directly as threat confidence
            threat_confidence = float(abuse_confidence_score)
            
            return {
                "raw": data,
                "abuse_confidence_score": abuse_confidence_score,
                "total_reports": total_reports,
                "num_distinct_users": num_distinct_users,
                "is_whitelisted": is_whitelisted,
                "is_public": is_public,
                "usage_type": usage_type,
                "is_tor": is_tor,
                "country_code": country_code,
                "isp": isp,
                "domain": domain,
                "hostnames": hostnames,
                "last_reported_at": last_reported_at,
                "threat_confidence": threat_confidence,
                "threat_types": list(threat_types),
                "reputation": reputation,
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


