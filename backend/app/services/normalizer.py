from typing import Dict, Any
from ..models import NormalizedThreatReport
from ..config import HIGH_RISK_COUNTRIES


class DataNormalizer:
    @staticmethod
    def normalize(raw_data: Dict[str, Any], ip: str) -> NormalizedThreatReport:
        vt = raw_data.get("virustotal", {}) or {}
        otx = raw_data.get("otx", {}) or {}
        geo = raw_data.get("geolocation", {}) or {}

        malicious_sources = int(vt.get("malicious", 0) or 0)
        suspicious_sources = int(vt.get("suspicious", 0) or 0)
        
        # Map OTX data to similar metrics
        threat_confidence = float(otx.get("threat_confidence", 0) or 0)
        pulse_count = int(otx.get("pulse_count", 0) or 0)
        otx_reputation = int(otx.get("reputation", 2) or 2)  # 0=malicious, 1=suspicious, 2=unknown, 3=good
        otx_threat_types = otx.get("threat_types", []) or []

        country = geo.get("country", "Unknown")
        country_code = geo.get("countryCode", "Unknown")
        asn_name = geo.get("org", "Unknown")

        categories = DataNormalizer._categorize(
            malicious_sources,
            suspicious_sources,
            threat_confidence,
            pulse_count,
            country_code,
            otx_threat_types,
            otx_reputation,
        )

        reputation_score = DataNormalizer._reputation(malicious_sources, threat_confidence, suspicious_sources, pulse_count)

        return NormalizedThreatReport(
            ip_address=ip,
            reputation_score=reputation_score,
            threat_categories=categories,
            malicious_sources=malicious_sources,
            suspicious_sources=suspicious_sources,
            abuse_confidence=threat_confidence,  # Map OTX threat_confidence to abuse_confidence field
            total_reports=pulse_count,  # Map OTX pulse_count to total_reports field
            country=country,
            country_code=country_code,
            asn_name=asn_name,
        )

    @staticmethod
    def _categorize(malicious: int, suspicious: int, threat_conf: float, pulse_count: int, country_code: str, otx_threat_types: list, otx_reputation: int):
        categories = []
        
        # VirusTotal-based categories
        if malicious >= 1:
            categories.append("malware")
        if suspicious >= 3:
            categories.append("scanner")
        
        # OTX-based categories
        if threat_conf >= 85:
            categories.append("brute_force")
        if pulse_count >= 10:
            categories.append("spam")
        if otx_reputation == 0:  # Malicious reputation
            categories.append("malware")
        if otx_reputation == 1:  # Suspicious reputation
            categories.append("scanner")
        
        # Map OTX threat types to categories
        threat_type_mapping = {
            "malware": "malware",
            "botnet": "botnet",
            "c2": "c2",
            "phishing": "phishing",
            "spam": "spam",
            "brute-force": "brute_force",
            "web-attack": "web_attack",
            "exploit": "exploit",
            "scanner": "scanner",
        }
        for otx_type in otx_threat_types:
            mapped = threat_type_mapping.get(otx_type)
            if mapped and mapped not in categories:
                categories.append(mapped)
        
        # Geography-based
        if country_code in HIGH_RISK_COUNTRIES:
            if "c2" not in categories:
                categories.append("c2")
        
        return list(dict.fromkeys(categories))

    @staticmethod
    def _reputation(malicious: int, threat_conf: float, suspicious: int, pulse_count: int) -> float:
        # 0 good → 100 bad
        # Combine VirusTotal and OTX indicators
        score = min(100, malicious * 12 + suspicious * 4 + int(threat_conf * 0.6) + pulse_count * 2)
        return float(score)


