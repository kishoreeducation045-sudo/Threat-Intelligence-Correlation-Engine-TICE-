from typing import Dict, Any
from ..models import NormalizedThreatReport
from ..config import HIGH_RISK_COUNTRIES


class DataNormalizer:
    @staticmethod
    def normalize(raw_data: Dict[str, Any], ip: str) -> NormalizedThreatReport:
        abuseipdb = raw_data.get("abuseipdb", {}) or {}
        geo = raw_data.get("geolocation", {}) or {}
        
        # Extract AbuseIPDB data
        abuse_confidence_score = float(abuseipdb.get("abuse_confidence_score", 0) or 0)
        total_reports = int(abuseipdb.get("total_reports", 0) or 0)
        num_distinct_users = int(abuseipdb.get("num_distinct_users", 0) or 0)
        is_whitelisted = bool(abuseipdb.get("is_whitelisted", False))
        is_tor = bool(abuseipdb.get("is_tor", False))
        abuseipdb_reputation = int(abuseipdb.get("reputation", 2) or 2)  # 0=malicious, 1=suspicious, 2=unknown, 3=good
        abuseipdb_threat_types = abuseipdb.get("threat_types", []) or []
        
        # Use AbuseIPDB country code if available, otherwise fall back to geolocation
        abuseipdb_country_code = abuseipdb.get("country_code", "")
        abuseipdb_isp = abuseipdb.get("isp", "")

        # Calculate malicious and suspicious sources based on AbuseIPDB data
        # AbuseIPDB reputation: 0=malicious, 1=suspicious, 2=unknown, 3=good
        if abuseipdb_reputation == 0:  # Malicious
            malicious_sources = max(1, min(total_reports, 10)) if total_reports > 0 else 1
            suspicious_sources = max(0, total_reports - malicious_sources)
        elif abuseipdb_reputation == 1:  # Suspicious
            malicious_sources = 0
            suspicious_sources = max(1, min(total_reports, 10)) if total_reports > 0 else 1
        else:
            # For unknown/good reputation, use total reports as suspicious indicator
            malicious_sources = 0
            suspicious_sources = max(0, min(total_reports // 2, 5)) if total_reports > 5 else 0

        # Prefer AbuseIPDB country code, fall back to geolocation
        country = geo.get("country", "Unknown")
        country_code = abuseipdb_country_code if abuseipdb_country_code and abuseipdb_country_code != "Unknown" else geo.get("countryCode", "Unknown")
        # Prefer AbuseIPDB ISP, fall back to geolocation ASN
        asn_name = abuseipdb_isp if abuseipdb_isp and abuseipdb_isp != "Unknown" else geo.get("org", "Unknown")

        categories = DataNormalizer._categorize(
            abuse_confidence_score,
            total_reports,
            country_code,
            abuseipdb_threat_types,
            abuseipdb_reputation,
            is_tor,
            is_whitelisted,
        )

        reputation_score = DataNormalizer._reputation(abuse_confidence_score, total_reports, abuseipdb_reputation)

        return NormalizedThreatReport(
            ip_address=ip,
            reputation_score=reputation_score,
            threat_categories=categories,
            malicious_sources=malicious_sources,
            suspicious_sources=suspicious_sources,
            abuse_confidence=abuse_confidence_score,
            total_reports=total_reports,
            country=country,
            country_code=country_code,
            asn_name=asn_name,
        )

    @staticmethod
    def _categorize(abuse_conf: float, total_reports: int, country_code: str, threat_types: list, reputation: int, is_tor: bool = False, is_whitelisted: bool = False):
        categories = []
        
        # Skip categorization if IP is whitelisted
        if is_whitelisted:
            return categories
        
        # Reputation-based categories
        if reputation == 0:  # Malicious reputation
            categories.append("malware")
        if reputation == 1:  # Suspicious reputation
            categories.append("scanner")
        
        # Abuse confidence score-based categories
        if abuse_conf >= 85:
            categories.append("brute_force")
            if total_reports >= 15:
                categories.append("botnet")
        elif abuse_conf >= 70:
            categories.append("web_attack")
        
        # Total reports-based categories
        if total_reports >= 10:
            categories.append("spam")
        if total_reports >= 5 and abuse_conf >= 50:
            categories.append("scanner")
        
        # Tor indicator
        if is_tor:
            categories.append("c2")  # Tor IPs often used for C2
        
        # Map threat types from AbuseIPDB to categories
        threat_type_mapping = {
            "malware": "malware",
            "botnet": "botnet",
            "c2": "c2",
            "c2server": "c2",
            "phishing": "phishing",
            "spam": "spam",
            "brute-force": "brute_force",
            "bruteforce": "brute_force",
            "web-attack": "web_attack",
            "webattack": "web_attack",
            "exploit": "exploit",
            "scanner": "scanner",
            "scanning": "scanner",
            "tor": "c2",
            "suspicious": "scanner",
        }
        for threat_type in threat_types:
            mapped = threat_type_mapping.get(threat_type.lower())
            if mapped and mapped not in categories:
                categories.append(mapped)
        
        # Geography-based
        if country_code in HIGH_RISK_COUNTRIES:
            if "c2" not in categories:
                categories.append("c2")
        
        return list(dict.fromkeys(categories))

    @staticmethod
    def _reputation(abuse_conf: float, total_reports: int, reputation: int) -> float:
        # 0 good → 100 bad
        # Calculate reputation based on AbuseIPDB data
        score = 0
        
        # Base score from abuse confidence (already 0-100)
        score += abuse_conf
        
        # Adjust based on reputation if abuse confidence is low but reputation indicates risk
        if reputation == 0:  # Malicious
            score = max(score, 75)  # Ensure minimum score for malicious
        elif reputation == 1:  # Suspicious
            score = max(score, 50)  # Ensure minimum score for suspicious
        
        # Add points for total reports (indicates repeated abuse)
        if total_reports > 0:
            score += min(15, total_reports)  # Cap at +15 points
        
        return float(min(100, score))


