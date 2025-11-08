from typing import List, Tuple
from ..models import NormalizedThreatReport
from ..config import RISK_LEVELS


class ThreatScoringEngine:
    """
    Rule-based threat scoring with additive points and capped at 100.
    """

    def __init__(self):
        self.rules = [
            ("AbuseIPDB High Abuse Confidence", lambda r: r.abuse_confidence >= 85, 35),
            ("AbuseIPDB Moderate Abuse Confidence", lambda r: 75 <= r.abuse_confidence < 85, 22),
            ("AbuseIPDB Elevated Abuse Confidence", lambda r: 60 <= r.abuse_confidence < 75, 12),
            ("AbuseIPDB High Report Count", lambda r: r.total_reports >= 15, 25),
            ("AbuseIPDB Moderate Report Count", lambda r: 10 <= r.total_reports < 15, 15),
            ("AbuseIPDB Multiple Reports", lambda r: 5 <= r.total_reports < 10, 8),
            ("High Malicious Sources", lambda r: r.malicious_sources >= 5, 30),
            ("Moderate Malicious Sources", lambda r: 2 <= r.malicious_sources < 5, 18),
            ("Suspicious Sources Detected", lambda r: r.suspicious_sources >= 3, 12),
            ("Category Malware", lambda r: "malware" in r.threat_categories, 35),
            ("Category Botnet/C2", lambda r: "botnet" in r.threat_categories or "c2" in r.threat_categories, 30),
            ("Category Phishing", lambda r: "phishing" in r.threat_categories, 25),
            ("High-Risk Geography", lambda r: r.country_code in {"KP", "IR", "SY", "CU"}, 15),
        ]

    def score(self, report: NormalizedThreatReport) -> Tuple[int, List[str]]:
        print(f"[DEBUG] Scoring IP:{report.ip_address} | Abuse Confidence:{report.abuse_confidence} | Malicious Sources:{report.malicious_sources} | Suspicious Sources:{report.suspicious_sources} | Total Reports:{report.total_reports} | Categories:{report.threat_categories} | Country:{report.country_code}")
        score = 0
        triggered: List[str] = []
        for name, cond, pts in self.rules:
            try:
                if cond(report):
                    score += pts
                    triggered.append(name)
            except Exception:  # noqa: BLE001
                continue
        score = max(0, min(100, score))
        return score, triggered

    @staticmethod
    def risk_level(score: int) -> str:
        for level, (lo, hi) in RISK_LEVELS.items():
            if lo <= score <= hi:
                return level
        return "LOW"


