from typing import List, Tuple
from ..models import NormalizedThreatReport
from ..config import RISK_LEVELS


class ThreatScoringEngine:
    """
    Rule-based threat scoring with additive points and capped at 100.
    """

    def __init__(self):
        self.rules = [
            ("VT High Malicious", lambda r: r.malicious_sources >= 5, 40),
            ("VT Moderate Malicious", lambda r: 2 <= r.malicious_sources < 5, 25),
            ("VT Suspicious Vendors", lambda r: r.suspicious_sources >= 3, 15),
            ("OTX High Threat Confidence", lambda r: r.abuse_confidence >= 85, 30),
            ("OTX Moderate Threat Confidence", lambda r: 50 <= r.abuse_confidence < 85, 18),
            ("OTX Multiple Pulses", lambda r: r.total_reports >= 10, 15),
            ("Category Malware", lambda r: "malware" in r.threat_categories, 35),
            ("Category Botnet/C2", lambda r: "botnet" in r.threat_categories or "c2" in r.threat_categories, 30),
            ("High-Risk Geography", lambda r: r.country_code in {"KP", "IR", "SY", "CU"}, 15),
        ]

    def score(self, report: NormalizedThreatReport) -> Tuple[int, List[str]]:
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


