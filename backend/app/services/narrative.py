import os
import asyncio
from ..models import NormalizedThreatReport

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except Exception:  # noqa: BLE001
    OPENAI_AVAILABLE = False


class NarrativeGenerator:
    def __init__(self, openai_key: str | None = None):
        self.openai_key = openai_key or os.getenv("OPENAI_API_KEY")
        self.client = None
        if OPENAI_AVAILABLE and self.openai_key:
            try:
                self.client = OpenAI(api_key=self.openai_key)
            except Exception:  # noqa: BLE001
                self.client = None

    async def generate(self, report: NormalizedThreatReport, score: int, risk_level: str) -> str:
        if self.client:
            try:
                return await self._generate_with_openai(report, score, risk_level)
            except Exception:  # noqa: BLE001
                pass
        return self._generate_template(report, score, risk_level)

    async def _generate_with_openai(self, report: NormalizedThreatReport, score: int, risk_level: str) -> str:
        system = "You are a security analyst generating concise threat narratives."
        user = (
            f"Summarize the threat for IP {report.ip_address}. "
            f"Risk: {risk_level} ({score}/100). "
            f"Categories: {', '.join(report.threat_categories) or 'none'}. "
            f"Malicious vendors: {report.malicious_sources}. "
            f"Abuse confidence: {report.abuse_confidence}%. "
            f"Country: {report.country}. ASN: {report.asn_name}. "
            "Give a short paragraph and 2-3 recommended actions."
        )

        # OpenAI Python SDK is sync; run in a thread to avoid blocking
        def _call():
            resp = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                temperature=0.2,
                max_tokens=220,
            )
            return resp.choices[0].message.content.strip()

        return await asyncio.to_thread(_call)

    def _generate_template(self, report: NormalizedThreatReport, score: int, risk_level: str) -> str:
        actions = [
            "Block the IP at network perimeter and WAF",
            "Search SIEM logs for recent connections from this IP",
            "Add monitoring rule for repeated access attempts",
        ]
        return (
            f"IP {report.ip_address} presents a {risk_level} risk with a score of {score}/100. "
            f"Observed indicators include {report.malicious_sources} malicious vendor detections and an AbuseIPDB confidence of {report.abuse_confidence}%. "
            f"Classification: {', '.join(report.threat_categories) or 'no specific categories'}. "
            f"Geolocation is {report.country} (ASN: {report.asn_name}).\n\n"
            f"Recommended actions: 1) {actions[0]}; 2) {actions[1]}; 3) {actions[2]}."
        )


