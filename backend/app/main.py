from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.config import VIRUSTOTAL_API_KEY, OTX_API_KEY, OPENAI_API_KEY
from app.services.collector import ThreatIntelCollector
from app.services.normalizer import DataNormalizer
from app.services.scorer import ThreatScoringEngine
from app.services.narrative import NarrativeGenerator
from .models import AnalysisRequest, AnalysisResponse

app = FastAPI(title="Cerberus - Threat Intelligence Correlation Engine")
@app.get("/")
def read_root():
    return {"message": "Welcome to the Cerberus Threat Intelligence Correlation Engine API"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services with API keys from .env file (loaded via config.py)
collector = ThreatIntelCollector(
    vt_key=VIRUSTOTAL_API_KEY,
    otx_key=OTX_API_KEY,
)
normalizer = DataNormalizer()
scorer = ThreatScoringEngine()
narrator = NarrativeGenerator(openai_key=OPENAI_API_KEY)


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "Cerberus TICE", "version": "1.0.0"}


def _validate_ipv4(ip: str) -> bool:
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit():
                return False
            n = int(p)
            if n < 0 or n > 255:
                return False
        return True
    except Exception:
        return False


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_ip(request: AnalysisRequest):
    ip = request.ip_address.strip()
    if not _validate_ipv4(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    raw_data = await collector.fetch_all(ip)
    report = normalizer.normalize(raw_data, ip)
    score, triggered = scorer.score(report)
    risk = ThreatScoringEngine.risk_level(score)
    narrative = await narrator.generate(report, score, risk)

    return AnalysisResponse(
        ip_address=ip,
        threat_score=score,
        risk_level=risk,
        threat_narrative=narrative,
        threat_categories=report.threat_categories,
        country=report.country,
        asn=report.asn_name,
        triggered_rules=triggered,
        malicious_sources=report.malicious_sources,
        abuse_confidence=report.abuse_confidence,
        raw_data=raw_data,
    )


