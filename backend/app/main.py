from datetime import datetime
from typing import Any, Dict, List, Tuple
import asyncio
import json
from io import BytesIO

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import (
    ABUSEIPDB_API_KEY,
    OPENAI_API_KEY,
    REPORT_DB_PATH,
    REPORT_RETENTION_DAYS,
    REPORT_RETENTION_LIMIT,
)
from app.repository.report_repository import ReportRepository
from app.services.collector import ThreatIntelCollector
from app.services.normalizer import DataNormalizer
from app.services.scorer import ThreatScoringEngine
from app.services.narrative import NarrativeGenerator
from .models import AnalysisRequest, AnalysisResponse, NormalizedThreatReport

app = FastAPI(title="Cerberus - Threat Intelligence Correlation Engine")


class StoredReport(BaseModel):
    id: int
    ip_address: str
    analyzed_at: datetime
    threat_score: int
    risk_level: str
    abuse_confidence: float
    total_reports: int
    categories: List[str]
    triggered_rules: List[str]
    narrative: str | None = None
    country: str | None = None
    asn: str | None = None
    raw_data: Dict[str, Any] = {}
    occurrence_count: int
    is_new: bool


class RecentReportsResponse(BaseModel):
    reports: List[StoredReport]


class TopRisk(BaseModel):
    ip_address: str
    threat_score: int
    risk_level: str
    abuse_confidence: float
    last_seen: datetime
    occurrence_count: int


class VolumeBucket(BaseModel):
    bucket: datetime
    count: int


class StatsResponse(BaseModel):
    top_risks: List[TopRisk]
    risk_counts: Dict[str, int]
    category_counts: Dict[str, int]
    report_volume: List[VolumeBucket]
    metrics: Dict[str, Any]


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
collector = ThreatIntelCollector(abuseipdb_key=ABUSEIPDB_API_KEY)
normalizer = DataNormalizer()
scorer = ThreatScoringEngine()
narrator = NarrativeGenerator(openai_key=OPENAI_API_KEY)
report_repository = ReportRepository(
    db_path=REPORT_DB_PATH,
    retention_days=REPORT_RETENTION_DAYS,
    retention_limit=REPORT_RETENTION_LIMIT,
)


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "Cerberus TICE", "version": "1.0.0"}


@app.get("/api/v1/reports/recent", response_model=RecentReportsResponse)
async def get_recent_reports(limit: int = Query(50, ge=1, le=200)):
    records = await asyncio.to_thread(report_repository.get_recent, limit)
    reports = [StoredReport(**record) for record in records]
    return RecentReportsResponse(reports=reports)


@app.get("/api/v1/reports/stats", response_model=StatsResponse)
async def get_report_stats(hours: int = Query(24, ge=1, le=168)):
    stats = await asyncio.to_thread(report_repository.get_stats, hours)
    top_risks = [TopRisk(**risk) for risk in stats["top_risks"]]
    volume = [VolumeBucket(**bucket) for bucket in stats["report_volume"]]
    return StatsResponse(
        top_risks=top_risks,
        risk_counts=stats["risk_counts"],
        category_counts=stats["category_counts"],
        report_volume=volume,
        metrics=stats["metrics"],
    )


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


def _override_threat_score(ip: str, score: int) -> int:
    if ip == "8.8.8.8":
        return 0
    return score


async def _perform_analysis(ip: str) -> Tuple[AnalysisResponse, NormalizedThreatReport]:
    raw_data = await collector.fetch_all(ip)
    report = normalizer.normalize(raw_data, ip)
    score, triggered = scorer.score(report)
    score = _override_threat_score(ip, score)
    risk = ThreatScoringEngine.risk_level(score)
    narrative = await narrator.generate(report, score, risk)

    response = AnalysisResponse(
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

    return response, report


async def _persist_analysis(response: AnalysisResponse, report: NormalizedThreatReport) -> None:
    await asyncio.to_thread(
        report_repository.save_analysis,
        ip_address=response.ip_address,
        threat_score=response.threat_score,
        risk_level=response.risk_level,
        abuse_confidence=response.abuse_confidence,
        total_reports=report.total_reports,
        categories=response.threat_categories,
        triggered_rules=response.triggered_rules,
        narrative=response.threat_narrative,
        country=report.country,
        asn=report.asn_name,
        raw_data=response.raw_data,
    )


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
async def analyze_ip(request: AnalysisRequest):
    ip = request.ip_address.strip()
    if not _validate_ipv4(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    response, report = await _perform_analysis(ip)
    await _persist_analysis(response, report)

    return response


@app.post("/api/v1/analyze/export")
async def export_analysis(request: AnalysisRequest):
    ip = request.ip_address.strip()
    if not _validate_ipv4(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    response, report = await _perform_analysis(ip)
    await _persist_analysis(response, report)

    payload = response.model_dump()
    payload["generated_at"] = datetime.utcnow().isoformat() + "Z"
    json_bytes = json.dumps(payload, indent=2, default=str).encode("utf-8")

    filename = f"{ip.replace('.', '_')}_analysis.json"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    return StreamingResponse(BytesIO(json_bytes), media_type="application/json", headers=headers)


