from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    ip_address: str = Field(..., description="IPv4 address to analyze", example="1.2.3.4")


class NormalizedThreatReport(BaseModel):
    ip_address: str
    reputation_score: float = Field(default=0, ge=0, le=100)
    threat_categories: List[str] = Field(default_factory=list)
    malicious_sources: int = Field(default=0, ge=0)
    suspicious_sources: int = Field(default=0, ge=0)
    abuse_confidence: float = Field(default=0, ge=0, le=100)
    country: str = Field(default="Unknown")
    country_code: str = Field(default="Unknown")
    asn_name: str = Field(default="Unknown")
    open_ports: List[int] = Field(default_factory=list)
    total_reports: int = Field(default=0, ge=0)
    timestamp: Optional[str] = None


class AnalysisResponse(BaseModel):
    ip_address: str
    threat_score: int = Field(..., ge=0, le=100)
    risk_level: str
    threat_narrative: str
    threat_categories: List[str] = Field(default_factory=list)
    country: str
    asn: str
    triggered_rules: List[str] = Field(default_factory=list)
    malicious_sources: int
    abuse_confidence: float
    raw_data: Dict[str, Any] = Field(default_factory=dict)


