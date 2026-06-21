from pydantic import BaseModel


class SummaryResponse(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    security_score: int


class FindingResponse(BaseModel):
    category: str
    username: str
    finding: str
    risk_level: str
    risk_score: int
    mitre_id: str