from pydantic import BaseModel
from typing import Optional, List
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendedAction(str, Enum):
    CLOSE = "CLOSE"
    MONITOR = "MONITOR"
    ESCALATE = "ESCALATE"
    BLOCK = "BLOCK"


class Alert(BaseModel):
    alert_id: str
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    file_hash: Optional[str] = None
    hash_type: Optional[str] = None  # md5, sha1, sha256
    timestamp: str
    raw_log: Optional[str] = None
    additional_context: Optional[dict] = None
    model: Optional[str] = None


class IOC(BaseModel):
    type: str  # ip, domain, hash
    value: str
    malicious: bool
    confidence: float  # 0.0 - 1.0
    source: str
    details: Optional[str] = None


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    confidence: float


class IncidentReport(BaseModel):
    alert_id: str
    severity: Severity
    recommended_action: RecommendedAction
    summary: str
    iocs: List[IOC]
    mitre_techniques: List[MitreTechnique]
    analyst_notes: str
    escalation_reason: Optional[str] = None
    false_positive_indicators: List[str] = []
    investigation_steps: List[str] = []


class AgentEvent(BaseModel):
    type: str  # "thinking" | "tool_call" | "tool_result" | "report" | "error"
    content: str
    tool_name: Optional[str] = None
    tool_input: Optional[dict] = None
