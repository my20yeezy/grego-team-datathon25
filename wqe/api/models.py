from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum

class LogType(str, Enum):
    COWRIE_SSH = "cowrie_ssh"
    PALO_ALTO = "palo_alto_firewall"
    FORTINET = "fortinet_firewall"
    GENERIC_SYSLOG = "generic_syslog"
    DIONAEA_MALWARE = "dionaea_malware"
    T_POT = "t_pot"

class LogEntry(BaseModel):
    source: str = Field(..., description="Откуда пришёл лог — IP или имя хоста")
    log_type: LogType = Field(..., description="Тип лога, чтобы понимать, как его разбирать")
    raw_data: Dict[str, Any] = Field(..., description="Сырые данные — пригодятся для расследования")
    timestamp: Optional[datetime] = Field(None, description="Когда произошло событие (если известно)")

class QueryRequest(BaseModel):
    query: str = Field("", description="Что ищем — можно задать ключевые слова")
    time_range: str = Field("1h", description="За какой период нужны логи: 1h, 6h, 24h, 3d, 7d")
    limit: int = Field(1000, description="Сколько результатов вернуть (от 1 до 10000)", ge=1, le=10000)

class AnomalyDetectionResult(BaseModel):
    is_anomaly: bool
    confidence: float
    rule_name: Optional[str] = None
    description: str
    severity: str  # low, medium, high, critical

class HealthCheckResponse(BaseModel):
    status: str
    redis_connected: bool
    elasticsearch_connected: bool
    total_logs_processed: int
    uptime_seconds: float

class BulkLogRequest(BaseModel):
    logs: List[LogEntry] = Field(..., description="Список логов для массовой загрузки")