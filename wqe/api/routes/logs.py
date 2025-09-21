from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from ..database import redis_client
from storage.short_term.redis_client import redis_client as anomaly_redis
import json

router = APIRouter()


@router.post("/api/v1/logs")
async def create_log(log: Dict[Any, Any]):
    try:
        # Save log as JSON string in Redis list
        redis_client.lpush("logs", json.dumps(log))
        return {"status": "success", "log_id": log.get('event_id')}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/logs/stats")
async def get_stats():
    try:
        logs = redis_client.lrange("logs", 0, -1)
        log_dicts: List[Dict[str, Any]] = []
        for log_str in logs:
            try:
                log_dict = json.loads(log_str)
                log_dicts.append(log_dict)
            except Exception:
                continue

        total_logs = len(log_dicts)
        by_severity: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        for log in log_dicts:
            severity = log.get("severity", "unknown")
            log_type = log.get("log_type", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[log_type] = by_type.get(log_type, 0) + 1

        return {
            "total": total_logs,
            "by_severity": by_severity,
            "by_type": by_type,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/logs/search")
async def search_logs(time_range: str = "24h", severity: Optional[str] = None, type: Optional[str] = None):
    try:
        logs = redis_client.lrange("logs", 0, -1)
        log_dicts: List[Dict[str, Any]] = []
        for log_str in logs:
            try:
                log_dict = json.loads(log_str)
                log_dicts.append(log_dict)
            except Exception:
                continue

        filtered_logs: List[Dict[str, Any]] = []
        # compute threshold using UTC
        hours = int(time_range.replace("h", "")) if time_range.endswith("h") else int(time_range)
        time_threshold = datetime.utcnow() - timedelta(hours=hours)

        for log in log_dicts:
            log_time_str = log.get("timestamp")
            if log_time_str:
                try:
                    log_time = datetime.fromisoformat(log_time_str.replace('Z', '+00:00'))
                except Exception:
                    continue
                if log_time < time_threshold:
                    continue

            if severity and log.get("severity") != severity:
                continue
            if type and log.get("log_type") != type:
                continue

            filtered_logs.append(log)

        return filtered_logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/anomalies/stats")
def get_anomaly_stats():
    try:
        stats = anomaly_redis.get_anomaly_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/anomalies/search")
def search_anomalies(time_range: str = "24h", severity: Optional[str] = None, rule_name: Optional[str] = None):
    try:
        anomalies = anomaly_redis.query_anomalies(time_range=time_range, severity=severity, rule_name=rule_name)
        return anomalies
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
