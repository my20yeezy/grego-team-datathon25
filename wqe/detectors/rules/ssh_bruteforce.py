from datetime import datetime, timedelta
from typing import Dict, Any
import asyncio
from storage.short_term.redis_client import redis_client

class SSHBruteforceDetector:
    def __init__(self):
        self.bruteforce_threshold = 10  # Попыток в минуту
        self.unique_user_threshold = 5  # Уникальных пользователей с одного IP
    
    async def check_bruteforce(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Обнаружение SSH брутфорс атак"""
        if log_data.get("event_type") != "cowrie.login.failure":
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "description": "Not a failed login attempt",
                "severity": "low"
            }
        
        src_ip = log_data.get("src_ip")
        username = log_data.get("username")
        
        if not src_ip:
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "description": "No source IP",
                "severity": "low"
            }
        
        # Получаем статистику за последние 5 минут
        stats = await self._get_bruteforce_stats(src_ip)
        
        # Проверяем пороги
        if stats["attempts_last_5min"] >= self.bruteforce_threshold:
            return {
                "is_anomaly": True,
                "confidence": 0.95,
                "rule_name": "ssh_bruteforce",
                "description": f"SSH bruteforce detected from {src_ip}: {stats['attempts_last_5min']} attempts in 5 minutes",
                "severity": "high"
            }
        
        if stats["unique_users"] >= self.unique_user_threshold:
            return {
                "is_anomaly": True,
                "confidence": 0.85,
                "rule_name": "ssh_user_enumeration",
                "description": f"User enumeration detected from {src_ip}: {stats['unique_users']} unique users tried",
                "severity": "medium"
            }
        
        return {
            "is_anomaly": False,
            "confidence": 0.0,
            "description": "No bruteforce detected",
            "severity": "low"
        }
    
    async def _get_bruteforce_stats(self, src_ip: str) -> Dict[str, Any]:
        """Получение статистики по bruteforce атакам"""
        # Получаем логи за последние 5 минут для этого IP
        logs = await redis_client.query_logs(time_range="1h", limit=1000)
        
        five_min_ago = datetime.utcnow() - timedelta(minutes=5)
        recent_logs = [
            log for log in logs 
            if log.get("src_ip") == src_ip 
            and log.get("event_type") == "cowrie.login.failure"
            and datetime.fromisoformat(log["timestamp"]) >= five_min_ago
        ]
        
        # Считаем уникальных пользователей
        unique_users = len(set(log.get("username") for log in recent_logs if log.get("username")))
        
        return {
            "attempts_last_5min": len(recent_logs),
            "unique_users": unique_users,
            "first_attempt": min([log["timestamp"] for log in recent_logs]) if recent_logs else None
        }