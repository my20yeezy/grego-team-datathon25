from datetime import datetime, timedelta
from typing import Dict, Any
import asyncio
from storage.short_term.redis_client import redis_client

class TrafficAnomalyDetector:
    def __init__(self):
        self.traffic_spike_threshold = 3.0  # 3x увеличение трафика
        self.port_scan_threshold = 50       # 50 попыток на разные порты
    
    async def check_traffic(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Обнаружение аномалий сетевого трафика"""
        if log_data.get("action") != "deny":
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "description": "Not a denied traffic event",
                "severity": "low"
            }
        
        src_ip = log_data.get("src_ip")
        
        # Проверяем различные типы аномалий
        scan_anomaly = await self._check_port_scan(src_ip)
        if scan_anomaly["is_anomaly"]:
            return scan_anomaly
        
        flood_anomaly = await self._check_traffic_flood(src_ip)
        if flood_anomaly["is_anomaly"]:
            return flood_anomaly
        
        return {
            "is_anomaly": False,
            "confidence": 0.0,
            "description": "No traffic anomalies detected",
            "severity": "low"
        }
    
    async def _check_port_scan(self, src_ip: str) -> Dict[str, Any]:
        """Обнаружение сканирования портов"""
        # Получаем логи за последний час
        logs = await redis_client.query_logs(time_range="1h", limit=5000)
        
        # Фильтруем логи по IP и denied traffic
        ip_logs = [
            log for log in logs 
            if log.get("src_ip") == src_ip 
            and log.get("action") == "deny"
            and log.get("log_type") in ["palo_alto_firewall", "fortinet_firewall"]
        ]
        
        # Считаем уникальные порты назначения
        unique_ports = len(set(log.get("dst_port") for log in ip_logs if log.get("dst_port")))
        
        if unique_ports >= self.port_scan_threshold:
            return {
                "is_anomaly": True,
                "confidence": 0.9,
                "rule_name": "port_scan",
                "description": f"Port scan detected from {src_ip}: {unique_ports} unique ports targeted",
                "severity": "medium"
            }
        
        return {"is_anomaly": False}
    
    async def _check_traffic_flood(self, src_ip: str) -> Dict[str, Any]:
        """Обнаружение flood атаки"""
        # Здесь можно реализовать проверку частоты запросов
        # Пока заглушка
        return {"is_anomaly": False}