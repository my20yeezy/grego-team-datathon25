import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
import numpy as np
from .ml_models.isolation_forest import IsolationForestModel
from .rules.ssh_bruteforce import SSHBruteforceDetector
from .rules.traffic_anomalies import TrafficAnomalyDetector
from storage.short_term.redis_client import redis_client

class AnomalyDetector:
    def __init__(self):
        self.ml_model = IsolationForestModel()
        self.ssh_detector = SSHBruteforceDetector()
        self.traffic_detector = TrafficAnomalyDetector()
        
        # Загрузка ML модели при инициализации
        asyncio.create_task(self.ml_model.load_model())
    
    async def check_anomalies(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Проверка лога на аномалии с помощью всех детекторов"""
        anomalies = []
        
        # Проверка правилами
        rule_anomalies = await self._check_rules(log_data)
        anomalies.extend(rule_anomalies)
        
        # Проверка ML моделью (если есть исторические данные)
        if await self._has_sufficient_data():
            ml_anomaly = await self.ml_model.detect_anomaly(log_data)
            if ml_anomaly["is_anomaly"]:
                anomalies.append(ml_anomaly)
        
        if anomalies:
            # Выбираем самую серьезную аномалию
            most_severe_anomaly = max(anomalies, key=lambda x: self._severity_to_score(x["severity"]))
            
            # Сохраняем аномалию в Redis
            await redis_client.store_anomaly({
                **most_severe_anomaly,
                **log_data,  # Добавляем исходные данные лога
                "event_id": log_data.get("event_id", str(uuid.uuid4()))
            })
            
            return most_severe_anomaly
        
        return {
            "is_anomaly": False,
            "confidence": 0.0,
            "description": "No anomalies detected",
            "severity": "low"
        }
    
    async def _check_rules(self, log_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Проверка лога по правилам"""
        anomalies = []
        
        # SSH брутфорс
        if log_data.get("log_type") == "cowrie_ssh":
            ssh_anomaly = await self.ssh_detector.check_bruteforce(log_data)
            if ssh_anomaly["is_anomaly"]:
                anomalies.append(ssh_anomaly)
        
        # Аномалии трафика
        if log_data.get("log_type") in ["palo_alto_firewall", "fortinet_firewall"]:
            traffic_anomaly = await self.traffic_detector.check_traffic(log_data)
            if traffic_anomaly["is_anomaly"]:
                anomalies.append(traffic_anomaly)
        
        return anomalies
    
    async def _has_sufficient_data(self) -> bool:
        """Проверка, достаточно ли данных для ML анализа"""
        # Минимум 1000 логов для обучения модели
        try:
            count = await redis_client.get_logs_count()
            return count > 1000
        except:
            return False
    
    def _severity_to_score(self, severity: str) -> int:
        """Конвертация severity в числовой score для сравнения"""
        severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return severity_map.get(severity, 0)
    
    async def train_models(self):
        """Переобучение ML моделей на исторических данных"""
        # Получаем исторические данные для обучения
        historical_data = await redis_client.query_logs(time_range="7d", limit=10000)
        
        if len(historical_data) > 1000:
            await self.ml_model.train(historical_data)
            return True
        return False

# Глобальный инстанс детектора
anomaly_detector = AnomalyDetector()