import redis
import json
from datetime import datetime, timedelta
import asyncio
from typing import Dict, List, Optional

class RedisClient:
    def __init__(self):
        self.client = redis.Redis(
            host="redis",
            port=6379,
            db=0,
            decode_responses=True
        )
        self.ttl_hours = 72  # Храним логи в краткосрочном кеше примерно 3 дня
        self.anomaly_ttl_hours = 168  # Аномалии держим неделю, чтобы не потерять важное
    
    async def store_log_short_term(self, log_data: Dict):
        """
        Кладём лог в Redis с ограниченным сроком жизни
        """
        key = f"log:{log_data['event_id']}"
        # Сохраняем в sorted set по времени — удобно искать свежие события
        timestamp_score = datetime.fromisoformat(log_data['timestamp']).timestamp()
        pipeline = self.client.pipeline()
        pipeline.hset(key, mapping=log_data)
        pipeline.expire(key, self.ttl_hours * 3600)
        pipeline.zadd("logs:timestamps", {key: timestamp_score})
        pipeline.execute()
    
    async def query_logs(self, time_range: str = "1h", limit: int = 1000) -> List[Dict]:
        """
        Достаём логи за нужный период — удобно для анализа
        """
        time_mapping = {
            "1h": 3600, "6h": 21600, "24h": 86400,
            "3d": 259200, "7d": 604800
        }
        seconds_ago = time_mapping.get(time_range, 3600)
        min_score = (datetime.now() - timedelta(seconds=seconds_ago)).timestamp()
        # Ищем ключи в sorted set — быстро и просто
        log_keys = self.client.zrangebyscore(
            "logs:timestamps", min_score, float('inf'),
            start=0, num=limit
        )
        # Собираем данные логов в список
        logs = []
        for key in log_keys:
            log_data = self.client.hgetall(key)
            if log_data:
                logs.append(log_data)
        
        return logs
    
    async def store_anomaly(self, anomaly_data: Dict):
        """
        Сохраняем аномалию в отдельной структуре
        """
        # Создаем уникальный ключ для аномалии
        anomaly_id = f"anomaly:{anomaly_data['event_id']}"
        # Добавляем временную метку обнаружения
        anomaly_data['detected_at'] = datetime.now().isoformat()
        # Сохраняем аномалию
        pipeline = self.client.pipeline()
        pipeline.hset(anomaly_id, mapping=anomaly_data)
        pipeline.expire(anomaly_id, self.anomaly_ttl_hours * 3600)
        # Добавляем в sorted set по времени обнаружения для быстрого поиска
        pipeline.zadd("anomalies:timestamps", {anomaly_id: datetime.now().timestamp()})
        # Добавляем в set по типу аномалии для быстрой фильтрации
        if 'rule_name' in anomaly_data:
            pipeline.sadd(f"anomalies:type:{anomaly_data['rule_name']}", anomaly_id)
        # Добавляем в set по уровню критичности
        pipeline.sadd(f"anomalies:severity:{anomaly_data['severity']}", anomaly_id)
        pipeline.execute()
    
    def query_anomalies(self, time_range: str = "24h", severity: str = None, rule_name: str = None, limit: int = 1000) -> List[Dict]:
        """
        Ищем аномалии с фильтрацией по времени, критичности и типу
        """
        time_mapping = {
            "1h": 3600, "6h": 21600, "24h": 86400,
            "3d": 259200, "7d": 604800
        }
        seconds_ago = time_mapping.get(time_range, 86400)  # По умолчанию 24 часа для аномалий
        min_score = (datetime.now() - timedelta(seconds=seconds_ago)).timestamp()
        anomaly_keys = self.client.zrangebyscore(
            "anomalies:timestamps", min_score, float('inf'),
            start=0, num=limit
        )
        if severity:
            severity_keys = self.client.smembers(f"anomalies:severity:{severity}")
            anomaly_keys = set(anomaly_keys) & severity_keys
        if rule_name:
            rule_keys = self.client.smembers(f"anomalies:type:{rule_name}")
            anomaly_keys = set(anomaly_keys) & rule_keys
        anomalies = []
        for key in anomaly_keys:
            anomaly_data = self.client.hgetall(key)
            if anomaly_data:
                anomalies.append(anomaly_data)
        return anomalies
    
    def get_anomaly_stats(self) -> Dict:
        """
        Получаем статистику по аномалиям
        """
        stats = {
            "total": len(self.client.keys("anomaly:*")),
            "by_severity": {},
            "by_type": {}
        }
        for severity in ["low", "medium", "high", "critical"]:
            count = len(self.client.smembers(f"anomalies:severity:{severity}"))
            if count > 0:
                stats["by_severity"][severity] = count
        for key in self.client.keys("anomalies:type:*"):
            rule_name = key.split(":")[-1]
            count = len(self.client.smembers(key))
            if count > 0:
                stats["by_type"][rule_name] = count
        return stats

redis_client = RedisClient()