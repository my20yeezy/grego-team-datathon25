from datetime import datetime
from typing import Dict, Any
import uuid

class LogNormalizer:
    def __init__(self):
        self.schema_mapping = {
            "cowrie_ssh": self.normalize_cowrie_ssh,
            "palo_alto_firewall": self.normalize_palo_alto,
            "fortinet_firewall": self.normalize_fortinet,
            "generic_syslog": self.normalize_syslog
        }
    
    def normalize(self, source: str, log_type: str, raw_data: Dict[str, Any], timestamp: datetime) -> Dict[str, Any]:
        """
        Приводим лог к единому формату, чтобы дальше было проще работать
        """
        normalizer_func = self.schema_mapping.get(log_type, self.normalize_generic)
        normalized = normalizer_func(raw_data)
        # Добавляем общие поля — чтобы не потерять важное
        normalized.update({
            "event_id": str(uuid.uuid4()),
            "received_at": datetime.utcnow().isoformat(),
            "source": source,
            "log_type": log_type,
            "timestamp": timestamp.isoformat(),
            "raw_data": raw_data  # Оригинальные данные — пригодятся для расследования
        })
        return normalized
    
    def normalize_cowrie_ssh(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_type": data.get("eventid", "unknown"),
            "src_ip": data.get("src_ip"),
            "src_port": data.get("src_port"),
            "dst_ip": data.get("dst_ip"),
            "dst_port": data.get("dst_port"),
            "username": data.get("username"),
            "password": data.get("password"),
            "success": data.get("success", False),
            "command": data.get("input"),
            "session": data.get("session"),
            "protocol": "ssh"
        }
    
    def normalize_palo_alto(self, data: Dict[str, Any]) -> Dict[str, Any]:
        # Разбираем CEF-формат, вытаскиваем полезное
        return {
            "event_type": "firewall_traffic",
            "src_ip": data.get("src"),
            "dst_ip": data.get("dst"),
            "src_port": data.get("spt"),
            "dst_port": data.get("dpt"),
            "action": data.get("act"),
            "rule": data.get("rule"),
            "bytes_sent": data.get("bytes"),
            "threat_id": data.get("threatid"),
            "severity": data.get("severity")
        }
    
    def normalize_fortinet(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_type": "firewall_traffic",
            "src_ip": data.get("srcip"),
            "dst_ip": data.get("dstip"),
            "src_port": data.get("srcport"),
            "dst_port": data.get("dstport"),
            "action": data.get("action"),
            "service": data.get("service"),
            "bytes": data.get("sentbyte")
        }
    
    def normalize_syslog(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_type": "syslog_message",
            "message": data.get("message"),
            "facility": data.get("facility"),
            "severity": data.get("severity"),
            "hostname": data.get("hostname")
        }
    
    def normalize_generic(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "event_type": "generic_event",
            "raw_message": str(data)
        }