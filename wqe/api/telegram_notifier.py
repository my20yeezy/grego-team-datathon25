# api/telegram_notifier.py
import os
import requests
import json
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

class TelegramNotifier:
    def __init__(self):
        self.bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.chat_id = os.getenv('TELEGRAM_CHAT_ID')
        self.alert_threshold = float(os.getenv('TELEGRAM_ALERT_THRESHOLD', 0.8))
        self.enabled = bool(self.bot_token and self.chat_id)

    def send_alert(self, anomaly_data: Dict[str, Any]) -> bool:
        """Отправка alert в Telegram"""
        if not self.enabled:
            print("Telegram notifier disabled - check TOKEN and CHAT_ID in .env")
            return False

        if anomaly_data.get('confidence', 0) < self.alert_threshold:
            return False

        message = self._format_message(anomaly_data)
        
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200
            
        except Exception as e:
            print(f"Telegram send error: {e}")
            return False

    def _format_message(self, anomaly_data: Dict[str, Any]) -> str:
        """Форматирование сообщения для Telegram"""
        confidence = anomaly_data.get('confidence', 0)
        class_name = anomaly_data.get('bert_class', 'Unknown')
        severity = anomaly_data.get('severity', 'unknown')
        source = anomaly_data.get('source', 'unknown')
        anomaly_id = anomaly_data.get('id', 'N/A')
        
        emoji = "🔴" if severity == "high" else "🟡" if severity == "medium" else "🔵"
        
        return f"""{emoji} <b>🚨 CRITICAL SECURITY ALERT</b> {emoji}

<b>Type:</b> {class_name}
<b>Severity:</b> {severity.upper()}
<b>Confidence:</b> {confidence:.2%}
<b>Source:</b> {source}
<b>ID:</b> <code>{anomaly_id}</code>

<b>Timestamp:</b> {anomaly_data.get('timestamp', 'N/A')}

⚠️ <i>Immediate attention required</i> ⚠️"""

    def test_connection(self) -> bool:
        """Тестирование подключения к Telegram"""
        if not self.enabled:
            return False
            
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/getMe"
            response = requests.get(url, timeout=10)
            return response.status_code == 200
        except:
            return False

# Глобальный инстанс notifier
telegram_notifier = TelegramNotifier()