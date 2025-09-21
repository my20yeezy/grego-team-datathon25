from fastapi import FastAPI, HTTPException, APIRouter
from transformers import BertForSequenceClassification, BertTokenizer
import torch
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
import uuid
from typing import Dict, Any, List, Optional
import redis
import json
from collections import defaultdict

import numpy as np

from telegram_notifier import telegram_notifier
app = FastAPI(title="Security Log API", version="1.0.0")

# Step 1: Load the model and tokenizer from Hugging Face
model = BertForSequenceClassification.from_pretrained("rahulm-selector/log-classifier-BERT-v1")
tokenizer = BertTokenizer.from_pretrained("rahulm-selector/log-classifier-BERT-v1")

# Классы аномалий
ANOMALY_CLASSES = {
    "0": "ALERT_IFD_CHANGE",
    "1": "ASIC_ALARM",
    "2": "BGP_INFO",
    "3": "INTERFACE_FLAP",
    "4": "InterfaceEvent",
    "5": "LLDP_NBR_DOWN",
    "6": "MPLS_CONFIG_CHANGE",
    "7": "MPLS_INTF_MAX_LABELS_ERROR",
    "8": "MPLS_PATH_STATUS",
    "9": "OAM_ADJACENCY_CFM",
    "10": "OAM_CFM",
    "11": "OAM_GENERAL",
    "12": "OSPF_NBRDOWN",
    "13": "RPD_RSVP_BYPASS_DOWN",
    "14": "RPD_RSVP_BYPASS_UP",
    "15": "RSVP_NBRDOWN",
    "16": "SMIC_SFPP_FAILED",
    "17": "SNMPD_AUTH_FAILURE",
    "18": "VRRPD_MISSING_VIP",
    "19": "aaa",
    "20": "bfd_change",
    "21": "bfd_down",
    "22": "bfd_flap",
    "23": "bfd_sess_create",
    "24": "bfd_sess_destroy",
    "25": "bfd_state_change",
    "26": "bgp_nbr_down",
    "27": "bgp_nbr_reset",
    "28": "bgp_state_change",
    "29": "bgp_updown",
    "30": "cli_cmd_executed",
    "31": "config_event",
    "32": "critical_log_event",
    "33": "demon_timeouts",
    "34": "eigrp",
    "35": "firewall_critical",
    "36": "firewall_high",
    "37": "firewall_low",
    "38": "firewall_medium",
    "39": "if_down",
    "40": "if_flap",
    "41": "if_lag",
    "42": "if_security",
    "43": "if_updown",
    "44": "neighbor_updown",
    "45": "ospf_neigh_state_flap",
    "46": "port_link_updown",
    "47": "power_change",
    "48": "ptp",
    "49": "rt_entry_add_msg_proc",
    "50": "rt_entry_failed",
    "51": "sfp_link_power",
    "52": "ssh",
    "53": "stp",
    "54": "stp_change",
    "55": "system_reboot",
    "56": "ui_commit_progress",
    "57": "ui_config_audit",
    "58": "vrrp_vlan"
}

# Критические классы, которые считаются аномалиями
CRITICAL_ANOMALY_CLASSES = {
    "1", "2", "3", "5", "6", "7", "8", "12", "13", "15", "16", "17",
    "20", "21", "22", "25", "26", "27", "28", "29", "32", "35", "36",
    "39", "40", "42", "45", "50", "52", "54", "55"
}

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Инициализация Redis
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)

# Создаем router для дополнительных эндпоинтов
router = APIRouter()

def classify_log_with_bert(log_text: str) -> Dict[str, Any]:
    """Классификация лога с помощью BERT модели"""
    try:
        # Токенизация текста
        inputs = tokenizer(
            log_text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )
        
        # Предсказание
        with torch.no_grad():
            outputs = model(**inputs)
        
        # Получаем предсказания
        predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
        predicted_class = torch.argmax(predictions, dim=-1).item()
        confidence = predictions[0][predicted_class].item()
        
        class_name = ANOMALY_CLASSES.get(str(predicted_class), "UNKNOWN")
        
        return {
            "class_id": predicted_class,
            "class_name": class_name,
            "confidence": float(confidence),
            "is_anomaly": str(predicted_class) in CRITICAL_ANOMALY_CLASSES
        }
    
    except Exception as e:
        return {
            "class_id": -1,
            "class_name": "ERROR",
            "confidence": 0.0,
            "is_anomaly": False,
            "error": str(e)
        }

async def detect_and_store_anomaly(log_data: Dict[str, Any], bert_result: Dict[str, Any]):
    """Обнаружение и сохранение аномалии с отправкой в Telegram"""
    if bert_result["is_anomaly"]:
        anomaly_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()
        
        # Определяем severity на основе confidence
        confidence = bert_result['confidence']
        if confidence > 0.8:
            severity = 'high'
        elif confidence > 0.6:
            severity = 'medium'
        else:
            severity = 'low'
        
        anomaly_data = {
            'id': anomaly_id,
            'log_id': log_data.get('event_id', 'unknown'),
            'source': log_data.get('source', 'unknown'),
            'log_type': log_data.get('log_type', 'unknown'),
            'timestamp': timestamp,
            'bert_class': bert_result['class_name'],
            'bert_class_id': bert_result['class_id'],
            'confidence': confidence,
            'severity': severity,
            'description': f"BERT detected anomaly: {bert_result['class_name']} (confidence: {confidence:.3f})",
            'raw_log': json.dumps(log_data.get('raw_data', {})),
            'status': 'new'
        }
        
        # Сохраняем аномалию в Redis
        anomaly_key = f"anomaly:{anomaly_id}"
        redis_client.hset(anomaly_key, mapping=anomaly_data)
        
        # Добавляем в отсортированный набор по времени
        redis_client.zadd("anomalies:timestamps", {anomaly_key: datetime.utcnow().timestamp()})
        
        # Добавляем в список всех аномалий
        redis_client.lpush("anomalies_list", anomaly_id)
        
        print(f"Anomaly detected: {bert_result['class_name']} (confidence: {confidence:.3f}, severity: {severity})")
        
        # Отправляем alert в Telegram если confidence высокий
        if confidence >= telegram_notifier.alert_threshold:
            telegram_notifier.send_alert(anomaly_data)
        
        return anomaly_data
    
    return None

@app.get("/api/v1/telegram/status")
async def get_telegram_status():
    """Статус Telegram интеграции"""
    return {
        "enabled": telegram_notifier.enabled,
        "connected": telegram_notifier.test_connection(),
        "alert_threshold": telegram_notifier.alert_threshold,
        "bot_configured": bool(telegram_notifier.bot_token),
        "chat_configured": bool(telegram_notifier.chat_id)
    }

@app.post("/api/v1/telegram/test")
async def test_telegram_alert():
    """Тестовая отправка alert в Telegram"""
    test_anomaly = {
        'id': 'test-' + str(uuid.uuid4()),
        'bert_class': 'TEST_ALERT',
        'confidence': 0.95,
        'severity': 'high',
        'source': 'test-system',
        'timestamp': datetime.utcnow().isoformat(),
        'description': 'Test alert from security system'
    }
    
    success = telegram_notifier.send_alert(test_anomaly)
    return {"success": success, "message": "Test alert sent" if success else "Failed to send test alert"}
@app.get("/")
async def root():
    return {"message": "Security Log API is running!"}

@app.get("/health")
async def health_check():
    try:
        redis_ok = redis_client.ping()
        
        # Проверяем доступность модели BERT
        test_text = "test log message"
        bert_result = classify_log_with_bert(test_text)
        bert_ok = bert_result["class_id"] != -1
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "redis_connected": redis_ok,
            "bert_model_loaded": bert_ok,
            "service": "log-api"
        }
    except Exception as e:
        return {
            "status": "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
            "service": "log-api"
        }

# Добавьте этот endpoint в api/main.py (после других endpoints)
@app.post("/api/v1/chat")
async def chat_with_ai(request: Dict[str, Any]):
    """Endpoint для чата с ИИ"""
    try:
        message = request.get('message', '')
        chat_history = request.get('chat_history', [])
        
        # Простой ответ для тестирования
        if message.lower() == "тест":
            return {
                "response": "✅ Тест успешен! Сервер работает корректно.",
                "function_called": None
            }
        elif "статистик" in message.lower():
            return {
                "response": "📊 Вот статистика системы:\n• Логи: 150\n• Аномалии: 12\n• Уровень аномалий: 8%",
                "function_called": None
            }
        elif "аномал" in message.lower():
            return {
                "response": "🚨 Обнаружено 12 аномалий:\n• 5 высокой серьезности\n• 4 средней\n• 3 низкой",
                "function_called": None
            }
        else:
            return {
                "response": f"🤖 Привет! Я ваш AI-ассистент по безопасности. Вы сказали: '{message}'\n\nЯ могу помочь с анализом логов, обнаружением аномалий и рекомендациями по безопасности.",
                "function_called": None
            }
        
    except Exception as e:
        return {
            "response": f"Произошла ошибка при обработке запроса: {str(e)}",
            "error": True
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat error: {str(e)}")

@app.post("/api/v1/logs")
async def ingest_log(log_data: Dict[str, Any]):
    """Endpoint для приема логов"""
    try:
        log_id = str(uuid.uuid4())
        timestamp = log_data.get('timestamp', datetime.utcnow().isoformat())
        
        # Извлекаем текст лога для анализа BERT
        log_text = ""
        raw_data = log_data.get('raw_data', {})
        if isinstance(raw_data, dict):
            log_text = raw_data.get('msg', '') or str(raw_data)
        else:
            log_text = str(raw_data)
        
        # Анализируем лог с помощью BERT
        bert_result = classify_log_with_bert(log_text)
        
        # Сохраняем в Redis
        log_key = f"log:{log_id}"
        redis_client.hset(log_key, mapping={
            'id': log_id,
            'source': log_data.get('source', 'unknown'),
            'log_type': log_data.get('log_type', 'unknown'),
            'timestamp': timestamp,
            'raw_data': json.dumps(log_data.get('raw_data', {})),
            'bert_class': bert_result['class_name'],
            'bert_class_id': str(bert_result['class_id']),
            'bert_confidence': str(bert_result['confidence']),
            'is_anomaly': str(bert_result['is_anomaly'])
        })
        
        # Сохраняем временную метку для поиска
        redis_client.zadd("logs:timestamps", {log_key: datetime.utcnow().timestamp()})
        
        # Сохраняем в список для быстрого доступа
        redis_client.lpush("logs_list", json.dumps({
            **log_data,
            'bert_analysis': bert_result
        }))
        
        # Если это аномалия - сохраняем отдельно
        anomaly = None
        if bert_result["is_anomaly"]:
            anomaly = await detect_and_store_anomaly(log_data, bert_result)
        
        return {
            "status": "success",
            "log_id": log_id,
            "bert_analysis": bert_result,
            "anomaly_detected": bert_result["is_anomaly"],
            "anomaly_id": anomaly["id"] if anomaly else None
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/v1/logs/create")
async def create_log(log: Dict[Any, Any]):
    """Альтернативный endpoint для создания логов"""
    try:
        # Анализируем лог с помощью BERT
        log_text = ""
        raw_data = log.get('raw_data', {})
        if isinstance(raw_data, dict):
            log_text = raw_data.get('msg', '') or str(raw_data)
        else:
            log_text = str(raw_data)
        
        bert_result = classify_log_with_bert(log_text)
        
        # Save log as JSON string in Redis list
        log_with_bert = {
            **log,
            'bert_analysis': bert_result
        }
        redis_client.lpush("logs_list", json.dumps(log_with_bert))
        
        # Также сохраняем как hash для consistency
        log_id = log.get('event_id', str(uuid.uuid4()))
        log_key = f"log:{log_id}"
        redis_client.hset(log_key, mapping={
            'id': log_id,
            'source': log.get('source', 'unknown'),
            'log_type': log.get('log_type', 'unknown'),
            'timestamp': log.get('timestamp', datetime.utcnow().isoformat()),
            'raw_data': json.dumps(log.get('raw_data', {})),
            'bert_class': bert_result['class_name'],
            'bert_class_id': str(bert_result['class_id']),
            'bert_confidence': str(bert_result['confidence']),
            'is_anomaly': str(bert_result['is_anomaly'])
        })
        
        # Если это аномалия - сохраняем отдельно
        anomaly = None
        if bert_result["is_anomaly"]:
            anomaly = await detect_and_store_anomaly(log, bert_result)
        
        return {
            "status": "success",
            "log_id": log_id,
            "bert_analysis": bert_result,
            "anomaly_detected": bert_result["is_anomaly"],
            "anomaly_id": anomaly["id"] if anomaly else None
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/logs/stats")
async def get_logs_stats():
    """Статистика по логам"""
    try:
        logs = redis_client.lrange("logs_list", 0, -1)
        log_dicts: List[Dict[str, Any]] = []
        
        for log_str in logs:
            try:
                log_dict = json.loads(log_str)
                log_dicts.append(log_dict)
            except Exception:
                continue

        total_logs = len(log_dicts)
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        by_bert_class = defaultdict(int)
        anomalies_count = 0
        
        for log in log_dicts:
            severity = log.get("severity", "unknown")
            log_type = log.get("log_type", "unknown")
            bert_class = log.get('bert_analysis', {}).get('class_name', 'unknown')
            
            by_severity[severity] += 1
            by_type[log_type] += 1
            by_bert_class[bert_class] += 1
            
            if log.get('bert_analysis', {}).get('is_anomaly', False):
                anomalies_count += 1

        return {
            "total": total_logs,
            "anomalies": anomalies_count,
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "by_bert_class": dict(by_bert_class),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/logs/search")
async def search_logs(
    time_range: str = "24h",
    severity: Optional[str] = None,
    type: Optional[str] = None,
    anomaly: Optional[bool] = None,
    limit: int = 100
):
    """Поиск логов с фильтрацией"""
    try:
        logs = redis_client.lrange("logs_list", 0, -1)
        log_dicts: List[Dict[str, Any]] = []
        
        for log_str in logs:
            try:
                log_dict = json.loads(log_str)
                log_dicts.append(log_dict)
            except Exception:
                continue

        filtered_logs: List[Dict[str, Any]] = []
        
        # Вычисляем временной порог
        hours = int(time_range.replace("h", "")) if time_range.endswith("h") else int(time_range)
        time_threshold = datetime.utcnow() - timedelta(hours=hours)

        for log in log_dicts:
            # Фильтрация по времени
            log_time_str = log.get("timestamp")
            if log_time_str:
                try:
                    log_time = datetime.fromisoformat(log_time_str.replace('Z', '+00:00'))
                    if log_time < time_threshold:
                        continue
                except Exception:
                    continue

            # Фильтрация по severity
            if severity and log.get("severity") != severity:
                continue
                
            # Фильтрация по типу
            if type and log.get("log_type") != type:
                continue
                
            # Фильтрация по аномалии
            if anomaly is not None:
                is_anomaly = log.get('bert_analysis', {}).get('is_anomaly', False)
                if is_anomaly != anomaly:
                    continue

            filtered_logs.append(log)
            
            # Ограничение по количеству
            if len(filtered_logs) >= limit:
                break

        return {
            "results": filtered_logs,
            "count": len(filtered_logs),
            "time_range": time_range
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/anomalies/stats")
async def get_anomaly_stats():
    """Статистика аномалий"""
    try:
        anomaly_keys = redis_client.keys("anomaly:*")
        total_anomalies = len(anomaly_keys)
        
        by_severity = defaultdict(int)
        by_bert_class = defaultdict(int)
        by_status = defaultdict(int)
        
        for key in anomaly_keys:
            anomaly_data = redis_client.hgetall(key)
            if anomaly_data:
                severity = anomaly_data.get('severity', 'unknown')
                bert_class = anomaly_data.get('bert_class', 'unknown')
                status = anomaly_data.get('status', 'new')
                
                by_severity[severity] += 1
                by_bert_class[bert_class] += 1
                by_status[status] += 1
        
        return {
            "total_anomalies": total_anomalies,
            "by_severity": dict(by_severity),
            "by_bert_class": dict(by_bert_class),
            "by_status": dict(by_status),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/v1/anomalies/search")
async def search_anomalies(
    time_range: str = "24h",
    severity: Optional[str] = None,
    bert_class: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50
):
    """Поиск аномалий"""
    try:
        anomaly_keys = redis_client.keys("anomaly:*")
        anomalies = []
        
        hours = int(time_range.replace("h", "")) if time_range.endswith("h") else 24
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        for key in anomaly_keys:
            anomaly_data = redis_client.hgetall(key)
            if anomaly_data:
                # Фильтрация по времени
                anomaly_time_str = anomaly_data.get('timestamp')
                if anomaly_time_str:
                    try:
                        anomaly_time = datetime.fromisoformat(anomaly_time_str.replace('Z', '+00:00'))
                        if anomaly_time < time_threshold:
                            continue
                    except Exception:
                        continue
                
                # Фильтрация по severity
                if severity and anomaly_data.get('severity') != severity:
                    continue
                    
                # Фильтрация по классу BERT
                if bert_class and anomaly_data.get('bert_class') != bert_class:
                    continue
                    
                # Фильтрация по status
                if status and anomaly_data.get('status') != status:
                    continue
                
                # Парсим confidence
                try:
                    anomaly_data['confidence'] = float(anomaly_data.get('confidence', 0))
                except:
                    anomaly_data['confidence'] = 0.0
                
                anomalies.append(anomaly_data)
                
                # Ограничение по количеству
                if len(anomalies) >= limit:
                    break
        
        return {
            "anomalies": anomalies,
            "count": len(anomalies),
            "time_range": time_range,
            "filters": {
                "severity": severity,
                "bert_class": bert_class,
                "status": status
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/query")
async def query_logs(request: Dict[str, Any]):
    """Query endpoint для запроса логов"""
    try:
        time_range = request.get('time_range', '1h')
        limit = min(request.get('limit', 100), 1000)
        
        # Получаем все ключи логов
        log_keys = redis_client.keys("log:*")
        
        # Ограничиваем количество
        log_keys = log_keys[:limit]
        
        # Получаем данные логов
        logs = []
        for key in log_keys:
            log_data = redis_client.hgetall(key)
            if log_data:
                # Парсим raw_data из JSON строки
                if 'raw_data' in log_data:
                    try:
                        log_data['raw_data'] = json.loads(log_data['raw_data'])
                    except:
                        log_data['raw_data'] = {}
                logs.append(log_data)
        
        return {
            "results": logs,
            "count": len(logs),
            "time_range": time_range
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/stats")
async def get_stats():
    """Общая статистика системы"""
    try:
        total_logs_hash = len(redis_client.keys("log:*"))
        total_logs_list = redis_client.llen("logs_list")
        total_anomalies = len(redis_client.keys("anomaly:*"))
        
        redis_info = redis_client.info()
        
        return {
            "logs": {
                "hash_storage": total_logs_hash,
                "list_storage": total_logs_list,
                "total_unique": total_logs_hash
            },
            "anomalies": {
                "total": total_anomalies,
                "new": len([k for k in redis_client.keys("anomaly:*") 
                          if redis_client.hget(k, 'status') == 'new'])
            },
            "bert_model": {
                "classes_loaded": len(ANOMALY_CLASSES),
                "critical_classes": len(CRITICAL_ANOMALY_CLASSES)
            },
            "redis": {
                "used_memory": redis_info.get('used_memory_human', 'N/A'),
                "connected_clients": redis_info.get('connected_clients', 0)
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Подключаем router с дополнительными эндпоинтами
app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)