import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
from typing import Dict, Any, List
import joblib
import os

class IsolationForestModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_path = "/app/models/isolation_forest.joblib"
        self.scaler_path = "/app/models/scaler.joblib"
    
    async def load_model(self):
        """Загрузка предобученной модели"""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                print("ML model loaded successfully")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = IsolationForest(contamination=0.1, random_state=42)
    
    async def train(self, training_data: List[Dict[str, Any]]):
        """Обучение модели на исторических данных"""
        try:
            # Преобразуем в DataFrame и выбираем признаки
            df = pd.DataFrame(training_data)
            features = self._extract_features(df)
            
            # Масштабируем признаки
            scaled_features = self.scaler.fit_transform(features)
            
            # Обучаем модель
            self.model.fit(scaled_features)
            
            # Сохраняем модель
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            
            print("ML model trained and saved successfully")
            
        except Exception as e:
            print(f"Error training model: {e}")
    
    async def detect_anomaly(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Обнаружение аномалии с помощью ML модели"""
        if self.model is None:
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "description": "ML model not ready",
                "severity": "low"
            }
        
        try:
            # Извлекаем признаки из лога
            features = self._extract_features_single(log_data)
            
            if features is None:
                return {
                    "is_anomaly": False,
                    "confidence": 0.0,
                    "description": "Insufficient features for ML analysis",
                    "severity": "low"
                }
            
            # Масштабируем и предсказываем
            scaled_features = self.scaler.transform([features])
            prediction = self.model.predict(scaled_features)
            scores = self.model.decision_function(scaled_features)
            
            is_anomaly = prediction[0] == -1
            confidence = abs(scores[0])  # Чем больше score по модулю, тем увереннее
            
            if is_anomaly:
                return {
                    "is_anomaly": True,
                    "confidence": min(confidence * 10, 1.0),  # Нормализуем confidence
                    "rule_name": "ml_anomaly",
                    "description": "Anomaly detected by machine learning model",
                    "severity": "medium" if confidence < 0.5 else "high"
                }
            
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "description": "No ML anomaly detected",
                "severity": "low"
            }
            
        except Exception as e:
            print(f"ML detection error: {e}")
            return {
                "is_anomaly": False,
                "confidence": 0.0,
                "description": f"ML detection error: {str(e)}",
                "severity": "low"
            }
    
    def _extract_features(self, df: pd.DataFrame) -> np.ndarray:
        """Извлечение признаков из DataFrame"""
        # Здесь должна быть сложная логика извлечения признаков
        # Пока простой пример
        features = []
        for _, row in df.iterrows():
            feat = self._extract_features_single(row.to_dict())
            if feat is not None:
                features.append(feat)
        
        return np.array(features)
    
    def _extract_features_single(self, log_data: Dict[str, Any]) -> Optional[np.ndarray]:
        """Извлечение признаков из одиночного лога"""
        try:
            # Простые числовые признаки (пример)
            features = [
                len(str(log_data.get("src_ip", ""))),
                len(str(log_data.get("dst_ip", ""))),
                int(log_data.get("dst_port", 0)) or 0,
                1 if log_data.get("success") else 0,
                # Добавьте больше признаков здесь
            ]
            return np.array(features)
        except:
            return None