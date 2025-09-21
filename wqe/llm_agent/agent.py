# llm_agent.py
import openai
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import asyncio

class LLMLogAgent:
    def __init__(self, api_url: str, openai_api_key: str):
        self.api_url = api_url
        self.openai_client = openai.AsyncOpenAI(api_key=openai_api_key)
        self.system_prompt = """Ты - AI ассистент по кибербезопасности. Ты помогаешь анализировать логи, 
        обнаруживать аномалии и предоставлять рекомендации по безопасности. Ты можешь:
        
        1. Анализировать логи и выявлять подозрительную активность
        2. Предлагать действия при обнаружении аномалий
        3. Объяснять типы угроз и уязвимостей
        4. Предоставлять рекомендации по защите
        5. Отвечать на вопросы о безопасности сетей и систем
        
        Всегда будь точным, профессиональным и предоставляй конкретные рекомендации.
        Если тебе нужны данные из системы, используй доступные функции."""

    async def analyze_recent_logs(self, natural_language_query: str) -> str:
        """Анализ логов за последний час с помощью LLM"""
        try:
            # Получаем логи за последний час
            async with aiohttp.ClientSession() as session:
                response = await session.post(
                    f"{self.api_url}/api/v1/query",
                    json={"query": "", "time_range": "1h", "limit": 2000}
                )
                logs = await response.json()
            
            # Формируем промпт для LLM
            prompt = self._build_analysis_prompt(natural_language_query, logs['results'])
            
            # Отправляем в LLM
            completion = await self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1
            )
            
            return completion.choices[0].message.content
            
        except Exception as e:
            return f"Error analyzing logs: {str(e)}"
    
    def _build_analysis_prompt(self, query: str, logs: list) -> str:
        return f"""
        Analyze these security logs and answer the question: {query}
        
        Logs data (JSON format):
        {json.dumps(logs, indent=2)[:10000]}  # Ограничиваем размер
        
        Provide a structured response with:
        1. Summary of findings
        2. Key statistics
        3. Potential security issues
        4. Recommendations
        """

    def get_available_functions(self) -> List[Dict]:
        """Возвращает список доступных функций"""
        return [
            {
                "name": "get_logs_stats",
                "description": "Получить статистику по логам",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "get_anomaly_stats",
                "description": "Получить статистику по аномалиям",
                "parameters": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "search_logs",
                "description": "Поиск логов с фильтрацией",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "time_range": {
                            "type": "string",
                            "description": "Временной диапазон (например, 24h, 7d)"
                        },
                        "severity": {
                            "type": "string", 
                            "description": "Уровень серьезности"
                        },
                        "log_type": {
                            "type": "string",
                            "description": "Тип лога"
                        },
                        "anomaly": {
                            "type": "boolean",
                            "description": "Только аномалии"
                        }
                    }
                }
            },
            {
                "name": "search_anomalies",
                "description": "Поиск аномалий",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "time_range": {
                            "type": "string",
                            "description": "Временной диапазон"
                        },
                        "severity": {
                            "type": "string",
                            "description": "Уровень серьезности"
                        },
                        "bert_class": {
                            "type": "string",
                            "description": "Класс BERT"
                        }
                    }
                }
            }
        ]

    async def call_api_function(self, function_name: str, params: Dict) -> Dict:
        """Вызывает API функцию асинхронно"""
        try:
            async with aiohttp.ClientSession() as session:
                if function_name == "get_logs_stats":
                    async with session.get(f"{self.api_url}/api/v1/logs/stats") as response:
                        return await response.json()
                
                elif function_name == "get_anomaly_stats":
                    async with session.get(f"{self.api_url}/api/v1/anomalies/stats") as response:
                        return await response.json()
                
                elif function_name == "search_logs":
                    async with session.get(f"{self.api_url}/api/v1/logs/search", params=params) as response:
                        return await response.json()
                
                elif function_name == "search_anomalies":
                    async with session.get(f"{self.api_url}/api/v1/anomalies/search", params=params) as response:
                        return await response.json()
                
                else:
                    return {"error": f"Unknown function: {function_name}"}
                    
        except Exception as e:
            return {"error": str(e)}

    async def chat_with_ai(self, message: str, chat_history: List[Dict] = None) -> Dict:
        """Общается с ИИ и возвращает ответ с функциями"""
        try:
            messages = [
                {"role": "system", "content": self.system_prompt}
            ]
            
            if chat_history:
                messages.extend(chat_history)
            
            messages.append({"role": "user", "content": message})

            completion = await self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=messages,
                functions=self.get_available_functions(),
                function_call="auto"
            )

            response_message = completion.choices[0].message
            
            # Если ИИ хочет вызвать функцию
            if response_message.function_call:
                function_name = response_message.function_call.name
                function_args = json.loads(response_message.function_call.arguments)
                
                # Вызываем функцию
                function_result = await self.call_api_function(function_name, function_args)
                
                # Добавляем результат в историю и получаем финальный ответ
                messages.append(response_message)
                messages.append({
                    "role": "function",
                    "name": function_name,
                    "content": json.dumps(function_result)
                })
                
                final_completion = await self.openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=messages
                )
                
                return {
                    "response": final_completion.choices[0].message.content,
                    "function_called": function_name,
                    "function_args": function_args,
                    "function_result": function_result
                }
            
            else:
                return {
                    "response": response_message.content,
                    "function_called": None
                }
                
        except Exception as e:
            return {
                "response": f"Ошибка при общении с ИИ: {str(e)}",
                "function_called": None,
                "error": str(e)
            }

    async def get_health_status(self) -> Dict:
        """Проверяет статус API"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.api_url}/health") as response:
                    return await response.json()
        except Exception as e:
            return {"status": "error", "message": str(e)}

# Пример использования
async def main():
    # Инициализация агента
    agent = LLMLogAgent(
        api_url="http://localhost:8000",
        openai_api_key="your-openai-api-key-here"
    )
    
    # Проверка здоровья
    health = await agent.get_health_status()
    print("Health status:", health)
    
    # Пример чата
    response = await agent.chat_with_ai("Покажи статистику логов за последние 24 часа")
    print("AI Response:", response["response"])
    
    if response["function_called"]:
        print("Function called:", response["function_called"])
        print("Function result:", response["function_result"])

if __name__ == "__main__":
    asyncio.run(main())