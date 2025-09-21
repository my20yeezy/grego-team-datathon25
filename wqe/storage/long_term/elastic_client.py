from elasticsearch import AsyncElasticsearch
from typing import Dict
import json

class ElasticsearchClient:
    def __init__(self):
        self.client = AsyncElasticsearch(["http://elasticsearch:9200"])
        self.index_prefix = "security-logs"
    
    async def store_log_long_term(self, log_data: Dict):
        """Сохранение лога в Elasticsearch для долгосрочного хранения"""
        index_name = f"{self.index_prefix}-{log_data['timestamp'][:7]}"  # monthly indices
        
        await self.client.index(
            index=index_name,
            document=log_data,
            id=log_data['event_id']
        )
    
    async def query_historical_data(self, query: Dict, size: int = 10000):
        """Запрос исторических данных для ML обучения"""
        response = await self.client.search(
            index=f"{self.index_prefix}-*",
            body=query,
            size=size
        )
        return response['hits']['hits']

es_client = ElasticsearchClient()