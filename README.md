# Система сбора логов

## Быстрый старт:
1. Убедитесь что установлены Docker и Docker Compose
2. Склонируйте репозиторий
3. Выполните: `docker-compose -f opensearch/docker-compose.yml up -d`
4. Проверьте: http://localhost:5601 (admin/GregoTeam#69!8--)

## Отправка логов:
```bash
# HTTP API endpoint: http://localhost:8686
curl -X POST http://localhost:8686 \
  -H "Content-Type: application/json" \
  -d '{"level": "INFO", "message": "Your log message", "source": "your-app"}'