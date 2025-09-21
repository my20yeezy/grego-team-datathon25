import redis

redis_client = redis.Redis(
    host='redis',  # используем имя сервиса из docker-compose
    port=6379,
    db=0,
    decode_responses=True
)