from app.services.event_bus import EventBus
from app.core.config import settings

bus = EventBus(settings.redis_url)
