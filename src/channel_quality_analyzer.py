"""
Интеллектуальный анализатор качества каналов с использованием SQLite и долгосрочной истории.
Оценивает каналы на основе метрик за последние N дней (по умолчанию 7) и отслеживает
динамику, позволяя каналам восстанавливаться после периодов неактивности.
"""

import logging
import numpy as np
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

from db import get_db
from user_settings import (
    CHANNEL_HEALTH_THRESHOLD,
    CHANNEL_MIN_CONFIGS,
    CHANNEL_MIN_VALID_RATIO,
    CHANNEL_MIN_PROTOCOLS,
    CHANNEL_HISTORY_DAYS,
    CHANNEL_WHITELIST,
    CHANNEL_RECOVERING_TREND_THRESHOLD,
    CHANNEL_MIN_RECENT_DAYS_FOR_TREND
)

logger = logging.getLogger(__name__)

HEALTH_THRESHOLD = max(30.0, CHANNEL_HEALTH_THRESHOLD)
MIN_CONFIGS = max(3, CHANNEL_MIN_CONFIGS)
MIN_VALID_RATIO = max(0.05, CHANNEL_MIN_VALID_RATIO)
MIN_PROTOCOLS = max(1, CHANNEL_MIN_PROTOCOLS)
HISTORY_DAYS = max(7, CHANNEL_HISTORY_DAYS)
RECOVERING_TREND_THRESHOLD = max(0.05, CHANNEL_RECOVERING_TREND_THRESHOLD)
MIN_RECENT_DAYS_FOR_TREND = max(2, CHANNEL_MIN_RECENT_DAYS_FOR_TREND)
MAX_HISTORY_SCORES = 100


class ChannelQualityAnalyzer:
    """
    Анализирует качество каналов на основе долгосрочной истории (SQLite) с учётом трендов.
    """

    def __init__(self):
        self._whitelist = set(CHANNEL_WHITELIST)
        self._is_first_run = self._check_first_run()
        self._last_check_cache = {}

    def _check_first_run(self) -> bool:
        import asyncio
        try:
            # Получаем объект БД и выполняем запрос
            db = asyncio.run(get_db())
            last_run = asyncio.run(db.get_last_run())
            return last_run is None
        except Exception:
            return True

    async def _get_channel_history_scores(self, url: str, days: int = HISTORY_DAYS) -> List[Dict]:
        db = await get_db()
        try:
            return await db.get_channel_history_scores(url, days, MAX_HISTORY_SCORES)
        except Exception as e:
            logger.warning(f"Failed to get channel history for {url}: {e}")
            return []

    async def get_channel_score(self, url: str) -> float:
        """Вычисляет взвешенное скользящее среднее."""
        history = await self._get_channel_history_scores(url, days=7)
        if not history:
            return 0
        scores = [h['score'] for h in history if h['score'] > 0]
        if not scores:
            return 0
        weights = np.exp(np.linspace(-1, 0, len(scores)))
        return np.average(scores, weights=weights)

    async def _get_channel_state(self, url: str) -> str:
        if url in self._whitelist:
            return 'active'

        if self._is_first_run:
            logger.info(f"First run: assuming all channels active, including {url}")
            return 'active'

        if url in self._last_check_cache:
            last_check = self._last_check_cache[url]
            if (datetime.now(timezone.utc) - last_check).days < 3:
                return 'inactive'

        score = await self.get_channel_score(url)
        if score >= HEALTH_THRESHOLD:
            return 'active'
        else:
            self._last_check_cache[url] = datetime.now(timezone.utc)
            return 'inactive'

    async def is_channel_healthy(self, channel_url: str) -> bool:
        state = await self._get_channel_state(channel_url)
        return state == 'active'

    async def get_channel_state(self, channel_url: str) -> str:
        return await self._get_channel_state(channel_url)

    async def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        unhealthy = []
        for url in channel_urls:
            if await self._get_channel_state(url) == 'inactive':
                unhealthy.append(url)
        return unhealthy

    async def update_health(self, channel_urls: List[str], run_id: int = None):
        try:
            from config import ProxyConfig
            config = ProxyConfig()
            db = await get_db()
            for ch in config.SOURCE_URLS:
                if ch.url in channel_urls:
                    m = ch.metrics
                    metrics = {
                        'total_configs': m.total_configs,
                        'valid_configs': m.valid_configs,
                        'unique_configs': m.unique_configs,
                        'avg_response_time': m.avg_response_time,
                        'last_success': m.last_success_time.isoformat() if m.last_success_time else None,
                        'fail_count': m.fail_count,
                        'success_count': m.success_count,
                        'overall_score': m.overall_score,
                        'protocol_counts': m.protocol_counts or {}
                    }
                    await db.update_channel(ch.url, metrics, enabled=ch.enabled)
                    if run_id is not None:
                        await db.add_channel_history(ch.url, run_id, metrics)
            logger.info(f"Channel health updated for {len(channel_urls)} channels.")
        except Exception as e:
            logger.error(f"Failed to update channel health: {e}")

    async def get_health_report(self) -> Dict:
        db = await get_db()
        channels = await db.get_all_channels()
        states = {'active': 0, 'inactive': 0}
        total = len(channels)
        for ch in channels:
            state = await self._get_channel_state(ch['url'])
            states[state] = states.get(state, 0) + 1
        return {
            'channels': channels,
            'summary': {
                'total': total,
                'active': states.get('active', 0),
                'inactive': states.get('inactive', 0)
            }
        }

    async def prune_bad_channels(self, channel_urls: List[str]) -> List[str]:
        healthy = []
        for url in channel_urls:
            state = await self._get_channel_state(url)
            if state == 'inactive':
                logger.info(f"Channel {url} is inactive, removing.")
            else:
                healthy.append(url)
        return healthy
