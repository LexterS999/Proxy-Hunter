"""
channel_quality_analyzer.py - Анализ качества каналов-источников
"""

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


class ChannelQualityAnalyzer:
    """Анализирует качество каналов-источников прокси"""

    # Порог success rate (в %), ниже которого канал считается нездоровым
    HEALTH_THRESHOLD = 10.0
    # Минимальное количество записей для учёта статистики
    MIN_SAMPLES = 3

    def __init__(self, db=None):
        self.db = db

    def _get_db(self):
        if self.db is None:
            # [CHANGE] ленивая инициализация БД (без побочных эффектов при импорте db)
            from db import get_db
            self.db = get_db()
        return self.db

    def update_health(self, channel_urls: List[str], run_id: Optional[str] = None) -> None:
        """
        [CHANGE] Реально обновляет метрики здоровья каналов в БД.
        Ранее метод имел пустое тело (pass), и фильтрация опиралась на устаревшие данные.

        Агрегирует статистику из таблицы history (последние записи по каждому каналу)
        и записывает success_rate / total_configs в таблицу channels.
        """
        if not channel_urls:
            return
        try:
            db = self._get_db()
            for url in channel_urls:
                records = db.get_channel_stats(url, limit=100)
                if not records:
                    continue

                total_runs = len(records)
                total_configs = sum(int(r.get('total_configs', 0) or 0) for r in records)
                success_runs = sum(1 for r in records if (r.get('success') or 0) > 0)
                success_rate = (success_runs / total_runs * 100) if total_runs else 0.0

                db.update_channel(
                    url,
                    success_rate=success_rate,
                    total_configs=total_configs,
                    last_run=run_id,
                )
            logger.debug(f"📊 Обновлено здоровье {len(channel_urls)} каналов")
        except Exception as e:
            logger.debug(f"⚠️ update_health: {e}")

    def get_healthy_channels(self, channel_urls: List[str]) -> List[str]:
        """Возвращает каналы с приемлемым success rate"""
        healthy = []
        try:
            db = self._get_db()
            for url in channel_urls:
                info = db.get_channel(url)
                if not info:
                    # Новый канал — даём шанс
                    healthy.append(url)
                    continue
                total = int(info.get('total_configs', 0) or 0)
                rate = float(info.get('success_rate', 0.0) or 0.0)
                # Если данных мало — не фильтруем
                if total < self.MIN_SAMPLES or rate >= self.HEALTH_THRESHOLD:
                    healthy.append(url)
            return healthy if healthy else channel_urls
        except Exception as e:
            logger.debug(f"⚠️ get_healthy_channels: {e}")
            return channel_urls
