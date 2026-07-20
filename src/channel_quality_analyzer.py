"""
Интеллектуальный анализатор качества каналов с использованием SQLite и долгосрочной истории.
Оценивает каналы на основе метрик за последние N дней (по умолчанию 7) и отслеживает
динамику, позволяя каналам восстанавливаться после периодов неактивности.
"""

import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

from db import HistoryDB
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

# Переопределяем пороги, чтобы сделать их более консервативными
HEALTH_THRESHOLD = max(30.0, CHANNEL_HEALTH_THRESHOLD)
MIN_CONFIGS = max(3, CHANNEL_MIN_CONFIGS)
MIN_VALID_RATIO = max(0.05, CHANNEL_MIN_VALID_RATIO)
MIN_PROTOCOLS = max(1, CHANNEL_MIN_PROTOCOLS)
HISTORY_DAYS = max(7, CHANNEL_HISTORY_DAYS)  # минимум 7 дней
RECOVERING_TREND_THRESHOLD = max(0.05, CHANNEL_RECOVERING_TREND_THRESHOLD)
MIN_RECENT_DAYS_FOR_TREND = max(2, CHANNEL_MIN_RECENT_DAYS_FOR_TREND)


class ChannelQualityAnalyzer:
    """
    Анализирует качество каналов на основе долгосрочной истории (SQLite) с учётом трендов.
    Состояния канала:
        - 'active'   : стабильно здоров (средний скор >= порога)
        - 'inactive' : стабильно болен (средний скор < порога, без признаков оживления)
        - 'recovering' : был болен, но наблюдается положительный тренд (канал оживает)
    """

    def __init__(self):
        self.db = HistoryDB()
        self._whitelist = set(CHANNEL_WHITELIST)
        self._is_first_run = self._check_first_run()

    def _check_first_run(self) -> bool:
        """Проверяет, был ли хотя бы один запуск."""
        last_run = self.db.get_last_run()
        return last_run is None

    def _get_channel_history_scores(self, url: str, days: int = HISTORY_DAYS) -> List[Dict]:
        """Возвращает историю скоров канала за последние days дней."""
        return self.db.get_channel_history_scores(url, days)

    def _calculate_long_term_score(self, url: str, days: int = HISTORY_DAYS) -> Optional[float]:
        """Вычисляет средний скор за последние days дней."""
        scores = self._get_channel_history_scores(url, days)
        valid_scores = [s['score'] for s in scores if s['score'] > 0]
        if not valid_scores:
            return None
        return sum(valid_scores) / len(valid_scores)

    def _compute_trend(self, scores: List[float]) -> float:
        """
        Вычисляет наклон линейной регрессии по временному ряду скоров.
        Положительное значение -> рост, отрицательное -> падение.
        """
        if len(scores) < 2:
            return 0.0
        x = np.arange(len(scores))
        y = np.array(scores)
        # Линейная регрессия через polyfit (степень 1)
        coeffs = np.polyfit(x, y, 1)
        slope = coeffs[0]  # наклон
        return slope

    def _get_channel_state(self, url: str) -> str:
        """
        Определяет состояние канала на основе истории и тренда.
        Возвращает 'active', 'inactive' или 'recovering'.
        """
        if url in self._whitelist:
            return 'active'

        if self._is_first_run:
            logger.info(f"First run: assuming all channels active, including {url}")
            return 'active'

        # Получаем все scores за последние HISTORY_DAYS дней
        history = self._get_channel_history_scores(url, days=HISTORY_DAYS)
        if not history:
            # Нет данных -> считаем неактивным
            return 'inactive'

        # Отфильтруем только те записи, где score > 0 (были конфиги)
        valid_entries = [h for h in history if h['score'] > 0]
        if not valid_entries:
            return 'inactive'

        scores = [h['score'] for h in valid_entries]
        avg_score = sum(scores) / len(scores)

        # Определяем, здоров ли канал по среднему скору
        is_healthy = avg_score >= HEALTH_THRESHOLD

        # Если здоров, то активен
        if is_healthy:
            return 'active'

        # Если не здоров, проверяем тренд за последние MIN_RECENT_DAYS_FOR_TREND дней
        # Берём последние N записей (N = MIN_RECENT_DAYS_FOR_TREND, но не более имеющихся)
        recent_count = min(MIN_RECENT_DAYS_FOR_TREND, len(scores))
        if recent_count < 2:
            return 'inactive'  # недостаточно данных для тренда

        recent_scores = scores[-recent_count:]
        slope = self._compute_trend(recent_scores)

        # Если наклон положительный и превышает порог (относительно среднего скора)
        # Например, если средний скор = 20, а наклон > 0.1*20 = 2, то считаем восстанавливающимся
        threshold = RECOVERING_TREND_THRESHOLD * avg_score
        if slope > threshold:
            logger.debug(f"Channel {url} has positive trend (slope={slope:.2f}) -> recovering")
            return 'recovering'
        else:
            return 'inactive'

    def is_channel_healthy(self, channel_url: str) -> bool:
        """Проверяет, здоров ли канал (активен или восстанавливается)."""
        state = self._get_channel_state(channel_url)
        return state in ('active', 'recovering')

    def get_channel_state(self, channel_url: str) -> str:
        """Возвращает текущее состояние канала."""
        return self._get_channel_state(channel_url)

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        """Возвращает список каналов, которые находятся в состоянии 'inactive'."""
        unhealthy = []
        for url in channel_urls:
            if self._get_channel_state(url) == 'inactive':
                unhealthy.append(url)
        return unhealthy

    def update_health(self, channel_urls: List[str], run_id: int = None):
        """Обновляет данные о здоровье для списка каналов (сохраняет метрики в БД)."""
        # Здесь мы просто вызываем обновление метрик через отдельный метод,
        # который уже используется в pipeline. Этот метод оставлен для интерфейса.
        pass

    def get_health_report(self) -> Dict:
        """Возвращает отчёт о состоянии всех каналов."""
        channels = self.db.get_all_channels()
        states = {'active': 0, 'inactive': 0, 'recovering': 0}
        total = len(channels)
        for ch in channels:
            state = self._get_channel_state(ch['url'])
            states[state] = states.get(state, 0) + 1
        return {
            'channels': channels,
            'summary': {
                'total': total,
                'active': states.get('active', 0),
                'inactive': states.get('inactive', 0),
                'recovering': states.get('recovering', 0)
            }
        }

    def prune_bad_channels(self, channel_urls: List[str]) -> List[str]:
        """
        Возвращает список каналов, которые следует оставить (удаляет только truly inactive).
        """
        healthy = []
        for url in channel_urls:
            state = self._get_channel_state(url)
            if state == 'inactive':
                logger.info(f"Channel {url} is inactive (score below threshold, no recovery trend), removing.")
            else:
                healthy.append(url)
        return healthy
