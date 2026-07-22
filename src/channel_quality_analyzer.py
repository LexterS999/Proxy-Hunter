# ============================================================================
# Файл: src/channel_quality_analyzer.py (обновлён)
# ============================================================================
"""
Интеллектуальный анализатор качества каналов с использованием SQLite и долгосрочной истории.
Оценивает каналы на основе метрик за последние N дней (по умолчанию 7) и отслеживает
динамику, позволяя каналам восстанавливаться после периодов неактивности.
Добавлены: карантин (grace period), взвешенное скользящее среднее, адаптивный порог.
"""

import logging
import numpy as np
from datetime import datetime, timedelta
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
    CHANNEL_MIN_RECENT_DAYS_FOR_TREND,
    GRACE_PERIOD_RUNS,
    ADAPTIVE_THRESHOLD_PERCENTILE,
    MIN_RECORDS_FOR_ADAPTIVE
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
        self.db = get_db()
        self._whitelist = set(CHANNEL_WHITELIST)
        self._is_first_run = self._check_first_run()
        self._grace_period_runs = GRACE_PERIOD_RUNS
        self._adaptive_percentile = ADAPTIVE_THRESHOLD_PERCENTILE
        self._min_records = MIN_RECORDS_FOR_ADAPTIVE

    def _check_first_run(self) -> bool:
        """Проверяет, был ли хотя бы один запуск."""
        last_run = self.db.get_last_run()
        return last_run is None

    def _get_channel_history_scores(self, url: str, days: int = HISTORY_DAYS) -> List[Dict]:
        """Возвращает историю скоров канала за последние days дней."""
        return self.db.get_channel_history_scores(url, days)

    # ===== ИЗМЕНЕНО: взвешенное среднее вместо простого среднего =====
    def _calculate_weighted_score(self, scores: List[float]) -> float:
        """Вычисляет экспоненциально взвешенное среднее (новые записи имеют больший вес)."""
        if not scores:
            return 0.0
        if len(scores) == 1:
            return scores[0]
        # Веса: более новые записи имеют больший вес
        n = len(scores)
        weights = np.exp(np.arange(n) / 3.0)  # экспоненциальный рост
        weights = weights / np.sum(weights)   # нормализация
        return np.average(scores, weights=weights)

    def _calculate_adaptive_threshold(self, all_scores: List[float]) -> float:
        """
        Вычисляет адаптивный порог как нижний перцентиль от всех скоров.
        Если данных мало, возвращает HEALTH_THRESHOLD.
        """
        if len(all_scores) < self._min_records:
            return HEALTH_THRESHOLD
        # Берём нижний перцентиль (например, 20-й)
        percentile = np.percentile(all_scores, self._adaptive_percentile)
        # Не ниже абсолютного минимума
        return max(10.0, percentile)

    def _get_channel_state(self, url: str, all_scores: List[float] = None) -> str:
        """
        Определяет состояние канала на основе истории, тренда и карантина.
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

        # Взвешенное среднее (новые записи важнее)
        avg_score = self._calculate_weighted_score(scores)

        # Адаптивный порог, если передан список всех скоров
        if all_scores is not None:
            threshold = self._calculate_adaptive_threshold(all_scores)
        else:
            threshold = HEALTH_THRESHOLD

        # Определяем, здоров ли канал по взвешенному скору
        is_healthy = avg_score >= threshold

        # Если здоров, то активен
        if is_healthy:
            return 'active'

        # Если не здоров, проверяем карантин
        # Получаем состояние карантина из БД
        grace_state = self.db.get_channel_grace_state(url)
        if grace_state is None:
            # Нет записи -> создаём с полным grace
            self.db.init_channel_grace_state(url, self._grace_period_runs)
            grace_remaining = self._grace_period_runs
            last_bad_run = None
        else:
            grace_remaining = grace_state.get('grace_remaining', 0)
            last_bad_run = grace_state.get('last_bad_run')

        # Если grace_remaining > 0, канал в карантине (recovering)
        if grace_remaining > 0:
            # Уменьшаем grace при каждом плохом запуске
            self.db.decrement_channel_grace(url)
            logger.debug(f"Channel {url} has {grace_remaining-1} grace runs left")
            return 'recovering'

        # Если grace исчерпан, проверяем тренд за последние MIN_RECENT_DAYS_FOR_TREND дней
        recent_count = min(MIN_RECENT_DAYS_FOR_TREND, len(scores))
        if recent_count < 2:
            return 'inactive'

        recent_scores = scores[-recent_count:]
        slope = self._compute_trend(recent_scores)

        # Если наклон положительный и превышает порог (относительно среднего скора)
        threshold_trend = RECOVERING_TREND_THRESHOLD * avg_score
        if slope > threshold_trend:
            logger.debug(f"Channel {url} has positive trend (slope={slope:.2f}) -> recovering")
            # Сбрасываем grace при положительном тренде
            self.db.reset_channel_grace(url, self._grace_period_runs)
            return 'recovering'
        else:
            return 'inactive'

    def _compute_trend(self, scores: List[float]) -> float:
        """
        Вычисляет наклон линейной регрессии по временному ряду скоров.
        Положительное значение -> рост, отрицательное -> падение.
        """
        if len(scores) < 2:
            return 0.0
        x = np.arange(len(scores))
        y = np.array(scores)
        coeffs = np.polyfit(x, y, 1)
        slope = coeffs[0]
        return slope

    def is_channel_healthy(self, channel_url: str) -> bool:
        """Проверяет, здоров ли канал (активен или восстанавливается)."""
        state = self._get_channel_state(channel_url)
        # Дополнительно: проверяем, что канал дал хотя бы один конфиг в последнем запуске
        if state == 'active':
            last_run = self.db.get_last_run()
            if last_run:
                # Проверяем, есть ли записи для этого канала в последнем запуске
                # (упрощённо: смотрим channel_history)
                history = self.db.get_channel_history(channel_url, limit=1)
                if history and history[0].get('total_configs', 0) > 0:
                    return True
                else:
                    return False
            return True
        return state in ('active', 'recovering')

    def get_channel_state(self, channel_url: str) -> str:
        """Возвращает текущее состояние канала."""
        # Собираем все scores для адаптивного порога (опционально)
        all_scores = []
        for ch in self.db.get_all_channels():
            scores = self.db.get_channel_history_scores(ch['url'], days=HISTORY_DAYS)
            for s in scores:
                if s['score'] > 0:
                    all_scores.append(s['score'])
        return self._get_channel_state(channel_url, all_scores)

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        """Возвращает список каналов, которые находятся в состоянии 'inactive'."""
        unhealthy = []
        for url in channel_urls:
            if self._get_channel_state(url) == 'inactive':
                unhealthy.append(url)
        return unhealthy

    def update_health(self, channel_urls: List[str], run_id: int = None):
        """Обновляет метрики каналов в БД на основе текущих данных из config.SOURCE_URLS."""
        try:
            from config import ProxyConfig
            config = ProxyConfig()
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
                    self.db.update_channel(ch.url, metrics, enabled=ch.enabled)
                    if run_id is not None:
                        self.db.add_channel_history(ch.url, run_id, metrics)
            logger.info(f"Channel health updated for {len(channel_urls)} channels.")
        except Exception as e:
            logger.error(f"Failed to update channel health: {e}")

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
