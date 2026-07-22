# ============================================================================
# Файл: src/channel_quality_analyzer.py (ОПТИМИЗИРОВАННАЯ ВЕРСИЯ, ИСПРАВЛЕНА)
# ============================================================================
"""
Интеллектуальный анализатор качества каналов с пакетной обработкой данных.
Оценивает каналы на основе долгосрочной истории (SQLite) с учётом трендов.
Состояния канала:
    - 'active'   : стабильно здоров (средний скор >= порога)
    - 'inactive' : стабильно болен (средний скор < порога, без признаков оживления)
    - 'recovering' : был болен, но наблюдается положительный тренд (канал оживает)

ОПТИМИЗАЦИИ:
- Пакетная загрузка истории для всех каналов (один SQL-запрос).
- Единый адаптивный порог на основе всех данных.
- Предзагрузка состояния карантина для всех каналов.
"""

import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any

from db import get_db
from user_settings import (
    CHANNEL_HEALTH_THRESHOLD,
    CHANNEL_MIN_CONFIGS,
    CHANNEL_MIN_VALID_RATIO,
    CHANNEL_MIN_PROTOCOLS,
    CHANNEL_HISTORY_DAYS,
    CHANNEL_WHITELIST,          # <-- ИСПРАВЛЕНО: правильное имя переменной
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
    """

    def __init__(self):
        self.db = get_db()
        self._whitelist = set(CHANNEL_WHITELIST)   # <-- ИСПРАВЛЕНО: теперь имя правильное
        self._is_first_run = self._check_first_run()
        self._grace_period_runs = GRACE_PERIOD_RUNS
        self._adaptive_percentile = ADAPTIVE_THRESHOLD_PERCENTILE
        self._min_records = MIN_RECORDS_FOR_ADAPTIVE

        # Кэш для данных (будет заполнен при первом вызове get_all_states)
        self._history_cache: Dict[str, List[Dict]] = {}
        self._grace_cache: Dict[str, Dict] = {}
        self._all_scores_cache: List[float] = []
        self._adaptive_threshold_cache: Optional[float] = None
        self._last_refresh: Optional[datetime] = None

    def _check_first_run(self) -> bool:
        """Проверяет, был ли хотя бы один запуск."""
        last_run = self.db.get_last_run()
        return last_run is None

    def _refresh_cache_if_needed(self) -> None:
        """
        Обновляет кэш данных, если он пуст или устарел (старше 1 минуты).
        """
        now = datetime.now()
        if (self._last_refresh is not None and 
            (now - self._last_refresh).total_seconds() < 60):
            return

        self._last_refresh = now
        self._history_cache = {}
        self._grace_cache = {}
        self._all_scores_cache = []
        self._adaptive_threshold_cache = None

        # 1. Загружаем историю для ВСЕХ каналов одним запросом
        all_history = self._get_all_channel_history(days=HISTORY_DAYS)
        for record in all_history:
            url = record['url']
            if url not in self._history_cache:
                self._history_cache[url] = []
            if record.get('overall_score', 0) > 0:
                self._history_cache[url].append({
                    'timestamp': record['timestamp'],
                    'score': record['overall_score']
                })
                self._all_scores_cache.append(record['overall_score'])

        # 2. Загружаем состояние карантина для ВСЕХ каналов одним запросом
        all_grace = self._get_all_channel_grace()
        for g in all_grace:
            self._grace_cache[g['url']] = {
                'grace_remaining': g.get('grace_remaining', 0),
                'last_bad_run': g.get('last_bad_run')
            }

        # 3. Вычисляем адаптивный порог один раз
        if len(self._all_scores_cache) >= self._min_records:
            self._adaptive_threshold_cache = np.percentile(
                self._all_scores_cache, self._adaptive_percentile
            )
            self._adaptive_threshold_cache = max(10.0, self._adaptive_threshold_cache)
        else:
            self._adaptive_threshold_cache = HEALTH_THRESHOLD

        logger.debug(f"Cache refreshed: {len(self._history_cache)} channels, "
                     f"{len(self._all_scores_cache)} score records, "
                     f"adaptive threshold={self._adaptive_threshold_cache:.2f}")

    def _get_all_channel_history(self, days: int = HISTORY_DAYS) -> List[Dict]:
        """
        Загружает историю для ВСЕХ каналов за последние days дней.
        Возвращает список словарей.
        """
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT url, timestamp, overall_score 
                FROM channel_history
                WHERE timestamp >= ?
                ORDER BY timestamp ASC
            ''', (cutoff,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def _get_all_channel_grace(self) -> List[Dict]:
        """Загружает состояние карантина для ВСЕХ каналов."""
        conn = self.db._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM channel_grace')
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def _calculate_weighted_score(self, scores: List[float]) -> float:
        """Вычисляет экспоненциально взвешенное среднее (новые записи имеют больший вес)."""
        if not scores:
            return 0.0
        if len(scores) == 1:
            return scores[0]
        n = len(scores)
        weights = np.exp(np.arange(n) / 3.0)
        weights = weights / np.sum(weights)
        return np.average(scores, weights=weights)

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
        return coeffs[0]

    def _get_channel_state(
        self, 
        url: str,
        history: List[Dict],
        grace_state: Optional[Dict],
        adaptive_threshold: float
    ) -> str:
        """
        Определяет состояние канала на основе переданной истории и карантина.
        """
        if url in self._whitelist:
            return 'active'

        if self._is_first_run:
            return 'active'

        # Фильтруем только записи с score > 0
        valid_scores = [h['score'] for h in history if h.get('score', 0) > 0]
        if not valid_scores:
            return 'inactive'

        # Взвешенное среднее
        avg_score = self._calculate_weighted_score(valid_scores)
        is_healthy = avg_score >= adaptive_threshold

        if is_healthy:
            return 'active'

        # Проверка карантина
        if grace_state is None:
            # Нет записи -> создаём с полным grace
            self.db.init_channel_grace_state(url, self._grace_period_runs)
            return 'recovering'

        grace_remaining = grace_state.get('grace_remaining', 0)
        if grace_remaining > 0:
            # Уменьшаем grace при каждом плохом запуске
            self.db.decrement_channel_grace(url)
            logger.debug(f"Channel {url} has {grace_remaining-1} grace runs left")
            return 'recovering'

        # Если grace исчерпан, проверяем тренд за последние MIN_RECENT_DAYS_FOR_TREND дней
        recent_count = min(MIN_RECENT_DAYS_FOR_TREND, len(valid_scores))
        if recent_count < 2:
            return 'inactive'

        recent_scores = valid_scores[-recent_count:]
        slope = self._compute_trend(recent_scores)

        threshold_trend = RECOVERING_TREND_THRESHOLD * avg_score
        if slope > threshold_trend:
            logger.debug(f"Channel {url} has positive trend (slope={slope:.2f}) -> recovering")
            self.db.reset_channel_grace(url, self._grace_period_runs)
            return 'recovering'
        else:
            return 'inactive'

    def get_all_channel_states(self, channel_urls: List[str]) -> Dict[str, str]:
        """
        Возвращает состояние для списка каналов.
        Использует пакетную загрузку для максимальной производительности.
        """
        self._refresh_cache_if_needed()
        result = {}
        adaptive_threshold = self._adaptive_threshold_cache or HEALTH_THRESHOLD

        for url in channel_urls:
            history = self._history_cache.get(url, [])
            grace_state = self._grace_cache.get(url)
            state = self._get_channel_state(url, history, grace_state, adaptive_threshold)
            result[url] = state

        return result

    def get_channel_state(self, channel_url: str) -> str:
        """Возвращает состояние одного канала (использует кэш)."""
        # Принудительно обновляем кэш, если он пуст
        if not self._history_cache:
            self._refresh_cache_if_needed()
        return self.get_all_channel_states([channel_url]).get(channel_url, 'inactive')

    def is_channel_healthy(self, channel_url: str) -> bool:
        """Проверяет, здоров ли канал (активен или восстанавливается)."""
        state = self.get_channel_state(channel_url)
        return state in ('active', 'recovering')

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        """Возвращает список каналов, которые находятся в состоянии 'inactive'."""
        states = self.get_all_channel_states(channel_urls)
        return [url for url, state in states.items() if state == 'inactive']

    def update_health(self, channel_urls: List[str], run_id: int = None):
        """Обновляет метрики каналов в БД на основе текущих данных."""
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
        urls = [ch['url'] for ch in channels]
        states = self.get_all_channel_states(urls)

        summary = {'active': 0, 'inactive': 0, 'recovering': 0}
        for url, state in states.items():
            summary[state] = summary.get(state, 0) + 1

        return {
            'channels': channels,
            'summary': {
                'total': len(channels),
                'active': summary.get('active', 0),
                'inactive': summary.get('inactive', 0),
                'recovering': summary.get('recovering', 0)
            }
        }

    def prune_bad_channels(self, channel_urls: List[str]) -> List[str]:
        """
        Возвращает список каналов, которые следует оставить (удаляет только truly inactive).
        """
        states = self.get_all_channel_states(channel_urls)
        healthy = []
        for url in channel_urls:
            state = states.get(url, 'inactive')
            if state == 'inactive':
                logger.info(f"Channel {url} is inactive (score below threshold, no recovery trend), removing.")
            else:
                healthy.append(url)
        return healthy
