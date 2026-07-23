"""
Анализатор качества каналов с пакетной загрузкой истории.

Ключевые исправления:
- Новые каналы из custom_channels.txt по умолчанию активны
- Уменьшен grace_period_runs для быстрого восстановления каналов
- Улучшена логика определения состояния канала
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import numpy as np

from db import get_db

logger = logging.getLogger(__name__)

# Загружаем настройки безопасно, чтобы избежать циклических импортов
try:
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
        MIN_RECORDS_FOR_ADAPTIVE,
        SOURCE_URLS,
    )
except ImportError:
    # Фоллбек на дефолтные значения
    CHANNEL_HEALTH_THRESHOLD = 30.0
    CHANNEL_MIN_CONFIGS = 1
    CHANNEL_MIN_VALID_RATIO = 0.01
    CHANNEL_MIN_PROTOCOLS = 1
    CHANNEL_HISTORY_DAYS = 7
    CHANNEL_WHITELIST = []
    CHANNEL_RECOVERING_TREND_THRESHOLD = 0.1
    CHANNEL_MIN_RECENT_DAYS_FOR_TREND = 2
    GRACE_PERIOD_RUNS = 3
    ADAPTIVE_THRESHOLD_PERCENTILE = 20
    MIN_RECORDS_FOR_ADAPTIVE = 10
    SOURCE_URLS = []

# Настраиваем параметры с учётом дефолтных значений
HEALTH_THRESHOLD = max(10.0, CHANNEL_HEALTH_THRESHOLD)  # Уменьшаем порог, чтобы больше каналов было активными
MIN_CONFIGS = max(1, CHANNEL_MIN_CONFIGS)
MIN_VALID_RATIO = max(0.01, CHANNEL_MIN_VALID_RATIO)  # Уменьшаем минимальную долю валидных конфигов
MIN_PROTOCOLS = max(1, CHANNEL_MIN_PROTOCOLS)
HISTORY_DAYS = max(7, CHANNEL_HISTORY_DAYS)
RECOVERING_TREND_THRESHOLD = max(0.01, CHANNEL_RECOVERING_TREND_THRESHOLD)
MIN_RECENT_DAYS_FOR_TREND = max(1, CHANNEL_MIN_RECENT_DAYS_FOR_TREND)


class ChannelQualityAnalyzer:
    """Анализатор качества каналов."""
    
    def __init__(self):
        self.db = get_db()
        self._whitelist = set(CHANNEL_WHITELIST)
        self._is_first_run = self._check_first_run()
        self._grace_period_runs = GRACE_PERIOD_RUNS
        self._adaptive_percentile = ADAPTIVE_THRESHOLD_PERCENTILE
        self._min_records = MIN_RECORDS_FOR_ADAPTIVE

        self._history_cache: Dict[str, List[Dict]] = {}
        self._grace_cache: Dict[str, Dict] = {}
        self._all_scores_cache: List[float] = []
        self._adaptive_threshold_cache: Optional[float] = None
        self._last_refresh: Optional[datetime] = None
        self._state_cache: Dict[str, str] = {}
        self._mutated_urls: set = set()
        
        # При первом запуске или если много неактивных каналов, сбрасываем кэш
        if self._is_first_run or self._has_too_many_inactive_channels():
            self._reset_grace_for_all_channels()

    def _check_first_run(self) -> bool:
        """Проверяет, первый ли это запуск."""
        return self.db.get_last_run() is None

    def _has_too_many_inactive_channels(self) -> bool:
        """Проверяет, есть ли слишком много неактивных каналов."""
        try:
            channels = self.db.get_all_channels()
            if not channels:
                return False
            inactive_count = sum(1 for ch in channels if not ch.get('enabled', True))
            return inactive_count > len(channels) * 0.9  # Если больше 90% каналов неактивны
        except Exception:
            return False

    def _reset_grace_for_all_channels(self) -> None:
        """Сбрасывает grace_period для всех каналов (даёт им шанс)."""
        try:
            channels = self.db.get_all_channels()
            for ch in channels:
                url = ch.get('url', '')
                if url:
                    self.db.reset_channel_grace(url, self._grace_period_runs)
                    self._grace_cache[url] = {'grace_remaining': self._grace_period_runs, 'last_bad_run': None}
            logger.info(f"Reset grace period for {len(channels)} channels")
        except Exception as e:
            logger.error(f"Failed to reset grace periods: {e}")

    def _refresh_cache_if_needed(self) -> None:
        """Обновляет кэш, если это необходимо."""
        now = datetime.now()
        if self._last_refresh and (now - self._last_refresh).total_seconds() < 60:
            return

        self._last_refresh = now
        self._history_cache = {}
        self._grace_cache = {}
        self._all_scores_cache = []
        self._adaptive_threshold_cache = None
        self._state_cache = {}
        self._mutated_urls = set()

        # Загружаем историю только для каналов из SOURCE_URLS
        try:
            for record in self._get_all_channel_history(days=HISTORY_DAYS):
                url = record['url']
                if url in SOURCE_URLS or any(url.endswith(ch.strip('/')) for ch in SOURCE_URLS):
                    if record.get('overall_score', 0) > 0:
                        self._history_cache.setdefault(url, []).append({
                            'timestamp': record['timestamp'],
                            'score': record['overall_score'],
                        })
                        self._all_scores_cache.append(record['overall_score'])
        except Exception as e:
            logger.error(f"Failed to load channel history: {e}")

        try:
            for g in self._get_all_channel_grace():
                self._grace_cache[g['url']] = {
                    'grace_remaining': g.get('grace_remaining', self._grace_period_runs),
                    'last_bad_run': g.get('last_bad_run'),
                }
        except Exception as e:
            logger.error(f"Failed to load channel grace: {e}")

        if len(self._all_scores_cache) >= self._min_records:
            adaptive = float(np.percentile(self._all_scores_cache, self._adaptive_percentile))
            self._adaptive_threshold_cache = max(10.0, adaptive)
        else:
            self._adaptive_threshold_cache = HEALTH_THRESHOLD

    def _get_all_channel_history(self, days: int = HISTORY_DAYS) -> List[Dict]:
        """Получает всю историю каналов."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        try:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    '''
                    SELECT url, timestamp, overall_score
                    FROM channel_history
                    WHERE timestamp >= ?
                    ORDER BY timestamp ASC
                    ''',
                    (cutoff,),
                )
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get channel history: {e}")
            return []

    def _get_all_channel_grace(self) -> List[Dict]:
        """Получает все записи о карантине каналов."""
        try:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM channel_grace')
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get channel grace: {e}")
            return []

    def _calculate_weighted_score(self, scores: List[float]) -> float:
        """Вычисляет взвешенный score."""
        if not scores:
            return 0.0
        if len(scores) == 1:
            return float(scores[0])
        n = len(scores)
        weights = np.exp(np.arange(n) / 3.0)
        weights /= np.sum(weights)
        return float(np.average(scores, weights=weights))

    def _compute_trend(self, scores: List[float]) -> float:
        """Вычисляет тренд."""
        if len(scores) < 2:
            return 0.0
        x = np.arange(len(scores))
        y = np.array(scores)
        return float(np.polyfit(x, y, 1)[0])

    def _apply_grace_once(self, url: str, action: str) -> None:
        """Применяет grace один раз для канала."""
        if url in self._mutated_urls:
            return
        if action == 'init':
            self.db.init_channel_grace_state(url, self._grace_period_runs)
            self._grace_cache[url] = {'grace_remaining': self._grace_period_runs, 'last_bad_run': None}
        elif action == 'decrement':
            self.db.decrement_channel_grace(url)
            state = self._grace_cache.setdefault(url, {'grace_remaining': self._grace_period_runs, 'last_bad_run': None})
            state['grace_remaining'] = max(0, int(state.get('grace_remaining', 0)) - 1)
        elif action == 'reset':
            self.db.reset_channel_grace(url, self._grace_period_runs)
            self._grace_cache[url] = {'grace_remaining': self._grace_period_runs, 'last_bad_run': None}
        self._mutated_urls.add(url)

    def _get_channel_state(self, url: str, history: List[Dict], grace_state: Optional[Dict], adaptive_threshold: float) -> str:
        """Определяет состояние канала."""
        if url in self._state_cache:
            return self._state_cache[url]

        # НОВОЕ: Все каналы из SOURCE_URLS по умолчанию активны
        if url in SOURCE_URLS or any(url.endswith(ch.strip('/')) for ch in SOURCE_URLS):
            state = 'active'
            self._state_cache[url] = state
            logger.debug(f"Channel {url} is in SOURCE_URLS, marking as active")
            return state

        # Белый список
        if url in self._whitelist or self._is_first_run:
            state = 'active'
            self._state_cache[url] = state
            return state

        valid_scores = [h['score'] for h in history if h.get('score', 0) > 0]
        if not valid_scores:
            # Если нет истории, но канал в SOURCE_URLS, считаем его активным
            if url in SOURCE_URLS or any(url.endswith(ch.strip('/')) for ch in SOURCE_URLS):
                state = 'active'
                self._state_cache[url] = state
                return state
            state = 'inactive'
            self._state_cache[url] = state
            return state

        avg_score = self._calculate_weighted_score(valid_scores)
        if avg_score >= adaptive_threshold:
            state = 'active'
            self._state_cache[url] = state
            return state

        if grace_state is None:
            self._apply_grace_once(url, 'init')
            state = 'recovering'
            self._state_cache[url] = state
            return state

        grace_remaining = int(grace_state.get('grace_remaining', 0))
        if grace_remaining > 0:
            self._apply_grace_once(url, 'decrement')
            state = 'recovering'
            self._state_cache[url] = state
            return state

        recent_count = min(MIN_RECENT_DAYS_FOR_TREND, len(valid_scores))
        if recent_count < 2:
            state = 'inactive'
            self._state_cache[url] = state
            return state

        recent_scores = valid_scores[-recent_count:]
        slope = self._compute_trend(recent_scores)
        threshold_trend = RECOVERING_TREND_THRESHOLD * max(1.0, avg_score)
        if slope > threshold_trend:
            self._apply_grace_once(url, 'reset')
            state = 'recovering'
        else:
            state = 'inactive'
        self._state_cache[url] = state
        return state

    def get_all_channel_states(self, channel_urls: List[str]) -> Dict[str, str]:
        """Получает состояния всех каналов."""
        self._refresh_cache_if_needed()
        adaptive_threshold = self._adaptive_threshold_cache or HEALTH_THRESHOLD
        result = {}
        for url in channel_urls:
            result[url] = self._get_channel_state(
                url,
                self._history_cache.get(url, []),
                self._grace_cache.get(url),
                adaptive_threshold,
            )
        return result

    def get_channel_state(self, channel_url: str) -> str:
        """Получает состояние канала."""
        return self.get_all_channel_states([channel_url]).get(channel_url, 'active')

    def is_channel_healthy(self, channel_url: str) -> bool:
        """Проверяет, здоров ли канал."""
        return self.get_channel_state(channel_url) in ('active', 'recovering')

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        """Получает список нездоровых каналов."""
        states = self.get_all_channel_states(channel_urls)
        return [url for url, state in states.items() if state == 'inactive']

    def update_health(self, channel_urls: List[str], run_id: int = None):
        """Обновляет состояние здоровья каналов."""
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
                        'protocol_counts': m.protocol_counts or {},
                    }
                    self.db.update_channel(ch.url, metrics, enabled=ch.enabled)
                    if run_id is not None:
                        self.db.add_channel_history(ch.url, run_id, metrics)
            logger.info("Channel health updated for %s channels.", len(channel_urls))
        except Exception as e:
            logger.error("Failed to update channel health: %s", e)

    def get_health_report(self) -> Dict:
        """Возвращает отчёт о здоровье каналов."""
        channels = self.db.get_all_channels()
        urls = [ch['url'] for ch in channels]
        states = self.get_all_channel_states(urls)
        summary = {'active': 0, 'inactive': 0, 'recovering': 0}
        for state in states.values():
            summary[state] = summary.get(state, 0) + 1
        return {
            'channels': channels,
            'summary': {
                'total': len(channels),
                'active': summary.get('active', 0),
                'inactive': summary.get('inactive', 0),
                'recovering': summary.get('recovering', 0),
            },
        }

    def prune_bad_channels(self, channel_urls: List[str]) -> List[str]:
        """Удаляет плохие каналы."""
        states = self.get_all_channel_states(channel_urls)
        healthy = []
        for url in channel_urls:
            state = states.get(url, 'active')  # По умолчанию active
            if state == 'inactive':
                logger.info("Channel %s is inactive, removing.", url)
            else:
                healthy.append(url)
        return healthy
