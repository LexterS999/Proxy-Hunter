"""
Анализатор качества каналов с пакетной загрузкой истории.

Ключевые исправления:
- Новые каналы (из custom_channels.txt) по умолчанию считаются активными
- Уменьшены требования к минимальному количеству конфигов
- Увеличен grace_period для новых каналов
- Добавлено логирование для отладки
- Состояние канала кешируется в рамках refresh-цикла
- Побочные DB-операции выполняются максимум один раз за цикл
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

import numpy as np

# Импортируем настройки безопасно, чтобы избежать циклических импортов
_settings = None

def get_settings_safe():
    """Безопасная загрузка настроек."""
    global _settings
    if _settings is None:
        try:
            from user_settings import get_settings
            _settings = get_settings()
        except ImportError:
            # Фоллбек на дефолтные значения
            _settings = type('Settings', (), {
                'channels': type('Channels', (), {
                    'channel_health_threshold': 30.0,
                    'channel_min_configs': 1,
                    'channel_min_valid_ratio': 0.01,
                    'channel_min_protocols': 1,
                    'channel_history_days': 7,
                    'channel_whitelist': [],
                    'channel_recovering_trend_threshold': 0.1,
                    'channel_min_recent_days_for_trend': 2,
                })(),
                'advanced': type('Advanced', (), {
                    'grace_period_runs': 3,
                    'adaptive_threshold_percentile': 20,
                    'min_records_for_adaptive': 10,
                })(),
            })()
    return _settings

logger = logging.getLogger(__name__)

# Получаем настройки
settings = get_settings_safe()

# Используем настройки с дефолтными значениями для избежания ошибок
HEALTH_THRESHOLD = max(10.0, getattr(settings.channels, 'channel_health_threshold', 30.0))
MIN_CONFIGS = max(1, getattr(settings.channels, 'channel_min_configs', 1))
MIN_VALID_RATIO = max(0.01, getattr(settings.channels, 'channel_min_valid_ratio', 0.05))
MIN_PROTOCOLS = max(1, getattr(settings.channels, 'channel_min_protocols', 1))
HISTORY_DAYS = max(7, getattr(settings.channels, 'channel_history_days', 7))
RECOVERING_TREND_THRESHOLD = max(0.05, getattr(settings.channels, 'channel_recovering_trend_threshold', 0.1))
MIN_RECENT_DAYS_FOR_TREND = max(2, getattr(settings.channels, 'channel_min_recent_days_for_trend', 2))
CHANNEL_WHITELIST = getattr(settings.channels, 'channel_whitelist', [])
GRACE_PERIOD_RUNS = max(3, getattr(settings.advanced, 'grace_period_runs', 3))
ADAPTIVE_THRESHOLD_PERCENTILE = max(5, min(50, getattr(settings.advanced, 'adaptive_threshold_percentile', 20)))
MIN_RECORDS_FOR_ADAPTIVE = max(3, getattr(settings.advanced, 'min_records_for_adaptive', 10))

# Импортируем БД безопасно
_db = None

def get_db_safe():
    """Безопасная загрузка БД."""
    global _db
    if _db is None:
        try:
            from db import get_db
            _db = get_db()
        except ImportError as e:
            logger.warning(f"Failed to import db: {e}")
            # Создаём заглушку для БД
            class _FakeDB:
                def _get_connection(self):
                    import sqlite3
                    return sqlite3.connect(':memory:')
                def get_last_run(self):
                    return None
                def get_all_channels(self):
                    return []
            _db = _FakeDB()
    return _db


class ChannelQualityAnalyzer:
    """Анализатор качества каналов."""
    
    def __init__(self):
        self.db = get_db_safe()
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
        self._mutated_urls: Set[str] = set()
        self._known_channels: Set[str] = set()  # Canalы, которые мы уже видели

    def _check_first_run(self) -> bool:
        """Проверяет, первый ли это запуск."""
        return self.db.get_last_run() is None

    def _refresh_cache_if_needed(self) -> None:
        """Обновляет кеш, если это необходимо."""
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
        self._known_channels = set()

        # Загружаем историю каналов
        for record in self._get_all_channel_history(days=HISTORY_DAYS):
            url = record['url']
            self._known_channels.add(url)
            if record.get('overall_score', 0) > 0:
                self._history_cache.setdefault(url, []).append({
                    'timestamp': record['timestamp'],
                    'score': record['overall_score'],
                })
                self._all_scores_cache.append(record['overall_score'])

        # Загружаем состояние grace
        for g in self._get_all_channel_grace():
            self._grace_cache[g['url']] = {
                'grace_remaining': g.get('grace_remaining', 0),
                'last_bad_run': g.get('last_bad_run'),
            }

        # Вычисляем адаптивный порог
        if len(self._all_scores_cache) >= self._min_records:
            adaptive = float(np.percentile(self._all_scores_cache, self._adaptive_percentile))
            self._adaptive_threshold_cache = max(10.0, adaptive)
        else:
            self._adaptive_threshold_cache = HEALTH_THRESHOLD

        logger.info(f"ChannelQualityAnalyzer: Loaded history for {len(self._history_cache)} channels, adaptive threshold: {self._adaptive_threshold_cache}")

    def _get_all_channel_history(self, days: int = HISTORY_DAYS) -> List[Dict]:
        """Возвращает всю историю каналов."""
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
        """Возвращает все записи о grace-периодах."""
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
        """Вычисляет тренд (наклон линии регрессии)."""
        if len(scores) < 2:
            return 0.0
        x = np.arange(len(scores))
        y = np.array(scores)
        return float(np.polyfit(x, y, 1)[0])

    def _apply_grace_once(self, url: str, action: str) -> None:
        """Применяет action к grace-периоду канала (только один раз за цикл)."""
        if url in self._mutated_urls:
            return
        try:
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
        except Exception as e:
            logger.error(f"Failed to apply grace action {action} for {url}: {e}")

    def _get_channel_state(self, url: str, history: List[Dict], grace_state: Optional[Dict], adaptive_threshold: float) -> str:
        """Определяет состояние канала."""
        if url in self._state_cache:
            return self._state_cache[url]

        # === НОВЫЕ КАНАЛЫ (нет в истории) считаем активными === 
        if url not in self._known_channels:
            logger.debug(f"Channel {url} is new (not in history), marking as active")
            self._state_cache[url] = 'active'
            return 'active'

        # Белый список
        if url in self._whitelist or self._is_first_run:
            state = 'active'
            self._state_cache[url] = state
            return state

        # Если нет валидных оценок, но канал новый (в известных, но без оценок)
        valid_scores = [h['score'] for h in history if h.get('score', 0) > 0]
        if not valid_scores:
            # Даём шанс новым каналам
            if self._is_first_run:
                state = 'active'
            else:
                state = 'inactive'
            self._state_cache[url] = state
            return state

        avg_score = self._calculate_weighted_score(valid_scores)
        
        # Если средний score выше порога - активный
        if avg_score >= adaptive_threshold:
            state = 'active'
            self._state_cache[url] = state
            return state

        # Если есть grace-период - восстанавливающийся
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

        # Проверяем тренд
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
        """Возвращает состояния всех каналов."""
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
        """Возвращает состояние одного канала."""
        return self.get_all_channel_states([channel_url]).get(channel_url, 'active')

    def is_channel_healthy(self, channel_url: str) -> bool:
        """Проверяет, здоровый ли канал."""
        return self.get_channel_state(channel_url) in ('active', 'recovering')

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        """Возвращает список нездоровых каналов."""
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
        """Удаляет плохие каналы из списка."""
        states = self.get_all_channel_states(channel_urls)
        healthy = []
        for url in channel_urls:
            state = states.get(url, 'active')
            if state == 'inactive':
                logger.debug("Channel %s is inactive, removing.", url)
            else:
                healthy.append(url)
        return healthy

    def reset_channel_states(self, channel_urls: List[str]) -> None:
        """Сбрасывает состояния каналов (для новых каналов)."""
        for url in channel_urls:
            self._state_cache.pop(url, None)
            self._history_cache.pop(url, None)
            self._grace_cache.pop(url, None)
            self._known_channels.discard(url)
        logger.info(f"Reset states for {len(channel_urls)} channels")
