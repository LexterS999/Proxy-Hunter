"""
Анализатор качества каналов с пакетной загрузкой истории.

Ключевые исправления:
- Новые каналы (из custom_channels.txt) по умолчанию считаются активными
- Уменьшены требования к минимальному количеству конфигов
- Увеличен grace_period для новых каналов
- Добавлено логирование для отладки
- Состояние канала кешируется в рамках refresh-цикла
- Побочные DB-операции выполняются максимум один раз за цикл
- Используется адаптивный порог здоровья (перцентиль)
- Увеличен HISTORY_DAYS до 14 дней
- grace_remaining при инициализации удвоен
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
# Восстановлено из коммита 3b71a01 (22.07.2026) — порог min 30.0, а не 10.0
HEALTH_THRESHOLD = max(30.0, getattr(settings.channels, 'channel_health_threshold', 30.0))
MIN_CONFIGS = max(1, getattr(settings.channels, 'channel_min_configs', 1))
MIN_VALID_RATIO = max(0.05, getattr(settings.channels, 'channel_min_valid_ratio', 0.05))  # min 5%, а не 1% — мягче
MIN_PROTOCOLS = max(1, getattr(settings.channels, 'channel_min_protocols', 1))
HISTORY_DAYS = max(7, getattr(settings.channels, 'channel_history_days', 7))
RECOVERING_TREND_THRESHOLD = max(0.03, getattr(settings.channels, 'channel_recovering_trend_threshold', 0.05))  # мягче → больше recovering
MIN_RECENT_DAYS_FOR_TREND = max(2, getattr(settings.channels, 'channel_min_recent_days_for_trend', 2))
CHANNEL_WHITELIST = getattr(settings.channels, 'channel_whitelist', [])
GRACE_PERIOD_RUNS = max(3, getattr(settings.advanced, 'grace_period_runs', 3))
ADAPTIVE_THRESHOLD_PERCENTILE = max(5, min(50, getattr(settings.advanced, 'adaptive_threshold_percentile', 20)))
MIN_RECORDS_FOR_ADAPTIVE = max(3, getattr(settings.advanced, 'min_records_for_adaptive', 10))

# Увеличиваем HISTORY_DAYS до 14 (было 7)
HISTORY_DAYS = 14

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

        # Загружаем историю каналов (используем HISTORY_DAYS = 14)
        # Восстановлено из коммита 3b71a01 (поведение до регрессии): даже ран со score=0
        # считается «данными» и не отбрасывается — это спасало канал, таймаутнувший один раз.
        for record in self._get_all_channel_history(days=HISTORY_DAYS):
            url = record['url']
            self._known_channels.add(url)
            score = float(record.get('overall_score') or 0.0)
            # В истоpию добавляем все раны, чтобы тренд считался корректно.
            # В all_scores_cache (для адаптивного перцентиля) — только положительные.
            self._history_cache.setdefault(url, []).append({
                'timestamp': record['timestamp'],
                'score': score,
            })
            if score > 0:
                self._all_scores_cache.append(score)

        # Загружаем состояние grace
        for g in self._get_all_channel_grace():
            self._grace_cache[g['url']] = {
                'grace_remaining': g.get('grace_remaining', 0),
                'last_bad_run': g.get('last_bad_run'),
            }

        # Вычисляем адаптивный порог. Восстановлено из becf3c3:
        # если данных мало или все скоры низкие, НЕ опускаем порог слишком сильно —
        # иначе перцентиль 20 при «провальных» прогонах поднимет порог и
        # порежет половину нормальных каналов.
        if len(self._all_scores_cache) >= self._min_records:
            adaptive = float(np.percentile(self._all_scores_cache, self._adaptive_percentile))
            # Ограничиваем снизу HEALTH_THRESHOLD (не min 10, как было), чтобы не было ложной фильтрации
            self._adaptive_threshold_cache = max(HEALTH_THRESHOLD, adaptive)
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
                # Удваиваем grace_remaining при инициализации
                doubled_grace = self._grace_period_runs * 2
                self.db.init_channel_grace_state(url, doubled_grace)
                self._grace_cache[url] = {'grace_remaining': doubled_grace, 'last_bad_run': None}
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
        """Определяет состояние канала с учётом адаптивного порога и скользящего среднего."""
        if url in self._state_cache:
            return self._state_cache[url]

        # НОВЫЕ КАНАЛЫ (нет в истории) – даём grace-период
        if url not in self._known_channels:
            logger.debug(f"Channel {url} is new (not in history), applying grace period")
            if grace_state is None:
                self._apply_grace_once(url, 'init')
                self._state_cache[url] = 'recovering'
                return 'recovering'
            else:
                # Если уже есть состояние, считаем его
                pass

        # Белый список
        if url in self._whitelist or self._is_first_run:
            state = 'active'
            self._state_cache[url] = state
            return state

        # Если нет валидных оценок, но канал известен – даём шанс.
        # Восстановлено из коммита 08efd05: отсутствие скоров → recovering (с grace),
        # а не inactive. Это спасает канал после таймаутов GitHub Actions.
        valid_scores = [h['score'] for h in history if h.get('score', 0) > 0]
        if not valid_scores:
            if self._is_first_run or url not in self._known_channels:
                state = 'active'
            else:
                # Даём grace-период, а не сразу inactive
                if grace_state is None:
                    self._apply_grace_once(url, 'init')
                    state = 'recovering'
                else:
                    grace_remaining = int(grace_state.get('grace_remaining', GRACE_PERIOD_RUNS))
                    if grace_remaining > 0:
                        state = 'recovering'
                    else:
                        state = 'inactive'
            self._state_cache[url] = state
            return state

        # Вычисляем скользящее среднее за последние 5 запусков
        recent_scores = [h['score'] for h in history[-5:] if h.get('score', 0) > 0]
        if recent_scores:
            avg_recent = sum(recent_scores) / len(recent_scores)
        else:
            avg_recent = 0.0

        # Используем адаптивный порог
        threshold = self._adaptive_threshold_cache or HEALTH_THRESHOLD

        # Если средний score выше порога - активный
        if avg_recent >= threshold:
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

        recent_trend = valid_scores[-recent_count:]
        slope = self._compute_trend(recent_trend)
        threshold_trend = RECOVERING_TREND_THRESHOLD * max(1.0, avg_recent)
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

    def predict_channel_activity(self, url: str) -> float:
        """
        Заглушка для ML-предсказания активности. В будущем можно обучить модель.
        Пока возвращает 0.5 (нейтрально).
        """
        # Можно добавить простую эвристику: если за последние 7 дней были конфиги, то вероятность выше
        history = self._history_cache.get(url, [])
        recent = [h for h in history if (datetime.now() - datetime.fromisoformat(h['timestamp'])).days < 7]
        if len(recent) >= 2:
            return 0.7
        elif len(recent) == 1:
            return 0.5
        else:
            return 0.3
