"""
Адаптивные пороги на основе распределения метрик всех каналов.
"""

import logging
import numpy as np
from typing import List, Dict, Optional

from user_settings import ADAPTIVE_THRESHOLDS_ENABLED

logger = logging.getLogger(__name__)


class AdaptiveThresholds:
    """
    Вычисляет пороги на основе распределения данных всех каналов.
    Использует перцентили вместо жёстких значений.
    """

    def __init__(self):
        self.thresholds = {
            'base_health': 25.0,
            'min_configs': 5,
            'min_valid_rate': 0.1,
            'max_volatility': 0.5,
            'trend_threshold': -0.3,
        }
        self._history = []
        self._enabled = ADAPTIVE_THRESHOLDS_ENABLED

    def update(self, all_channels: List[Dict]) -> None:
        """
        Пересчитывает пороги на основе распределения всех каналов.
        Ожидает список словарей с ключами: overall_score, total_configs, valid_configs,
        config_volatility, score_trend.
        """
        if not self._enabled or len(all_channels) < 5:
            logger.debug("Adaptive thresholds disabled or insufficient data")
            return

        # Извлекаем метрики
        scores = [c.get('overall_score', 0) for c in all_channels if c.get('overall_score', 0) > 0]
        configs = [c.get('total_configs', 0) for c in all_channels if c.get('total_configs', 0) > 0]
        valid_rates = []
        volatilities = []
        trends = []

        for c in all_channels:
            total = c.get('total_configs', 0)
            valid = c.get('valid_configs', 0)
            if total > 0:
                valid_rates.append(valid / total)
            if c.get('config_volatility') is not None:
                volatilities.append(c['config_volatility'])
            if c.get('score_trend') is not None:
                trends.append(c['score_trend'])

        # Обновляем пороги, если данных достаточно
        if len(scores) >= 10:
            # Явно приводим к float, чтобы избежать numpy-типов
            self.thresholds['base_health'] = float(max(10.0, np.percentile(scores, 25) * 0.7))

        if len(configs) >= 10:
            self.thresholds['min_configs'] = int(max(2, np.percentile(configs, 10)))

        if len(valid_rates) >= 10:
            self.thresholds['min_valid_rate'] = float(max(0.02, np.percentile(valid_rates, 5)))

        if len(volatilities) >= 10:
            self.thresholds['max_volatility'] = float(min(1.0, np.percentile(volatilities, 90)))

        if len(trends) >= 10:
            self.thresholds['trend_threshold'] = float(np.percentile(trends, 10))

        logger.info(f"Adaptive thresholds updated: {self.thresholds}")

    def get_thresholds(self) -> Dict:
        """Возвращает текущие пороги (все значения — стандартные Python-типы)."""
        return self.thresholds.copy()

    def is_enabled(self) -> bool:
        return self._enabled
