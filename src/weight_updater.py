"""
Модуль для периодического обновления региональных весов на основе накопленной статистики.
"""

import logging
import json
import os
from typing import Dict, Optional
from regional_stats import RegionalStats
from regional_scorer import RegionalScorer

logger = logging.getLogger(__name__)

class WeightUpdater:
    def __init__(self, region: str = 'RU', stats_file: str = 'configs/regional_stats.json'):
        self.region = region
        self.stats = RegionalStats(stats_file)
        self.scorer = RegionalScorer(region)
        self.weights_file = 'configs/regional_weights.json'

    def update(self) -> bool:
        """
        Обновляет веса для заданного региона на основе статистики и сохраняет их в файл.
        Возвращает True, если обновление выполнено.
        """
        # Агрегируем статистику
        self.stats._aggregate()
        # Обновляем веса в scorer
        self.stats.update_weights(self.region, self.scorer)
        # Сохраняем обновлённые веса в файл
        try:
            os.makedirs(os.path.dirname(self.weights_file), exist_ok=True)
            with open(self.weights_file, 'w') as f:
                json.dump(self.scorer.REGIONAL_BONUS, f, indent=2)
            logger.info(f"Weights for region {self.region} saved to {self.weights_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save weights: {e}")
            return False

    def load_and_apply(self):
        """
        Загружает веса из файла и применяет их к scorer.
        """
        try:
            with open(self.weights_file, 'r') as f:
                weights = json.load(f)
            self.scorer.reload_weights(weights)
            logger.info(f"Weights for region {self.region} loaded and applied.")
        except Exception as e:
            logger.warning(f"Could not load weights: {e}")

    def periodic_update(self, interval_hours: int = 24):
        """
        Запускает периодическое обновление весов (может быть вызвано из cron или отдельного потока).
        """
        import time
        while True:
            self.update()
            time.sleep(interval_hours * 3600)
