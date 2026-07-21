"""
Сбор и анализ статистики локальных проверок для корректировки региональных весов.
"""

import json
import os
import logging
from typing import Dict, List, Optional
from collections import defaultdict
import time

logger = logging.getLogger(__name__)

class RegionalStats:
    def __init__(self, stats_file: str = 'configs/regional_stats.json'):
        self.stats_file = stats_file
        self.stats = self._load_stats()

    def _load_stats(self) -> Dict:
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_stats(self):
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)

    def record_local_check(self, config: str, success: bool, latency: float, region: str = 'RU'):
        """
        Записывает результат локальной проверки.
        """
        key = f"{region}:{config[:50]}"  # упрощённо
        if key not in self.stats:
            self.stats[key] = {'successes': 0, 'fails': 0, 'latencies': [], 'last_seen': 0}
        self.stats[key]['successes'] += 1 if success else 0
        self.stats[key]['fails'] += 0 if success else 1
        if latency > 0:
            self.stats[key]['latencies'].append(latency)
        self.stats[key]['last_seen'] = time.time()
        self._save_stats()

    def get_stats_for_config(self, config: str, region: str = 'RU') -> Optional[Dict]:
        key = f"{region}:{config[:50]}"
        return self.stats.get(key)

    def compute_adjustment(self, config: str, region: str = 'RU') -> float:
        """
        Вычисляет корректирующий множитель на основе истории проверок.
        """
        stats = self.get_stats_for_config(config, region)
        if not stats:
            return 1.0
        total = stats['successes'] + stats['fails']
        if total == 0:
            return 1.0
        success_rate = stats['successes'] / total
        # Если успешность выше 70% — бонус, ниже 30% — штраф
        if success_rate > 0.7:
            return 1.2
        elif success_rate < 0.3:
            return 0.7
        else:
            return 1.0

    def get_region_adjustments(self, region: str = 'RU') -> Dict:
        """
        Возвращает словарь корректировок для всех конфигов в регионе.
        """
        adjustments = {}
        for key, stats in self.stats.items():
            if key.startswith(f"{region}:"):
                config_key = key.split(':', 1)[1]
                adjustments[config_key] = self.compute_adjustment(config_key, region)
        return adjustments
