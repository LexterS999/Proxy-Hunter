"""
Интеллектуальный анализатор качества каналов.
Оценивает каналы по множеству метрик и принимает решение об их отключении,
если они не приносят полезных конфигураций.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque
import statistics

from user_settings import (
    CHANNEL_HEALTH_THRESHOLD,
    CHANNEL_MIN_CONFIGS,
    CHANNEL_MIN_VALID_RATIO,
    CHANNEL_MIN_PROTOCOLS,
    CHANNEL_HISTORY_DAYS,
    CHANNEL_WHITELIST
)

logger = logging.getLogger(__name__)

# Константы по умолчанию, если не заданы в user_settings
DEFAULT_HEALTH_THRESHOLD = 25.0
DEFAULT_MIN_CONFIGS = 5
DEFAULT_MIN_VALID_RATIO = 0.1
DEFAULT_MIN_PROTOCOLS = 1
DEFAULT_HISTORY_DAYS = 7

class ChannelQualityAnalyzer:
    """
    Анализирует качество каналов на основе истории их работы.
    """

    def __init__(self, history_file: str = 'configs/channel_stats.json',
                 health_file: str = 'configs/channel_health.json'):
        self.history_file = history_file
        self.health_file = health_file
        self.history = self._load_history()
        self.health_data = self._load_health()
        self._whitelist = set(CHANNEL_WHITELIST)
        self._is_first_run = not self.history.get('channels')

    def _load_history(self) -> Dict:
        """Загружает историю каналов из channel_stats.json."""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data
            except Exception as e:
                logger.warning(f"Failed to load channel history: {e}")
        return {}

    def _load_health(self) -> Dict:
        """Загружает сохранённые данные о здоровье каналов."""
        if os.path.exists(self.health_file):
            try:
                with open(self.health_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'channels' not in data:
                        data['channels'] = {}
                    if 'last_updated' not in data:
                        data['last_updated'] = datetime.now().isoformat()
                    return data
            except Exception as e:
                logger.warning(f"Failed to load health data: {e}")
        return {'channels': {}, 'last_updated': datetime.now().isoformat()}

    def _save_health(self):
        """Сохраняет данные о здоровье каналов."""
        self.health_data['last_updated'] = datetime.now().isoformat()
        try:
            os.makedirs(os.path.dirname(self.health_file), exist_ok=True)
            with open(self.health_file, 'w', encoding='utf-8') as f:
                json.dump(self.health_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save health data: {e}")

    def _get_channel_metrics(self, channel_url: str) -> Dict:
        """Извлекает метрики канала из истории."""
        channels = self.history.get('channels', [])
        for ch in channels:
            if ch.get('url') == channel_url:
                return ch.get('metrics', {})
        return {}

    def _get_channel_history(self, channel_url: str) -> List[Dict]:
        metrics = self._get_channel_metrics(channel_url)
        if metrics:
            return [metrics]
        return []

    def calculate_health_score(self, channel_url: str) -> float:
        if channel_url in self._whitelist:
            return 100.0

        metrics = self._get_channel_metrics(channel_url)
        if not metrics:
            logger.debug(f"No metrics for {channel_url}, assuming healthy (first run)")
            return 50.0

        total = metrics.get('total_configs', 0)
        valid = metrics.get('valid_configs', 0)
        overall_score = metrics.get('overall_score', 0)
        last_success = metrics.get('last_success')
        protocol_counts = metrics.get('protocol_counts', {})
        unique_protocols = len([p for p, c in protocol_counts.items() if c > 0])

        score = 0.0

        min_configs = CHANNEL_MIN_CONFIGS
        config_score = min(30, (total / min_configs) * 30 if min_configs > 0 else 0)
        score += config_score

        if total > 0:
            ratio = valid / total
            min_ratio = CHANNEL_MIN_VALID_RATIO
            ratio_score = min(30, (ratio / min_ratio) * 30 if min_ratio > 0 else 0)
            score += ratio_score

        min_protos = CHANNEL_MIN_PROTOCOLS
        proto_score = min(20, (unique_protocols / min_protos) * 20 if min_protos > 0 else 0)
        score += proto_score

        score_score = min(20, (overall_score / 50) * 20 if overall_score > 0 else 0)
        score += score_score

        if last_success:
            try:
                last_time = datetime.fromisoformat(last_success)
                age = (datetime.now() - last_time).total_seconds() / 3600
                if age < 24:
                    bonus = 10
                elif age < 72:
                    bonus = 5
                else:
                    bonus = 0
                score += bonus
            except:
                pass
        else:
            score -= 10

        return max(0, min(100, score))

    def is_channel_healthy(self, channel_url: str) -> bool:
        if channel_url in self._whitelist:
            return True
        if self._is_first_run:
            return True
        score = self.calculate_health_score(channel_url)
        threshold = CHANNEL_HEALTH_THRESHOLD
        return score >= threshold

    def get_unhealthy_channels(self, channel_urls: List[str]) -> List[str]:
        unhealthy = []
        for url in channel_urls:
            if not self.is_channel_healthy(url):
                unhealthy.append(url)
        return unhealthy

    def update_health(self, channel_urls: List[str], history_data: Optional[Dict] = None):
        """
        Обновляет данные о здоровье для списка каналов.
        Если передан history_data, использует его, иначе читает с диска.
        """
        if history_data is not None:
            self.history = history_data
        else:
            self.history = self._load_history()

        for url in channel_urls:
            score = self.calculate_health_score(url)
            self.health_data['channels'][url] = {
                'health_score': score,
                'last_checked': datetime.now().isoformat(),
                'is_healthy': score >= CHANNEL_HEALTH_THRESHOLD
            }
        self._save_health()

    def get_health_report(self) -> Dict:
        return {
            'channels': self.health_data.get('channels', {}),
            'last_updated': self.health_data.get('last_updated'),
            'summary': {
                'total': len(self.health_data.get('channels', {})),
                'healthy': sum(1 for c in self.health_data.get('channels', {}).values() if c.get('is_healthy', False)),
                'unhealthy': sum(1 for c in self.health_data.get('channels', {}).values() if not c.get('is_healthy', False))
            }
        }

    def prune_bad_channels(self, channel_urls: List[str]) -> List[str]:
        healthy = []
        for url in channel_urls:
            if self.is_channel_healthy(url):
                healthy.append(url)
            else:
                logger.info(f"Channel {url} marked as unhealthy, will be removed.")
        return healthy
